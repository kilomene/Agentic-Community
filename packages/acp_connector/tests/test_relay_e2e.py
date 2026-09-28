"""End-to-end: full pairing + messaging between two Connectors joined only
by a wss:// relay link — no TCP dials anywhere.

A stub WebSocket "hub" stands in for the relay Worker: it verifies the
hello with the real relay verifier, routes envelopes by ``to`` pid, and
returns relayed:false for unknown pids. The connectors under test use the
real RelayLink + Connector._get_conn relay fallback.

Run: python3 -m pytest packages/acp_connector/tests/test_relay_e2e.py -q
"""
import json
import os
import queue
import struct
import sys
import threading

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "..", "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay"))

from acp_proto import AcpError, frame_envelope  # noqa: E402
from acp_connector import Connector  # noqa: E402
import acp_connector.relay_link as relay_link_mod  # noqa: E402
from acp_connector.relay_link import _looks_like_envelope  # noqa: E402
from relay import verify_hello  # noqa: E402  (services/acp_relay/relay.py)


# ------------------------------------------------------------ stub WS layer

class _PipeWs:
    """Stands in for WsConn; frames go to the hub, objects come back."""

    def __init__(self, hub):
        self._hub = hub
        self._q = queue.Queue()
        self._closed = False

    @property
    def closed(self):
        return self._closed

    def send_env(self, env):
        self.send_raw(frame_envelope(env))

    def send_raw(self, frame_bytes):
        if self._closed:
            raise AcpError("INTERNAL", "link closed")
        ln = struct.unpack(">I", bytes(frame_bytes)[:4])[0]
        obj = json.loads(bytes(frame_bytes)[4:4 + ln].decode("utf-8"))
        self._hub.client_frame(self, obj)

    def read_loop(self, on_envelope, on_error=None):
        while not self._closed:
            try:
                obj = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            if obj is None:
                break
            try:
                on_envelope(obj)
            except Exception as e:  # never let the reader die silently
                if on_error:
                    on_error("INTERNAL", e)

    def close(self):
        self._closed = True
        self._q.put(None)
        self._hub.unregister(self)


class _Hub:
    """Minimal relay stand-in: hello registers, envelopes route by to."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pipes = {}

    def client_frame(self, pipe, obj):
        if not isinstance(obj, dict):
            return
        if "hello" in obj:
            pid = verify_hello(obj)  # the real relay verifier
            with self._lock:
                self._pipes[pid] = pipe
            return
        if _looks_like_envelope(obj):
            with self._lock:
                dest = self._pipes.get(obj.get("to"))
            if dest is not None and not dest.closed:
                dest._q.put(obj)
            else:
                pipe._q.put({"relayed": False, "to": obj.get("to"),
                             "error": "offline", "queued": False,
                             "req_id": obj.get("req_id")})

    def unregister(self, pipe):
        with self._lock:
            for pid, p in list(self._pipes.items()):
                if p is pipe:
                    del self._pipes[pid]


def _wait_until(fn, what, timeout=10):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.05)
    raise AssertionError("timed out waiting for: %s" % what)


# ------------------------------------------------------------------- tests

@pytest.fixture()
def relayed_pair(tmp_path, monkeypatch):
    hub = _Hub()
    monkeypatch.setattr(relay_link_mod, "wss_connect",
                        lambda url, timeout=10: _PipeWs(hub))
    home_a = str(tmp_path / "a")
    home_b = str(tmp_path / "b")
    cA = Connector(home_a, "pass-a", "alice")
    cB = Connector(home_b, "pass-b", "bob")
    cA.relay_connect("wss://relay.test/acp")
    cB.relay_connect("wss://relay.test/acp")
    yield cA, cB
    cA.stop()
    cB.stop()


def test_relay_connect_sends_verified_hello(relayed_pair):
    cA, cB = relayed_pair
    assert cA._relay_link is not None and not cA._relay_link.closed
    assert cB._relay_link is not None and not cB._relay_link.closed
    assert cA._relay_link.peer_addr is None  # not a TCP conn


def test_pairing_and_messaging_over_relay(relayed_pair):
    cA, cB = relayed_pair

    req_ev = threading.Event()
    got = {}

    def on_req(session):
        got["session"] = session
        req_ev.set()

    cB.on_pairing_request(on_req)

    sessA = cA.pair_initiate_relay(cB.peer_id)
    assert sessA.peer_pid == cB.peer_id
    assert req_ev.wait(10), "responder never received pair_request"
    sessB = got["session"]
    assert sessB.code and len(sessB.code) == 6

    # No direct TCP connection may have been created for this.
    with cA._conns_lock:
        bound = cA._conns.get(cB.peer_id)
        assert bound is None or bound is cA._relay_link

    sessB.accept()  # responder approves -> pair_challenge over the link
    _wait_until(lambda: sessA.state == "await_code",
                "challenge processing")

    sessA.confirm(sessB.code)  # code typed on the initiator side
    _wait_until(lambda: sessA.state == "done" and sessB.state == "done",
                "pairing completion")
    p12 = cA.store.get_peer(cB.peer_id)
    p21 = cB.store.get_peer(cA.peer_id)
    assert p12 and not p12["revoked"], "cA did not store cB as peer"
    assert p21 and not p21["revoked"], "cB did not store cA as peer"

    # Now E2E-encrypted messaging over the same shared link.
    msg_ev = threading.Event()
    received = {}

    def on_msg(sender, text, msg_id):
        received.update(sender=sender, text=text, msg_id=msg_id)
        msg_ev.set()

    cB.on_message(on_msg)
    mid = cA.send_message(cB.peer_id, "hello via relay")
    assert msg_ev.wait(10), "message never arrived"
    assert received["sender"] == cA.peer_id
    assert received["text"] == "hello via relay"
    assert received["msg_id"] == mid

    # The shared link survived everything (pairing-expiry sweeps,
    # rebinds, and drops must never close it).
    assert not cA._relay_link.closed
    assert not cB._relay_link.closed


def test_pair_initiate_relay_without_link_raises(tmp_path):
    home = str(tmp_path / "c")
    c = Connector(home, "pass-c", "carol")
    try:
        with pytest.raises(AcpError):
            c.pair_initiate_relay("somepid")
    finally:
        c.stop()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
