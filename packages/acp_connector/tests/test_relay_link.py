"""Tests for acp_connector.relay_link (wss:// relay client).

- The hello frame sent on connect() must verify against the real TCP
  relay's verify_hello (services/acp_relay/relay.py).
- Mailbox drain/ack arming: after a mailbox_delivery notice, the next
  len(ids) envelopes are delivered, then a mailbox_ack goes back.
- relayed-offline controls are audited; pong/unknown frames ignored.

Run: python3 -m pytest packages/acp_connector/tests/test_relay_link.py -q
"""
import json
import os
import struct
import sys
from types import SimpleNamespace

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "..", "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay"))

from acp_crypto import generate_ed25519_keypair  # noqa: E402
from acp_proto import AcpError, b62encode  # noqa: E402
import acp_connector.relay_link as relay_link_mod  # noqa: E402
from acp_connector.relay_link import (  # noqa: E402
    RelayLink, _looks_like_envelope,
)
from relay import verify_hello  # noqa: E402  (services/acp_relay/relay.py)


# ------------------------------------------------------------------- fakes

class _FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, event, actor="local", target=None, result="ok",
            details=None):
        self.events.append({"event": event, "actor": actor,
                            "target": target, "result": result,
                            "details": details})


class _FakeConnector:
    def __init__(self):
        ed_priv, ed_pub = generate_ed25519_keypair()
        self.peer_id = b62encode(ed_pub)
        self.identity = SimpleNamespace(ed_priv=ed_priv)
        self.audit = _FakeAudit()
        self.queued_notices = []

    def _on_relay_queued(self, to_pid, mailbox_id):
        self.queued_notices.append((to_pid, mailbox_id))


class _FakeWs:
    """Stands in for WsConn: records sends, replays canned frames."""

    def __init__(self):
        self.sent = []       # raw bytes passed to send_raw
        self.incoming = []   # canned JSON objects fed to read_loop
        self._closed = False

    @property
    def closed(self):
        return self._closed

    def send_env(self, env):
        raise AssertionError("test uses send_raw only")

    def send_raw(self, frame_bytes):
        self.sent.append(bytes(frame_bytes))

    def read_loop(self, on_envelope, on_error=None):
        for obj in self.incoming:
            on_envelope(obj)

    def close(self):
        self._closed = True


def _link_with_fake(monkeypatch, incoming):
    fake = _FakeWs()
    fake.incoming = list(incoming)
    monkeypatch.setattr(relay_link_mod, "wss_connect",
                        lambda url, timeout=10: fake)
    conn = _FakeConnector()
    link = RelayLink(conn)
    link.connect("wss://example.com/acp")
    return conn, link, fake


def _decoded_sends(fake):
    """Decode sent frames (skipping nothing); returns list of objects."""
    out = []
    for raw in fake.sent:
        ln = struct.unpack(">I", raw[:4])[0]
        out.append(json.loads(raw[4:4 + ln].decode("utf-8")))
    return out


def _envelope(nonce="n1"):
    return {"kind": "msg", "from": "a", "to": "b", "ts": 1,
            "nonce": nonce, "sig": "s", "payload": {}}


# ------------------------------------------------------------------- tests

def test_looks_like_envelope():
    assert _looks_like_envelope(_envelope())
    e2e = dict(_envelope(), payload=None)
    del e2e["payload"]
    e2e["box"] = {"nonce": "x", "ct": "y"}
    assert _looks_like_envelope(e2e)
    assert not _looks_like_envelope({"relayed": False, "to": "x"})
    assert not _looks_like_envelope({"pong": 1})
    assert not _looks_like_envelope({"mailbox_delivery": {"ids": []}})
    assert not _looks_like_envelope([1, 2])
    assert not _looks_like_envelope("nope")
    both = dict(_envelope())
    both["box"] = {}
    assert not _looks_like_envelope(both)  # payload AND box


def test_hello_verifies_against_real_relay(monkeypatch):
    conn, link, fake = _link_with_fake(monkeypatch, [])
    assert len(fake.sent) == 1
    obj = _decoded_sends(fake)[0]
    assert set(obj.keys()) == {"hello"}
    # The real relay's verifier must accept our hello and return our pid.
    assert verify_hello(obj) == conn.peer_id


def test_hello_rejected_when_tampered(monkeypatch):
    conn, link, fake = _link_with_fake(monkeypatch, [])
    obj = _decoded_sends(fake)[0]
    obj["hello"]["ts"] = 1  # stale timestamp
    with pytest.raises(ValueError):
        verify_hello(obj)


def test_mailbox_ack_sent_after_drain(monkeypatch):
    e1, e2 = _envelope("n1"), _envelope("n2")
    conn, link, fake = _link_with_fake(
        monkeypatch,
        [{"mailbox_delivery": {"ids": [11, 22]}}, e1, e2])
    log = []

    orig_send_raw = fake.send_raw

    def send_raw_and_log(frame_bytes):
        ln = struct.unpack(">I", bytes(frame_bytes)[:4])[0]
        log.append(("sent", json.loads(bytes(frame_bytes)[4:4 + ln]
                                      .decode("utf-8"))))
        orig_send_raw(frame_bytes)

    fake.send_raw = send_raw_and_log

    def on_env(env):
        log.append(("env", env["nonce"]))

    link.read_loop(on_env)
    # Drop the hello (sent during connect); the ack must come AFTER
    # both drained envelopes were delivered.
    log = [e for e in log if not (e[0] == "sent" and "hello" in e[1])]
    assert log == [("env", "n1"), ("env", "n2"),
                   ("sent", {"mailbox_ack": {"ids": [11, 22]}})]


def test_empty_mailbox_delivery_acked_immediately(monkeypatch):
    conn, link, fake = _link_with_fake(
        monkeypatch, [{"mailbox_delivery": {"ids": []}}])
    link.read_loop(lambda env: None)
    objs = _decoded_sends(fake)
    assert {"mailbox_ack": {"ids": []}} in objs


def test_relayed_offline_is_audited(monkeypatch):
    conn, link, fake = _link_with_fake(
        monkeypatch,
        [{"relayed": False, "to": "somepid", "error": "offline",
          "queued": True}])
    got = []
    link.read_loop(got.append)
    assert got == []
    assert len(conn.audit.events) == 1
    ev = conn.audit.events[0]
    assert ev["result"] == "relayed_offline"
    assert ev["target"] == "somepid"


def test_pong_and_unknown_controls_ignored(monkeypatch):
    conn, link, fake = _link_with_fake(
        monkeypatch,
        [{"pong": 12345},
         {"mailbox_ack": {"acked": 2}},   # reply to our own ack
         {"something_new": True},          # forward-compatible: ignore
         [1, 2, 3]])                       # non-dict: ignore
    got = []
    link.read_loop(got.append)  # must not raise
    assert got == []
    assert conn.audit.events == []
    # Only the hello went out.
    assert len(fake.sent) == 1


def test_envelope_without_drain_passes_through(monkeypatch):
    conn, link, fake = _link_with_fake(monkeypatch, [_envelope("n9")])
    got = []
    link.read_loop(got.append)
    assert [e["nonce"] for e in got] == ["n9"]
    assert len(fake.sent) == 1  # hello only; no ack armed


def test_link_closed_before_connect():
    link = RelayLink(_FakeConnector())
    assert link.closed
    with pytest.raises(AcpError):
        link.send_env(_envelope())


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


# ------------------------------------------------- queued-notice tests

def _fake_with_queue_methods(conn):
    """Bind the real queued-notice methods onto the fake connector."""
    import threading
    from acp_connector import Connector
    conn._relay_queued = []
    conn._relay_queued_lock = threading.Lock()
    conn._on_relay_queued = Connector._on_relay_queued.__get__(conn)
    conn._pop_relay_queued = Connector._pop_relay_queued.__get__(conn)
    return conn


def test_queued_control_surfaces_to_connector(monkeypatch):
    conn, link, fake = _link_with_fake(
        monkeypatch,
        [{"relayed": False, "to": "pidA", "error": "offline",
          "queued": True, "mailbox_id": "mbx1"},
         {"relayed": False, "to": "pidB", "error": "offline"}])
    _fake_with_queue_methods(conn)
    link.read_loop(lambda env: None)
    assert conn._pop_relay_queued("pidA") == "mbx1"
    assert conn._pop_relay_queued("pidB") is None   # no queued flag
    assert conn._pop_relay_queued("pidA") is None   # consumed


def test_queued_notices_are_fifo_per_pid(monkeypatch):
    conn, link, fake = _link_with_fake(
        monkeypatch,
        [{"relayed": False, "to": "pidA", "error": "offline",
          "queued": True, "mailbox_id": "mbx1"},
         {"relayed": False, "to": "pidA", "error": "offline",
          "queued": True, "mailbox_id": "mbx2"}])
    _fake_with_queue_methods(conn)
    link.read_loop(lambda env: None)
    assert conn._pop_relay_queued("pidA") == "mbx1"
    assert conn._pop_relay_queued("pidA") == "mbx2"
    assert conn._pop_relay_queued("pidA") is None
