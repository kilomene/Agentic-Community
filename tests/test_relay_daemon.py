"""Daemon tests: the relay daemon connects, claims a pairing code, publishes
state files, refreshes the code before expiry, and releases on shutdown —
all against a fake in-process relay (no network).

Run: python3 -m pytest tests/test_relay_daemon.py -q
"""
import argparse
import json
import os
import queue
import struct
import sys
import tempfile
import types
import threading
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

from acp_connector import Connector  # noqa: E402
import acp_connector.relay_link as relay_link_mod  # noqa: E402
import daemon as daemon_mod  # noqa: E402
from acp_connector import AcpError  # noqa: E402
from daemon import Daemon, PAIR_CODE_TTL  # noqa: E402


# ------------------------------------------------------------ fake relay

class FakeWs:
    """Stands in for WsConn: answers hello silently, claims/releases
    pairing codes, routes nothing else."""

    def __init__(self, taken=None):
        self._q = queue.Queue()
        self._closed = False
        self.sent = []
        self.taken = taken if taken is not None else set()  # refused codes

    @property
    def closed(self):
        return self._closed

    def send_env(self, env):
        self.send_raw(struct.pack(">I", 0) + b"{}")

    def send_ping(self, payload=b""):  # noqa: ARG002
        self.sent.append({"ws_ping": True})

    def send_raw(self, frame_bytes):
        if self._closed:
            raise RuntimeError("link closed")
        ln = struct.unpack(">I", bytes(frame_bytes)[:4])[0]
        obj = json.loads(bytes(frame_bytes)[4:4 + ln].decode("utf-8"))
        self.sent.append(obj)
        if "pair_code_claim" in obj:
            body = obj["pair_code_claim"]
            code = body["code"]
            if code in self.taken:
                self._q.put({"pair_code_error": {"code": code,
                                                "req": body["req"],
                                                "error": "taken"}})
            else:
                self._q.put({"pair_code_claimed": {"code": code,
                                                  "req": body["req"]}})
        elif "pair_code_release" in obj:
            body = obj["pair_code_release"]
            self._q.put({"pair_code_released": {"code": body["code"],
                                                "req": body["req"]}})

    def read_loop(self, on_frame, on_error=None):
        while not self._closed:
            try:
                obj = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                on_frame(obj)
            except Exception as e:  # noqa: BLE001
                if on_error:
                    on_error(e)

    def close(self):
        self._closed = True


@pytest.fixture()
def fakes():
    made = []
    taken = set()

    def _wss_connect(url):
        ws = FakeWs(taken=taken)
        made.append(ws)
        return ws

    orig = relay_link_mod.wss_connect
    relay_link_mod.wss_connect = _wss_connect
    try:
        fakes_ns = types.SimpleNamespace(conns=made, taken=taken)
        yield fakes_ns
    finally:
        relay_link_mod.wss_connect = orig


@pytest.fixture()
def daemon_env(tmp_path):
    home = tmp_path / "acp-home"
    home.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    conn = Connector(str(home), "test-passphrase", "daemon-test")
    args = argparse.Namespace(
        home=str(home), passphrase_file=str(tmp_path / "pw"),
        url="wss://fake-relay/acp", state_dir=str(state),
        pid_file=str(tmp_path / "daemon.pid"), log_level="CRITICAL")
    d = Daemon(args)
    d.conn = conn  # skip passphrase-file loading
    try:
        yield d, tmp_path
    finally:
        try:
            if d.link is not None:
                d.link.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            conn.stop()
        except Exception:  # noqa: BLE001
            pass


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def test_connect_claims_code_and_publishes_state(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        assert not link.closed
        assert d.code and len(d.code) == 6

        pair = _read_json(tmp / "state" / "pair-code.json")
        assert pair["code"] == d.code
        assert pair["expires_at"] > time.time()

        status = _read_json(tmp / "state" / "relay-status.json")
        assert status["connected"] is True
        assert status["code"] == d.code
        assert status["peer_id"] == d.conn.peer_id
        assert status["handle"] == "daemon-test"
    finally:
        d._release_code()
        link.close()


def test_release_code_sends_release_frame(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    code = d.code
    d._release_code()
    link.close()
    assert d.code is None
    releases = [o for o in fakes.conns[0].sent if "pair_code_release" in o]
    assert releases and releases[0]["pair_code_release"]["code"] == code


def test_refresh_reclaims_same_code_near_expiry(fakes, daemon_env):
    # the pairing code is permanent: refresh re-claims the SAME code,
    # it never mints a fresh random one
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        old = d.code
        # pretend the code is about to expire
        with d._code_lock:
            d.code_expires_at = int(time.time()) + 60
        d._refresh_code_if_needed()
        pair = _read_json(tmp / "state" / "pair-code.json")
        assert pair["code"] == d.code == old
        assert d.code_expires_at > time.time() + 3000
        # the claim frame asked for the same code back
        claims = [o for o in fakes.conns[0].sent if "pair_code_claim" in o]
        assert claims and claims[-1]["pair_code_claim"]["code"] == old
        # nothing was released: the code never changed hands
        releases = [o for o in fakes.conns[0].sent if "pair_code_release" in o]
        assert not releases
    finally:
        d._release_code()
        link.close()


def test_connect_reclaims_permanent_code(fakes, daemon_env):
    # a code recorded in pair-code.json is re-claimed on (re)connect
    d, tmp = daemon_env
    with open(tmp / "state" / "pair-code.json", "w",
              encoding="utf-8") as fh:
        json.dump({"code": "ABC234", "claimed_at": 1, "expires_at": 2}, fh)
    link = d._connect_once()
    try:
        assert d.code == "ABC234"
        claims = [o for o in fakes.conns[0].sent if "pair_code_claim" in o]
        assert claims and claims[0]["pair_code_claim"]["code"] == "ABC234"
    finally:
        d._release_code()
        link.close()


def test_connect_falls_back_when_permanent_code_taken(fakes, daemon_env):
    # someone else grabbed our old code while we were down: claim a fresh
    # one and carry on
    fakes.taken.add("ABC234")
    d, tmp = daemon_env
    with open(tmp / "state" / "pair-code.json", "w",
              encoding="utf-8") as fh:
        json.dump({"code": "ABC234", "claimed_at": 1, "expires_at": 2}, fh)
    link = d._connect_once()
    try:
        assert d.code and d.code != "ABC234" and len(d.code) == 6
        pair = _read_json(tmp / "state" / "pair-code.json")
        assert pair["code"] == d.code  # the new code is now the permanent one
    finally:
        d._release_code()
        link.close()


def test_status_reports_pairing_active(fakes, daemon_env):
    import types
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        assert d._status()["pairing_active"] == 0
        sess = types.SimpleNamespace(state="await_confirm", expired=False)
        d.conn.pairing._sessions["s1"] = sess
        assert d._status()["pairing_active"] == 1
        sess.state = "failed"
        assert d._status()["pairing_active"] == 0
        status = _read_json(tmp / "state" / "relay-status.json")
        assert status["pairing_active"] == 0
    finally:
        d.conn.pairing._sessions.pop("s1", None)
        d._release_code()
        link.close()


def test_no_refresh_when_code_fresh(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        before = fakes.conns[0].sent[:]
        d._refresh_code_if_needed()
        claims = [o for o in fakes.conns[0].sent[len(before):]
                  if "pair_code_claim" in o]
        assert not claims
    finally:
        d._release_code()
        link.close()


def test_status_reflects_disconnect(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    d._release_code()
    link.close()
    d.link = None
    d.connected_since = 0
    d._publish()
    status = _read_json(tmp / "state" / "relay-status.json")
    assert status["connected"] is False
    assert status["code"] is None


def test_pairing_request_callback_matches_api_and_records(daemon_env):
    """Regression: PairingManager calls cb(session) with ONE arg. The
    daemon's callback must accept exactly that, auto-accept the request
    (send the challenge immediately, like the `acp` CLI — otherwise the
    initiator deadlocks in await_challenge), and persist the confirm
    code to state/pairing-requests.json (2026-09-29 live bug: the
    two-arg callback crashed, losing the confirm code)."""
    from types import SimpleNamespace
    d, tmp = daemon_env
    d._register_callbacks()
    cbs = d.conn.pairing._request_cbs
    assert cbs, "daemon did not register a pairing-request callback"
    accepted = []
    session = SimpleNamespace(
        session_id="sess-123", peer_pid="peer-abc",
        peer_handle="olatunde", code="K7Q2XD",
        accept=lambda: accepted.append(True))
    for cb in list(cbs):
        cb(session)  # must not raise TypeError
    assert accepted == [True], "daemon did not auto-accept the request"
    recs = _read_json(tmp / "state" / "pairing-requests.json")
    assert len(recs) == 1
    rec = recs[0]
    assert rec["session_id"] == "sess-123"
    assert rec["peer_handle"] == "olatunde"
    assert rec["code"] == "K7Q2XD"


def test_pairing_request_prunes_superseded_records(daemon_env):
    """A stale record (session done/failed/expired, e.g. superseded by a
    newer request from the same peer) is pruned from
    pairing-requests.json when a new request is recorded, so a dead
    code is never read out."""
    from types import SimpleNamespace
    from acp_connector.pairing import PairingSession
    d, tmp = daemon_env
    d._register_callbacks()
    cbs = d.conn.pairing._request_cbs
    cb = cbs[0]
    mgr = d.conn.pairing
    # Emulate a superseded session: failed, but its record is still out.
    dead = PairingSession(mgr, "sess-old", "responder")
    dead.peer_pid = "peer-abc"
    dead.state = "failed"
    with mgr._lock:
        mgr._sessions["sess-old"] = dead
    stale = SimpleNamespace(
        session_id="sess-old", peer_pid="peer-abc",
        peer_handle="olatunde", code="OLD111",
        accept=lambda: None)
    cb(stale)
    # Now a fresh request arrives; the stale record must be pruned.
    fresh = SimpleNamespace(
        session_id="sess-new", peer_pid="peer-abc",
        peer_handle="olatunde", code="NEW222",
        accept=lambda: None)
    cb(fresh)
    recs = _read_json(tmp / "state" / "pairing-requests.json")
    codes = [r["code"] for r in recs]
    assert "OLD111" not in codes, "stale superseded code still recorded"
    assert "NEW222" in codes


def test_on_message_callback_matches_connector_signature(tmp_path):
    """Regression: Messaging invokes on_message cbs as cb(sender, text,
    msg_id) (3 args). The daemon's handler must accept all three — a
    2-arg handler raised TypeError on every inbound message, which the
    connector swallowed into audit.message.callback_error, so messages
    were stored and acked but never surfaced in the daemon log."""
    from types import SimpleNamespace

    captured = {}

    class FakeConn:
        def on_message(self, cb):
            captured["cb"] = cb

        def on_pairing_request(self, cb):
            pass

        def on_file_offer(self, cb):
            pass

    d = Daemon.__new__(Daemon)
    d.conn = FakeConn()
    d.args = SimpleNamespace(state_dir=str(tmp_path / "state"))
    Daemon._register_callbacks(d)

    cb = captured["cb"]
    # Exactly how acp_connector/messaging.py invokes it:
    cb("peer-abc", "Hello, how are you doing phoenix", "e2401fa513f0")


def test_pairing_complete_callback_fires_and_survives_raise(daemon_env):
    """PairingManager.on_pairing_complete fires cb(peer_pid, peer_handle,
    role); a raising callback is audited, never propagated."""
    d, tmp = daemon_env
    seen = []
    d.conn.pairing.on_pairing_complete(
        lambda pid, handle, role: seen.append((pid, handle, role)))

    def boom(pid, handle, role):  # noqa: ARG001
        raise RuntimeError("boom")

    d.conn.pairing.on_pairing_complete(boom)
    d.conn.pairing._fire_complete("peer-abc", "olatunde", "responder")
    assert seen == [("peer-abc", "olatunde", "responder")]


def test_fleet_auto_add_creates_group_and_adds_peer(daemon_env):
    """With fleet auto-join enabled, a pairing completion creates the
    fleet group on first use and adds the peer (offline-safe: sends to
    the unreachable peer are audited, membership persists locally)."""
    from acp_connector.groups import GroupChat
    d, tmp = daemon_env
    d._register_callbacks()
    cfg = d._fleet_cfg()
    assert cfg["auto_join"] is False  # opt-in, never on by default
    cfg["auto_join"] = True
    d._fleet_save(cfg)

    peer_pid = "fleet-peer-" + "x" * 32
    d.conn._store_peer(peer_pid, "agent-x", "ab" * 32, "cd" * 32)
    # through the real completion-callback path the daemon registered
    for cb in list(d.conn.pairing._complete_cbs):
        cb(peer_pid, "agent-x", "responder")

    groups = GroupChat(d.conn)
    found = [g for g in groups.list_groups()
             if g["group_id"] == d._fleet_cfg()["group_id"]]
    assert found, "fleet group was not created"
    members = groups.get_group(found[0]["group_id"])["members"]
    assert d.conn.peer_id in members
    assert peer_pid in members


def test_fleet_auto_add_disabled_by_default(daemon_env):
    """A pairing completion with auto-join off creates no group."""
    d, tmp = daemon_env
    d._register_callbacks()
    peer_pid = "quiet-peer-" + "x" * 31
    d.conn._store_peer(peer_pid, "agent-y", "ab" * 32, "cd" * 32)
    for cb in list(d.conn.pairing._complete_cbs):
        cb(peer_pid, "agent-y", "responder")
    from acp_connector.groups import GroupChat
    assert GroupChat(d.conn).list_groups() == []
    assert not os.path.exists(tmp / "state" / "fleet.json") or \
        d._fleet_cfg()["group_id"] is None


def test_fleet_status_reports_group(daemon_env):
    d, tmp = daemon_env
    d._register_callbacks()
    st = d._status()["fleet"]
    assert st["auto_join"] is False
    assert st["group_id"] is None
    assert st["members"] is None


def test_serve_sends_keepalive_pings(fakes, daemon_env, monkeypatch):
    # the serve loop pings the relay every PING_INTERVAL so idle
    # middleboxes don't kill a quiet connection
    d, tmp = daemon_env
    monkeypatch.setattr(daemon_mod, "PING_INTERVAL", 0.05)
    link = d._connect_once()
    d._stop.clear()
    t = threading.Thread(target=d._serve_until_drop, args=(link,))
    t.start()
    time.sleep(0.3)
    d._stop.set()
    t.join(timeout=10)
    assert not t.is_alive(), "serve loop hung"
    pings = [o for o in fakes.conns[0].sent if o == {"ws_ping": True}]
    assert len(pings) >= 2, "expected periodic keepalive pings, got %d" \
        % len(pings)


def test_serve_ping_failure_breaks_to_reconnect(fakes, daemon_env,
                                                monkeypatch):
    # a failed ping means the link is dead: the loop must exit so the
    # reconnect path takes over instead of spinning on a dead socket
    d, tmp = daemon_env
    monkeypatch.setattr(daemon_mod, "PING_INTERVAL", 0.01)

    class DeadWs(FakeWs):
        def send_ping(self, payload=b""):
            raise AcpError("INTERNAL", "connection closed")

    link = d._connect_once()
    link._ws = DeadWs()  # socket dies underneath the RelayLink
    d._stop.clear()
    start = time.time()
    d._serve_until_drop(link)
    assert time.time() - start < 5, "serve loop did not exit on ping failure"
