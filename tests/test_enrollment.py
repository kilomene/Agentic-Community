"""One-step enrollment tests (workstream D).

  * window opens / closes / reports status
  * auto-expiry: on every pairing attempt AND on the periodic sweep
    (never a single timer)
  * pairing auto-accepts inside an open window -- a full two-connector
    handshake completes with NO confirm() call
  * the confirm-code flow is untouched outside a window and when the
    presented code doesn't match
  * audit entries (pairing.enrolled) record who paired, when, via what

Run: python3 -m pytest tests/test_enrollment.py -q
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

from acp_connector import Connector  # noqa: E402
import enrollment  # noqa: E402
from daemon import Daemon  # noqa: E402

DAEMON_CODE = "ENRK2X"  # the daemon's live claimed pairing code


# ------------------------------------------------------------- helpers

def wait_until(fn, timeout=30, interval=0.1, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(interval)
    raise AssertionError("timeout waiting for %s" % what)


def audit_has(conn, action, timeout=10, **wants):
    """True when conn's audit log holds `action` whose merged fields
    (audit() stores actor/target/result/ts as row columns, the rest
    inside the details JSON) contain every wants key/value.

    The audit write lands in the reader thread just AFTER
    session.state flips to "done", so a one-shot check right after
    wait_until() is racy -- poll for a few seconds instead.
    """
    deadline = time.time() + timeout
    while True:
        for r in conn.audit_log(limit=200):
            if r["action"] != action:
                continue
            try:
                details = json.loads(r.get("details") or "{}")
            except (ValueError, TypeError):
                details = {}
            merged = dict(details)
            for k in ("actor", "target", "result", "ts"):
                if k in r:
                    merged[k] = r[k]
            if all(merged.get(k) == v for k, v in wants.items()):
                return True
        if time.time() >= deadline:
            return False
        time.sleep(0.2)


class FakeSession:
    """Minimal stand-in for a responder PairingSession (decision only)."""

    def __init__(self, presented_code=None):
        self.presented_code = presented_code


@pytest.fixture()
def state_dir():
    d = tempfile.mkdtemp(prefix="enroll-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------- window lifecycle

def test_window_open_close_status(state_dir):
    w = enrollment.open_window(state_dir, 30, "head")
    assert w["open"] is True
    assert w["opened_by"] == "head"
    assert w["open_until"] == w["opened_at"] + 30 * 60

    st = enrollment.status(state_dir)
    assert st["open"] is True
    assert st["opened_by"] == "head"
    assert 0 < st["remaining"] <= 30 * 60

    w = enrollment.close_window(state_dir, reason="closed by head")
    assert w["open"] is False
    assert w["close_reason"] == "closed by head"

    st = enrollment.status(state_dir)
    assert st["open"] is False
    assert st["remaining"] is None


def test_window_rejects_bad_minutes(state_dir):
    with pytest.raises(ValueError):
        enrollment.open_window(state_dir, 0, "head")
    with pytest.raises(ValueError):
        enrollment.open_window(state_dir, 24 * 60 + 1, "head")


def test_window_auto_expires_on_read(state_dir):
    # Backdate the deadline, then read: the window must auto-close with
    # reason "expired" and persist that way (per-attempt expiry check).
    enrollment.open_window(state_dir, 30, "head")
    path = enrollment.window_path(state_dir)
    with open(path, encoding="utf-8") as fh:
        w = json.load(fh)
    w["open_until"] = int(time.time()) - 5
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(w, fh)

    got = enrollment.get_window(state_dir)
    assert got["open"] is False
    assert got["close_reason"] == "expired"
    # persisted, not just in-memory
    with open(path, encoding="utf-8") as fh:
        assert json.load(fh)["open"] is False
    assert enrollment.is_open(state_dir) is False


def test_sweep_expired_closes_window(state_dir):
    enrollment.open_window(state_dir, 30, "head")
    assert enrollment.sweep_expired(state_dir) is False  # not expired yet

    path = enrollment.window_path(state_dir)
    with open(path, encoding="utf-8") as fh:
        w = json.load(fh)
    w["open_until"] = int(time.time()) - 5
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(w, fh)

    assert enrollment.sweep_expired(state_dir) is True
    assert enrollment.is_open(state_dir) is False
    # second sweep is a no-op
    assert enrollment.sweep_expired(state_dir) is False


# ------------------------------------------------------- pairing decision

def test_evaluate_request(state_dir):
    now = int(time.time())
    enrollment.open_window(state_dir, 30, "head", now=now)

    ok = enrollment.evaluate_request(FakeSession("enrk2x"), DAEMON_CODE,
                                     state_dir, now=now)
    assert ok is not None
    assert ok["code"] == DAEMON_CODE

    # presented code doesn't match the daemon's live code
    assert enrollment.evaluate_request(FakeSession("ZZZZZZ"), DAEMON_CODE,
                                       state_dir, now=now) is None
    # no code presented (direct peer-id pairing)
    assert enrollment.evaluate_request(FakeSession(None), DAEMON_CODE,
                                       state_dir, now=now) is None
    # daemon holds no live code
    assert enrollment.evaluate_request(FakeSession("enrk2x"), None,
                                       state_dir, now=now) is None


def test_evaluate_request_closed_or_missing_window(state_dir):
    assert enrollment.evaluate_request(FakeSession("enrk2x"), DAEMON_CODE,
                                       state_dir) is None
    enrollment.open_window(state_dir, 30, "head")
    enrollment.close_window(state_dir)
    assert enrollment.evaluate_request(FakeSession("enrk2x"), DAEMON_CODE,
                                       state_dir) is None


def test_evaluate_request_expired_window_never_accepts(state_dir):
    now = int(time.time())
    enrollment.open_window(state_dir, 30, "head", now=now)
    # one second past the deadline: the per-attempt check closes it
    assert enrollment.evaluate_request(
        FakeSession("enrk2x"), DAEMON_CODE, state_dir,
        now=now + 30 * 60 + 1) is None
    assert enrollment.is_open(state_dir, now=now + 30 * 60 + 1) is False


# ------------------------------------------------------- daemon + handshake

def _make_daemon(state_dir, connector, code):
    """A real Daemon bound to a live connector and tmp state dir (the
    running daemon's state is never touched)."""
    args = types.SimpleNamespace(home=connector._home
                                 if hasattr(connector, "_home") else "",
                                 url="wss://example.invalid/acp",
                                 state_dir=state_dir,
                                 passphrase_file="")
    d = Daemon(args)
    d.conn = connector
    d.code = code
    return d


def _pair_of_connectors(handle_a="enroll-a", handle_b="enroll-b"):
    ha = tempfile.mkdtemp(prefix="enroll-ca-")
    hb = tempfile.mkdtemp(prefix="enroll-cb-")
    ca = Connector(ha, "enroll-pass-a", handle=handle_a)
    cb = Connector(hb, "enroll-pass-b", handle=handle_b)
    pa = ca.start_server("127.0.0.1", 0)
    pb = cb.start_server("127.0.0.1", 0)
    return ca, cb, ha, hb, pa, pb


def _stop(ca, cb, ha, hb):
    for c in (ca, cb):
        try:
            c.stop()
        except Exception:
            pass
    for h in (ha, hb):
        shutil.rmtree(h, ignore_errors=True)


def test_enrollment_pairing_auto_accepts(state_dir):
    """Window open + valid presented code -> pairing completes with NO
    confirm-code step (the real daemon decision path end to end)."""
    ca, cb, ha, hb, pa, pb = _pair_of_connectors()
    try:
        enrollment.open_window(state_dir, 30, "head")
        d = _make_daemon(state_dir, cb, DAEMON_CODE)

        sessions = []
        seen = threading.Event()

        def on_req(s):
            sessions.append(s)
            d._handle_pair_request(s)
            seen.set()

        cb.on_pairing_request(on_req)
        # lowercase on purpose: the presented code is normalized
        s1 = ca.pair_initiate("127.0.0.1", pb, relay_code="enrk2x")
        assert seen.wait(10), "responder never got the pair_request"
        s2 = sessions[0]

        wait_until(lambda: s1.state == "done" and s2.state == "done",
                   what="enrollment pairing to complete")
        assert s2.enrollment is True
        # no human confirm step happened on either side
        assert s1.attempts == 0
        # both peers actually trust each other now
        assert ca.store.get_peer(cb.peer_id) is not None
        assert cb.store.get_peer(ca.peer_id) is not None
        # audit trail: who paired, when, via enrollment
        assert audit_has(cb, "pairing.enrolled", actor=ca.peer_id,
                         handle="enroll-a", via="enrollment")
        assert audit_has(cb, "pairing.completed", actor=ca.peer_id)
        assert audit_has(ca, "pairing.enrollment_confirmed",
                         actor=cb.peer_id)
        # the request record notes the enrollment
        with open(os.path.join(state_dir, "pairing-requests.json"),
                   encoding="utf-8") as fh:
            recs = json.load(fh)
        assert any(r.get("session_id") == s2.session_id
                   and r.get("enrolled") is True for r in recs)
    finally:
        _stop(ca, cb, ha, hb)


def test_confirm_still_required_outside_window(state_dir):
    """No window open -> the initiator must type the confirm code; the
    default flow is untouched."""
    ca, cb, ha, hb, pa, pb = _pair_of_connectors()
    try:
        d = _make_daemon(state_dir, cb, DAEMON_CODE)
        sessions = []
        seen = threading.Event()

        def on_req(s):
            sessions.append(s)
            d._handle_pair_request(s)
            seen.set()

        cb.on_pairing_request(on_req)
        s1 = ca.pair_initiate("127.0.0.1", pb, relay_code="enrk2x")
        assert seen.wait(10), "responder never got the pair_request"
        s2 = sessions[0]

        wait_until(lambda: s1.state == "await_code", what="challenge")
        assert s2.enrollment is False
        # without the confirm step it must NOT complete
        time.sleep(2)
        assert s1.state == "await_code"
        assert s2.state == "await_confirm"

        # ... and typing the code completes it, as before
        s1.confirm(s2.code)
        wait_until(lambda: s1.state == "done" and s2.state == "done",
                   what="manual pairing to complete")
        assert audit_has(cb, "pairing.completed", actor=ca.peer_id)
        assert not audit_has(cb, "pairing.enrolled")
    finally:
        _stop(ca, cb, ha, hb)


def test_wrong_presented_code_falls_back_to_confirm(state_dir):
    """Window open but the presented code doesn't match -> confirm-code
    flow, no auto-accept."""
    ca, cb, ha, hb, pa, pb = _pair_of_connectors()
    try:
        enrollment.open_window(state_dir, 30, "head")
        d = _make_daemon(state_dir, cb, DAEMON_CODE)
        sessions = []
        seen = threading.Event()

        def on_req(s):
            sessions.append(s)
            d._handle_pair_request(s)
            seen.set()

        cb.on_pairing_request(on_req)
        s1 = ca.pair_initiate("127.0.0.1", pb, relay_code="WRONG1")
        assert seen.wait(10), "responder never got the pair_request"
        s2 = sessions[0]

        wait_until(lambda: s1.state == "await_code", what="challenge")
        time.sleep(2)
        assert s1.state == "await_code", "must not auto-complete"
        assert s2.enrollment is False
        assert not audit_has(cb, "pairing.enrolled")
    finally:
        _stop(ca, cb, ha, hb)


def test_daemon_sweep_closes_expired_window(state_dir):
    ca, cb, ha, hb, pa, pb = _pair_of_connectors()
    try:
        d = _make_daemon(state_dir, cb, DAEMON_CODE)
        enrollment.open_window(state_dir, 30, "head")
        d._enrollment_sweep()  # not expired: no-op
        assert enrollment.is_open(state_dir) is True

        path = enrollment.window_path(state_dir)
        with open(path, encoding="utf-8") as fh:
            w = json.load(fh)
        w["open_until"] = int(time.time()) - 5
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(w, fh)

        d._enrollment_sweep()  # periodic sweep closes it
        assert enrollment.is_open(state_dir) is False
    finally:
        _stop(ca, cb, ha, hb)
