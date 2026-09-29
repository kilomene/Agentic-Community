"""Tests for typing indicators (Workstream B: packages/acp_connector/presence.py).

Real connectors on localhost with real keys and real wire crypto.
Trust is established directly (pairing itself is covered by the V1
tests) so the suite stays fast: each side stores the other's real
identity keys and dials a real TCP connection.

Scenarios:
  1. direct round trip: A.typing_start(B) -> B.is_typing(A) is True;
     A.typing_stop(B) -> False. typing_start to unknown/revoked peer
     raises via _require_peer.
  2. TTL expiry: injected typing event with a monkeypatched clock;
     past 8s without refresh -> is_typing False, pruned from
     typing_peers() on read.
  3. group typing: 3-member group, A.typing_start_group(g) -> B and C
     see A in typing_in_group(g); non-member D typing_start_group ->
     POLICY_DENIED; D's forged group frame -> dropped + audited.
  4. attacks: TYPING from unknown peer -> dropped, typing.unknown_sender
     audited, no state stored. typing="yes" (non-bool) -> BAD_ENVELOPE.
     Unknown context -> BAD_ENVELOPE. Group frame without group_id ->
     BAD_ENVELOPE. Non-string context_id -> BAD_ENVELOPE.
  5. heartbeat dedupe: two typing_start frames 1s apart -> a single
     typing.received audit entry; a start after expiry logs again.

Run: python3 -m pytest tests/test_im_presence.py -q
"""
import os
import shutil
import sys
import tempfile
import time
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_proto import AcpError  # noqa: E402
from acp_connector import Connector  # noqa: E402
from acp_connector.presence import (  # noqa: E402
    TYPING, TYPING_TTL,
)
from acp_connector.groups import GroupChat  # noqa: E402

PASS_PHRASE = "typing-test-pass"

NODES = []


def wait_until(fn, timeout=60, interval=0.2, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(interval)
    raise AssertionError(f"timeout waiting for {what}")


def expect_acp_error(fn, code):
    try:
        fn()
    except AcpError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e.detail}"
        return e
    raise AssertionError(f"expected AcpError({code}), none raised")


def audit_has(conn, action, actor=None, limit=500):
    return any(r["action"] == action and (actor is None or
                                         r["actor"] == actor)
               for r in conn.audit_log(limit=limit))


def audit_count(conn, action, actor=None, limit=1000):
    return sum(1 for r in conn.audit_log(limit=limit)
               if r["action"] == action and (actor is None or
                                             r["actor"] == actor))


def make_node(handle):
    home = tempfile.mkdtemp(prefix="acp-typing-test-")
    c = Connector(home, PASS_PHRASE, handle=handle)
    port = c.start_server("127.0.0.1", 0)
    NODES.append((c, home))
    return c, home, port


def trust(a, port_a, b, port_b):
    """Bidirectional trust + live TCP both ways (real keys, real wire)."""
    for x, y, port_y in ((a, b, port_b), (b, a, port_a)):
        x._store_peer(y.peer_id, y.handle, y.identity.ed_pub.hex(),
                      y.identity.x_pub.hex())
        conn = x.transport.connect("127.0.0.1", port_y)
        x._bind_conn(y.peer_id, conn)
        x._spawn_reader(conn)


def teardown_module():
    for c, home in NODES:
        try:
            c.stop()
        except Exception:
            pass
        shutil.rmtree(home, ignore_errors=True)


# ------------------------------------------------------------------ fixtures
ca, home_a, port_a = make_node("t-alice")
cb, home_b, port_b = make_node("t-bob")
cc, home_c, port_c = make_node("t-carol")
cd, home_d, port_d = make_node("t-dave")  # trusted peer, NOT a group member

trust(ca, port_a, cb, port_b)
trust(ca, port_a, cc, port_c)
trust(ca, port_a, cd, port_d)
trust(cb, port_b, cc, port_c)
trust(cb, port_b, cd, port_d)
trust(cc, port_c, cd, port_d)

# The TYPING handler is wired shortly after each Connector is built
# (deferred registration -- see Presence._ensure_typing_handler). Wait
# for it on every node so the tests never depend on timing luck.
for _c in (ca, cb, cc, cd):
    wait_until(lambda c=_c: TYPING in c._ext_handlers,
               what="typing handler registered")

ga, gb, gc, gd = (GroupChat(ca), GroupChat(cb), GroupChat(cc),
                  GroupChat(cd))
GROUP = ga.create_group("typing-group", [cb.peer_id, cc.peer_id])
wait_until(lambda: gb.get_group(GROUP) is not None, what="bob group sync")
wait_until(lambda: gc.get_group(GROUP) is not None, what="carol group sync")


# ------------------------------------------------------------------ 1. direct
def test_direct_round_trip():
    assert not cb.presence.is_typing(ca.peer_id)
    ca.presence.typing_start(cb.peer_id)
    wait_until(lambda: cb.presence.is_typing(ca.peer_id),
               what="bob sees alice typing")
    assert (ca.peer_id, "direct", cb.peer_id) in cb.presence.typing_peers()
    ca.presence.typing_stop(cb.peer_id)
    wait_until(lambda: not cb.presence.is_typing(ca.peer_id),
               what="bob sees alice stopped")
    assert cb.presence.typing_peers() == []


def test_direct_unknown_and_revoked_peer():
    expect_acp_error(lambda: ca.presence.typing_start("no-such-peer"),
                     "NOT_FOUND")
    expect_acp_error(lambda: ca.presence.typing_stop("no-such-peer"),
                     "NOT_FOUND")
    # revoked peer: _require_peer raises POLICY_DENIED
    cb.store._db.execute("UPDATE trusted_agents SET revoked=1 WHERE"
                         " agent_id=?", (ca.peer_id,))
    cb.store._db.commit()
    try:
        expect_acp_error(lambda: cb.presence.typing_start(ca.peer_id),
                         "POLICY_DENIED")
    finally:
        cb.store._db.execute("UPDATE trusted_agents SET revoked=0 WHERE"
                             " agent_id=?", (ca.peer_id,))
        cb.store._db.commit()


# ------------------------------------------------------------------ 2. TTL
def test_ttl_expiry_prunes_on_read():
    env = {"from": ca.peer_id, "to": cb.peer_id}
    with mock.patch("acp_connector.presence.time") as mtime:
        mtime.time.return_value = 1_000_000.0
        cb.presence._on_typing(None, env,
                               {"typing": True, "context": "direct"})
        assert cb.presence.is_typing(ca.peer_id)
        # still live just before the 8s TTL
        mtime.time.return_value = 1_000_000.0 + TYPING_TTL - 0.1
        assert cb.presence.is_typing(ca.peer_id)
        # expired just past the TTL -> gone, pruned from typing_peers
        mtime.time.return_value = 1_000_000.0 + TYPING_TTL + 0.1
        assert not cb.presence.is_typing(ca.peer_id)
        assert cb.presence.typing_peers() == []


# ------------------------------------------------------------------ 3. group
def test_group_typing_fanout():
    assert cb.presence.typing_in_group(GROUP) == []
    ca.presence.typing_start_group(GROUP)
    wait_until(lambda: ca.peer_id in cb.presence.typing_in_group(GROUP),
               what="bob sees alice typing in group")
    wait_until(lambda: ca.peer_id in cc.presence.typing_in_group(GROUP),
               what="carol sees alice typing in group")
    # sender does not see itself typing
    assert ca.peer_id not in ca.presence.typing_in_group(GROUP)
    ca.presence.typing_stop_group(GROUP)
    wait_until(lambda: cb.presence.typing_in_group(GROUP) == [],
               what="bob sees typing cleared")
    wait_until(lambda: cc.presence.typing_in_group(GROUP) == [],
               what="carol sees typing cleared")


def test_group_typing_non_member_denied():
    # D is a trusted peer but not a group member: local fanout refuses.
    expect_acp_error(lambda: cd.presence.typing_start_group(GROUP),
                     "POLICY_DENIED")
    expect_acp_error(lambda: cd.presence.typing_stop_group(GROUP),
                     "POLICY_DENIED")
    # D's forged group frame to B: dropped, audited, no state stored.
    env = {"from": cd.peer_id, "to": cb.peer_id}
    cb.presence._on_typing(
        None, env,
        {"typing": True, "context": "group", "context_id": GROUP})
    assert audit_has(cb, "typing.group_spoof", actor=cd.peer_id)
    assert cd.peer_id not in cb.presence.typing_in_group(GROUP)


# ------------------------------------------------------------------ 4. attacks
def test_unknown_sender_dropped_and_audited():
    env = {"from": "ghost-peer-xyz", "to": cb.peer_id}
    before = audit_count(cb, "typing.unknown_sender")
    # must not raise, must not store state
    cb.presence._on_typing(None, env,
                            {"typing": True, "context": "direct"})
    assert audit_count(cb, "typing.unknown_sender") == before + 1
    assert all(pid != "ghost-peer-xyz"
               for (pid, _, _) in cb.presence.typing_peers())


def test_bad_payloads_rejected():
    env = {"from": ca.peer_id, "to": cb.peer_id}
    expect_acp_error(
        lambda: cb.presence._on_typing(
            None, env, {"typing": "yes", "context": "direct"}),
        "BAD_ENVELOPE")
    expect_acp_error(
        lambda: cb.presence._on_typing(
            None, env, {"typing": 1, "context": "direct"}),
        "BAD_ENVELOPE")
    expect_acp_error(
        lambda: cb.presence._on_typing(
            None, env, {"typing": True, "context": "room"}),
        "BAD_ENVELOPE")
    expect_acp_error(
        lambda: cb.presence._on_typing(
            None, env, {"typing": True, "context": "group"}),
        "BAD_ENVELOPE")  # group context requires a group_id
    expect_acp_error(
        lambda: cb.presence._on_typing(
            None, env,
            {"typing": True, "context": "direct", "context_id": 42}),
        "BAD_ENVELOPE")
    # none of the malformed frames left state behind
    assert not cb.presence.is_typing(ca.peer_id)


# ------------------------------------------------------------------ 5. dedupe
def test_heartbeat_dedupe_single_audit():
    env = {"from": ca.peer_id, "to": cb.peer_id}
    base = audit_count(cb, "typing.received", actor=ca.peer_id)
    with mock.patch("acp_connector.presence.time") as mtime:
        mtime.time.return_value = 2_000_000.0
        cb.presence._on_typing(None, env,
                               {"typing": True, "context": "direct"})
        # heartbeat refresh 1s later: no second audit entry
        mtime.time.return_value = 2_000_001.0
        cb.presence._on_typing(None, env,
                               {"typing": True, "context": "direct"})
    assert audit_count(cb, "typing.received",
                       actor=ca.peer_id) == base + 1
    # a start after the key expired counts as a new session: logged again
    with mock.patch("acp_connector.presence.time") as mtime:
        mtime.time.return_value = 2_000_000.0 + TYPING_TTL + 5.0
        cb.presence._on_typing(None, env,
                               {"typing": True, "context": "direct"})
    assert audit_count(cb, "typing.received",
                       actor=ca.peer_id) == base + 2
    # cleanup: stop the indicator
    with mock.patch("acp_connector.presence.time") as mtime:
        mtime.time.return_value = 2_000_000.0 + TYPING_TTL + 6.0
        cb.presence._on_typing(None, env,
                               {"typing": False, "context": "direct"})
    assert not cb.presence.is_typing(ca.peer_id)


def test_typing_kind_registered_plaintext():
    from acp_proto import ALL_KINDS, E2E_KINDS, PAYLOAD_SCHEMA
    assert TYPING == "typing"
    assert TYPING in ALL_KINDS
    assert TYPING not in E2E_KINDS  # signed plaintext, like PRESENCE
    assert PAYLOAD_SCHEMA[TYPING] == ("typing",)
    # handler is wired on the connector's V2+ extension table
    # (self-healing: any Presence entry point (re)registers it)
    assert ca.presence.is_typing("nobody") is False
    assert TYPING in ca._ext_handlers
    # idempotent: repeated entry points keep a single registration
    cb.presence.typing_peers()
    assert TYPING in cb._ext_handlers
