"""Tests for E2E group chat (packages/acp_connector/groups.py).

Real connectors on localhost with real keys and real wire crypto.
Trust is established directly (pairing itself is covered by the V1
tests) so the suite stays fast: each side stores the other's real
identity keys and dials a real TCP connection.

Scenarios:
  1. create -> message -> history (both directions)
  2. add member -> epoch rotation -> new member cannot read old epochs
  3. replayed group_msg (fresh envelope nonce, same group/sender/seq)
     -> dropped exactly-once
  4. forged group_msg signature -> INVALID_SIG, nothing stored
  5. non-admin member add -> POLICY_DENIED locally + denied on the wire
  6. remove member (attack) -> removed member gets no new epoch key and
     receives nothing sent after removal

Run: python3 -m pytest tests/test_groups.py -q
"""
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_proto import AcpError, make_envelope  # noqa: E402
from acp_connector import Connector  # noqa: E402
from acp_connector.groups import (  # noqa: E402
    GroupChat, GROUP_MSG,
)

PASS_PHRASE = "groups-test-pass"


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


def audit_has(conn, action, limit=200):
    return any(r["action"] == action
               for r in conn.audit_log(limit=limit))


def make_node(handle):
    home = tempfile.mkdtemp(prefix="acp-groups-test-")
    c = Connector(home, PASS_PHRASE, handle=handle)
    port = c.start_server("127.0.0.1", 0)
    return c, home, port


def trust(a, port_a, b, port_b):
    """Bidirectional trust + live TCP both ways (real keys, real wire)."""
    for x, y, port_y in ((a, b, port_b), (b, a, port_a)):
        x._store_peer(y.peer_id, y.handle, y.identity.ed_pub.hex(),
                      y.identity.x_pub.hex())
        conn = x.transport.connect("127.0.0.1", port_y)
        x._bind_conn(y.peer_id, conn)
        x._spawn_reader(conn)


class BlackHole:
    def __init__(self):
        self.sent = []
        self.peer_addr = None

    def send_env(self, env):
        self.sent.append(env)


# ------------------------------------------------------------------ fixtures
ca, home_a, port_a = make_node("g-alice")
cb, home_b, port_b = make_node("g-bob")
cc, home_c, port_c = make_node("g-carol")
trust(ca, port_a, cb, port_b)
trust(ca, port_a, cc, port_c)
trust(cb, port_b, cc, port_c)

ga, gb, gc = GroupChat(ca), GroupChat(cb), GroupChat(cc)

got_b = []
ev_b = threading.Event()
gb.on_group_message(lambda gid, s, t, seq: (got_b.append((gid, s, t, seq)),
                                            ev_b.set()))
got_c = []
ev_c = threading.Event()
gc.on_group_message(lambda gid, s, t, seq: (got_c.append((gid, s, t, seq)),
                                            ev_c.set()))
GROUP = ga.create_group("test-group", [cb.peer_id])
print(f"group {GROUP} created", flush=True)
wait_until(lambda: gb.get_group(GROUP) is not None, what="bob group sync")
wait_until(lambda: gb.get_group(GROUP)["epoch"] == 1,
           what="bob epoch key")


# ------------------------------------------------------------------ 1. basic
def test_create_message_history():
    assert ga.get_group(GROUP)["admin_id"] == ca.peer_id
    assert set(gb.get_group(GROUP)["members"]) == {ca.peer_id, cb.peer_id}

    ga.send_group_message(GROUP, "hello group from alice")
    assert ev_b.wait(60), "bob never got the group message"
    gid, sender, text, seq = got_b[0]
    assert gid == GROUP and sender == ca.peer_id
    assert text == "hello group from alice" and seq == 1

    # reverse direction
    got_a2 = []
    ev_a2 = threading.Event()
    ga.on_group_message(lambda gid, s, t, seq: (got_a2.append((s, t)),
                                               ev_a2.set()))
    gb.send_group_message(GROUP, "bob here")
    assert ev_a2.wait(60), "alice never got bob's message"
    assert got_a2[0] == (cb.peer_id, "bob here")

    ha = ga.get_history(GROUP)
    hb = gb.get_history(GROUP)
    assert [m["text"] for m in ha] == ["hello group from alice", "bob here"]
    assert [m["text"] for m in hb] == ["hello group from alice", "bob here"]
    assert all(m["epoch"] == 1 for m in ha + hb)


# ------------------------------------------------------------------ 2. add
def test_add_member_rotates_and_new_member_cannot_read_history():
    ga.add_member(GROUP, cc.peer_id)
    wait_until(lambda: gb.get_group(GROUP)["epoch"] == 2,
               what="bob epoch 2")
    wait_until(lambda: gc.get_group(GROUP) is not None
               and gc.get_group(GROUP)["epoch"] == 2,
               what="carol epoch 2")
    assert set(ga.get_group(GROUP)["members"]) == \
        {ca.peer_id, cb.peer_id, cc.peer_id}

    # Carol only ever received the epoch-2 key: no history access.
    assert gc._get_epoch_key(GROUP, 1) is None
    assert gc._get_epoch_key(GROUP, 2) is not None

    # New-epoch traffic reaches everyone still in the group.
    n_b, n_c = len(got_b), len(got_c)
    ga.send_group_message(GROUP, "epoch two message")
    wait_until(lambda: len(got_b) > n_b and len(got_c) > n_c,
               what="epoch-2 delivery")
    assert got_c[-1][2] == "epoch two message"
    assert gc.get_history(GROUP)[-1]["epoch"] == 2


# ------------------------------------------------------------------ 3. replay
def test_replayed_group_msg_dropped():
    # Capture a real group_msg payload off the wire.
    captured = []
    orig = ca._send_plain

    def spy(kind, pid, payload):
        if kind == GROUP_MSG:
            captured.append(payload)
        return orig(kind, pid, payload)

    ca._send_plain = spy
    try:
        n_b = len(got_b)
        ga.send_group_message(GROUP, "replay me once")
        wait_until(lambda: len(got_b) > n_b, what="original delivery")
    finally:
        ca._send_plain = orig
    assert captured, "no group_msg captured"
    payload = captured[-1]
    seq = payload["seq"]

    # Re-sign the SAME payload (group, sender, seq) under a FRESH
    # envelope nonce: passes the connector replay cache, must die in
    # the group-layer per-(group, sender, seq) cache.
    forged_env = make_envelope(GROUP_MSG, ca.peer_id, cb.peer_id, payload,
                               ca.identity.ed_priv)
    before = len(gb.get_history(GROUP))
    cb._on_frame(BlackHole(), forged_env)
    time.sleep(1)
    after = len(gb.get_history(GROUP))
    assert after == before, "replayed group_msg was stored twice"
    assert len(got_b) == n_b + 1, "replayed group_msg re-announced"
    assert audit_has(cb, "group.msg_replay_dropped"), \
        "no replay-drop audit entry"


# ------------------------------------------------------------------ 4. forge
def test_forged_group_msg_signature_rejected():
    payload = {"group_id": GROUP, "epoch": 999, "seq": 4242,
               "nonce": "00", "ct": "00"}
    env = make_envelope(GROUP_MSG, ca.peer_id, cb.peer_id, payload,
                        ca.identity.ed_priv)
    tampered = dict(env)
    tampered["payload"] = dict(payload)
    tampered["payload"]["ct"] = "ff"  # flip ciphertext, keep signature
    before = len(gb.get_history(GROUP))
    cb._on_frame(BlackHole(), tampered)
    time.sleep(1)
    assert len(gb.get_history(GROUP)) == before, \
        "forged group_msg was stored"
    assert audit_has(cb, "envelope.rejected"), \
        "forged envelope not audit-logged as rejected"


# ------------------------------------------------------------------ 5. perms
def test_non_admin_add_rejected():
    # Local API: bob is not admin (carol is a real peer, so the admin
    # check — not peer lookup — is what fires).
    expect_acp_error(lambda: gb.add_member(GROUP, cc.peer_id),
                     "POLICY_DENIED")
    # Wire: bob sends a signed group_member_add anyway; alice (admin)
    # must deny it and leave membership untouched.
    before = set(ga.get_group(GROUP)["members"])
    fake_pid = "zz" + "9" * 41
    cb._send_plain("group_member_add", ca.peer_id,
                   {"group_id": GROUP, "member_id": fake_pid})
    wait_until(lambda: audit_has(ca, "group.member_add_denied"),
               what="add-denied audit")
    assert set(ga.get_group(GROUP)["members"]) == before
    assert fake_pid not in ga.get_group(GROUP)["members"]


# ------------------------------------------------------------------ 6. remove
def test_remove_member_cannot_read_future_messages():
    ga.remove_member(GROUP, cb.peer_id)
    wait_until(lambda: gc.get_group(GROUP)["epoch"] == 3,
               what="carol epoch 3")
    assert cb.peer_id not in ga.get_group(GROUP)["members"]

    # Attack check: bob never received the epoch-3 key...
    assert gb._get_epoch_key(GROUP, 3) is None
    # ...and traffic sent after his removal never reaches him.
    n_b = len(got_b)
    ga.send_group_message(GROUP, "after bob left")
    wait_until(lambda: len(got_c) > 0 and
               got_c[-1][2] == "after bob left",
               what="carol gets post-removal message")
    time.sleep(2)
    assert len(got_b) == n_b, "removed member received a message"
    assert all(m["text"] != "after bob left"
               for m in gb.get_history(GROUP)), \
        "removed member stored a post-removal message"


def teardown_module():
    for c in (ca, cb, cc):
        try:
            c.stop()
        except Exception:
            pass
    for h in (home_a, home_b, home_c):
        shutil.rmtree(h, ignore_errors=True)
