"""Tests for group / project channels (packages/acp_connector/groups.py).

Channels are group chats bound to a project: open_channel /
link_project / unlink_project / get_channel, send_channel_message with
reply_to + task refs (refs cross-checked against the linked project's
tasks), deterministic shared message ids so reply_to threads resolve on
every member's database, and malformed inner fields dropped + audited.

Real connectors on localhost with real keys and real wire crypto, same
in-process pattern as tests/test_groups.py: trust is established
directly and each side dials a real TCP connection.

Scenarios:
  1. open_channel with project link -> get_channel shows project_id/topic
  2. link/unlink: non-admin -> POLICY_DENIED; unknown project -> NOT_FOUND
  3. send_channel_message with refs to real tasks -> members receive,
     refs intact on both databases, shared deterministic message id
  4. refs to nonexistent / foreign-project task on a linked channel ->
     NOT_FOUND, nothing sent
  5. unlinked channel: refs type-validated and stored, no cross-check
  6. reply_to threading: 3-message thread resolves ordered on the second
     member's database
  7. backward compat: old-format inner (no new keys) accepted by new code
  8. backward compat: new-format inner still readable by a minimal
     text/sender/seq-only parser
  9. attack: refs = "not-a-list" (and other malformed values) -> dropped
     + audited
 10. attack: non-member posting -> dropped (existing behavior)
 11. attack: forged inner sender mismatch -> dropped (existing behavior)
 12. send_group_message still works exactly as before (plain inner)

Run: python3 -m pytest tests/test_im_channels.py -q
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_proto import (  # noqa: E402
    AcpError, make_envelope, canonical, b62encode_fixed,
)
from acp_crypto import aead_encrypt, random_bytes  # noqa: E402
from acp_connector import Connector  # noqa: E402
from acp_connector.groups import (  # noqa: E402
    GroupChat, GROUP_MSG,
)

PASS_PHRASE = "channels-test-pass"


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
    home = tempfile.mkdtemp(prefix="acp-channels-test-")
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
ca, home_a, port_a = make_node("c-alice")
cb, home_b, port_b = make_node("c-bob")
cc, home_c, port_c = make_node("c-carol")
trust(ca, port_a, cb, port_b)
trust(ca, port_a, cc, port_c)
trust(cb, port_b, cc, port_c)

ga, gb, gc = GroupChat(ca), GroupChat(cb), GroupChat(cc)

got_b = []
ev_b = threading.Event()
gb.on_group_message(lambda gid, s, t, seq: (got_b.append((gid, s, t, seq)),
                                            ev_b.set()))

PROJ = ca.projects.create("chan-proj", "channel test project")
T1 = ca.projects.add_task(PROJ, "write spec")
T2 = ca.projects.add_task(PROJ, "build it")
OTHER_PROJ = ca.projects.create("other-proj")
TX = ca.projects.add_task(OTHER_PROJ, "unrelated task")

CHAN = ga.open_channel("chan", [cb.peer_id], project_id=PROJ,
                       topic="sprint-1")
print(f"channel {CHAN} opened on project {PROJ}", flush=True)
wait_until(lambda: gb.get_group(CHAN) is not None, what="bob group sync")
wait_until(lambda: gb.get_group(CHAN)["epoch"] == 1,
           what="bob epoch key")


def _next_seq(gchat, group_id, sender_pid):
    """Consume the next seq for hand-crafted envelopes."""
    return gchat._next_seq(group_id, sender_pid)


def craft_group_msg(sender_gchat, group_id, text, seq, extra=None,
                    inner_sender=None):
    """Build a signed group_msg payload from the sender's side, encrypted
    under the sender's current epoch key. The caller delivers it with
    deliver() so malformed/old-format inners can be tested."""
    c = sender_gchat._c
    g = sender_gchat.get_group(group_id)
    epoch = int(g["epoch"])
    key = sender_gchat._get_epoch_key(group_id, epoch)
    inner = {"text": text, "sender": inner_sender or c.peer_id, "seq": seq}
    if extra:
        inner.update(extra)
    nonce = random_bytes(12)
    pt = canonical(inner)
    aad = canonical({"group_id": group_id, "epoch": epoch, "seq": seq})
    ct = aead_encrypt(key, nonce, pt, aad)
    return {"group_id": group_id, "epoch": epoch, "seq": seq,
            "nonce": b62encode_fixed(nonce), "ct": b62encode_fixed(ct)}


def deliver(receiver_c, sender_c, payload):
    env = make_envelope(GROUP_MSG, sender_c.peer_id, receiver_c.peer_id,
                        payload, sender_c.identity.ed_priv)
    receiver_c._on_frame(BlackHole(), env)


# ------------------------------------------------------------------ 1. open
def test_open_channel_links_project():
    ch = ga.get_channel(CHAN)
    assert ch["project_id"] == PROJ
    assert ch["topic"] == "sprint-1"
    assert ch["admin_id"] == ca.peer_id
    assert set(ch["members"]) == {ca.peer_id, cb.peer_id}

    # Plain group: no project binding.
    plain = ga.open_channel("plain", [cb.peer_id])
    wait_until(lambda: gb.get_group(plain) is not None, what="plain sync")
    ch2 = ga.get_channel(plain)
    assert ch2["project_id"] is None
    assert ch2["topic"] == ""

    assert ga.get_channel("g-does-not-exist") is None
    expect_acp_error(
        lambda: ga.open_channel("x", [cb.peer_id],
                                project_id="proj_does_not_exist"),
        "NOT_FOUND")


# ------------------------------------------------------------------ 2. link
def test_link_unlink_permissions():
    # Non-admin (bob is a member, not admin): both ops denied.
    expect_acp_error(lambda: gb.link_project(CHAN, PROJ), "POLICY_DENIED")
    expect_acp_error(lambda: gb.unlink_project(CHAN), "POLICY_DENIED")
    # Admin, unknown project.
    expect_acp_error(lambda: ga.link_project(CHAN, "proj_missing"),
                     "NOT_FOUND")
    # Admin, unknown group.
    expect_acp_error(lambda: ga.link_project("g-missing", PROJ), "INTERNAL")

    ga.unlink_project(CHAN)
    assert ga.get_channel(CHAN)["project_id"] is None
    ga.link_project(CHAN, PROJ)
    assert ga.get_channel(CHAN)["project_id"] == PROJ


# ------------------------------------------------------------------ 3. refs
def test_send_channel_message_with_refs():
    n = len(got_b)
    msg_id = ga.send_channel_message(CHAN, "shipping task one",
                                     refs=[T1, T2])
    wait_until(lambda: len(got_b) > n, what="channel msg delivery")
    gid, sender, text, seq = got_b[-1]
    assert gid == CHAN and sender == ca.peer_id
    assert text == "shipping task one"

    # Receiver's database: refs intact, shared message id.
    rows = [m for m in gb.get_channel_history(CHAN)
            if m["message_id"] == msg_id]
    assert rows, "message missing on receiver db"
    assert rows[0]["refs"] == [T1, T2]
    assert rows[0]["reply_to"] is None

    # Sender's database: identical id and refs.
    rows_a = [m for m in ga.get_channel_history(CHAN)
              if m["message_id"] == msg_id]
    assert rows_a and rows_a[0]["refs"] == [T1, T2]
    assert rows_a[0]["message_id"] == msg_id


# ------------------------------------------------------------------ 4. refs
def test_refs_nonexistent_task_rejected():
    sent = []
    orig = ca._send_plain

    def spy(kind, pid, payload):
        sent.append(kind)
        return orig(kind, pid, payload)

    ca._send_plain = spy
    try:
        before = len(gb.get_channel_history(CHAN))
        expect_acp_error(
            lambda: ga.send_channel_message(CHAN, "bad ref",
                                            refs=["task_nope"]),
            "NOT_FOUND")
        # Task exists but belongs to a different project.
        expect_acp_error(
            lambda: ga.send_channel_message(CHAN, "cross ref", refs=[TX]),
            "NOT_FOUND")
        # Type validation happens before anything is sent, too.
        expect_acp_error(
            lambda: ga.send_channel_message(CHAN, "x", refs="not-a-list"),
            "INTERNAL")
        expect_acp_error(
            lambda: ga.send_channel_message(CHAN, "x", refs=[T1, 42]),
            "INTERNAL")
        expect_acp_error(
            lambda: ga.send_channel_message(CHAN, "x", reply_to=123),
            "INTERNAL")
    finally:
        ca._send_plain = orig
    assert GROUP_MSG not in sent, "rejected send leaked a group_msg"
    time.sleep(1)
    assert len(gb.get_channel_history(CHAN)) == before, \
        "rejected refs reached the receiver"


# ------------------------------------------------------------------ 5. free
def test_unlinked_channel_refs_stored_without_crosscheck():
    ga.unlink_project(CHAN)
    assert ga.get_channel(CHAN)["project_id"] is None
    # Unlinked: no project to check against -> validated, stored, kept.
    msg_id = ga.send_channel_message(CHAN, "free refs", refs=["task_nope"])
    rows = [m for m in ga.get_channel_history(CHAN)
            if m["message_id"] == msg_id]
    assert rows and rows[0]["refs"] == ["task_nope"]
    wait_until(lambda: any(t[2] == "free refs" for t in got_b),
               what="bob free-refs sync")
    ga.link_project(CHAN, PROJ)
    assert ga.get_channel(CHAN)["project_id"] == PROJ


# ------------------------------------------------------------------ 6. plain
def test_send_group_message_unchanged():
    n = len(got_b)
    msg_id = ga.send_group_message(CHAN, "legacy plain")
    wait_until(lambda: len(got_b) > n, what="legacy delivery")
    assert got_b[-1][2] == "legacy plain"
    row = [m for m in gb.get_channel_history(CHAN)
           if m["message_id"] == msg_id][0]
    assert row["refs"] == [] and row["reply_to"] is None
    assert row["text"] == "legacy plain"


# ------------------------------------------------------------------ 7. thread
def test_reply_to_threading():
    root = ga.send_channel_message(CHAN, "thread root")
    wait_until(lambda: any(m["message_id"] == root
                           for m in gb.get_channel_history(CHAN)),
               what="bob root sync")
    r1 = ga.send_channel_message(CHAN, "first reply", reply_to=root)
    wait_until(lambda: any(m["message_id"] == r1
                           for m in gb.get_channel_history(CHAN)),
               what="bob r1 sync")
    # The second member replies to alice's reply: reply_to must resolve
    # on both databases.
    r2 = gb.send_channel_message(CHAN, "second reply", reply_to=r1)
    wait_until(lambda: len(ga.get_channel_thread(CHAN, root)) == 3,
               what="alice thread complete")
    wait_until(lambda: len(gb.get_channel_thread(CHAN, root)) == 3,
               what="bob thread complete")
    for gchat in (ga, gb):
        th = gchat.get_channel_thread(CHAN, root)
        assert [m["text"] for m in th] == ["thread root", "first reply",
                                          "second reply"], \
            f"thread order wrong: {[m['text'] for m in th]}"
        assert [m["reply_to"] for m in th] == [None, root, r1]
        assert [m["refs"] for m in th] == [[], [], []]
    # Unknown root -> empty thread, not an error.
    assert ga.get_channel_thread(CHAN, "gm-nope") == []
    assert ga.get_channel_thread("g-nope", root) == []


# ------------------------------------------------------------------ 8. compat
def test_old_format_inner_accepted():
    # Simulate a V-current peer: inner dict carries no reply_to/refs
    # keys at all. The new code must accept and store it.
    seq = _next_seq(gb, CHAN, cb.peer_id)
    payload = craft_group_msg(gb, CHAN, "old style msg", seq)
    deliver(ca, cb, payload)
    wait_until(lambda: any(m["text"] == "old style msg"
                           for m in ga.get_channel_history(CHAN)),
               what="old-format delivery")
    row = [m for m in ga.get_channel_history(CHAN)
           if m["text"] == "old style msg"][0]
    assert row["refs"] == []
    assert row["reply_to"] is None


def test_new_format_readable_by_minimal_parser():
    # A peer that only knows text/sender/seq still extracts them from a
    # V-next inner dict carrying reply_to + refs.
    inner = {"text": "hi", "sender": "pidX", "seq": 7,
             "reply_to": "gm-abc", "refs": ["task_1"]}
    pt = canonical(inner)
    parsed = json.loads(pt.decode("utf-8"))
    assert (parsed["text"], parsed["sender"], parsed["seq"]) == \
        ("hi", "pidX", 7)


# ------------------------------------------------------------------ 9. bad
def test_malformed_refs_dropped_and_audited():
    bad_values = ["not-a-list", [1, 2], ["ok", 42], {"a": 1}, 12345]
    for bad in bad_values:
        seq = _next_seq(gb, CHAN, cb.peer_id)
        payload = craft_group_msg(gb, CHAN, "evil", seq,
                                  extra={"refs": bad})
        before = len(ga.get_channel_history(CHAN))
        deliver(ca, cb, payload)
        time.sleep(0.5)
        after = len(ga.get_channel_history(CHAN))
        assert after == before, \
            f"malformed refs {bad!r} were stored"
    # Malformed reply_to type: also dropped.
    seq = _next_seq(gb, CHAN, cb.peer_id)
    payload = craft_group_msg(gb, CHAN, "evil2", seq,
                              extra={"reply_to": 123})
    before = len(ga.get_channel_history(CHAN))
    deliver(ca, cb, payload)
    time.sleep(0.5)
    assert len(ga.get_channel_history(CHAN)) == before
    assert audit_has(ca, "group.msg_bad_fields"), \
        "malformed inner fields not audit-logged"


# ------------------------------------------------------------------ 10. outs
def test_non_member_post_dropped():
    # Carol is a trusted peer but not a CHAN member; she signs a real
    # envelope. Dropped at the membership check, before any decrypt.
    payload = {"group_id": CHAN, "epoch": 1, "seq": 1,
               "nonce": "AA", "ct": "BB"}
    before = len(ga.get_channel_history(CHAN))
    deliver(ca, cc, payload)
    wait_until(lambda: audit_has(ca, "group.msg_not_member"),
               what="not-member audit")
    time.sleep(0.5)
    assert len(ga.get_channel_history(CHAN)) == before, \
        "non-member message was stored"


# ------------------------------------------------------------------ 11. forg
def test_forged_inner_sender_dropped():
    # Envelope really from bob, but the inner claims alice sent it.
    seq = _next_seq(gb, CHAN, cb.peer_id)
    payload = craft_group_msg(gb, CHAN, "impersonate", seq,
                              inner_sender=ca.peer_id)
    before = len(ga.get_channel_history(CHAN))
    deliver(ca, cb, payload)
    wait_until(lambda: audit_has(ca, "group.msg_inner_mismatch"),
               what="inner-mismatch audit")
    time.sleep(0.5)
    assert len(ga.get_channel_history(CHAN)) == before, \
        "forged inner sender was stored"


def teardown_module():
    for c in (ca, cb, cc):
        try:
            c.stop()
        except Exception:
            pass
    for h in (home_a, home_b, home_c):
        shutil.rmtree(h, ignore_errors=True)
