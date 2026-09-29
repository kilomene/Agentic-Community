"""Workstream F: end-to-end proof of agent-to-agent instant messaging.

Two REAL Connector instances (Alice and Bob), servers never started, no
network, no humans. They are linked by a fake in-process transport that
delivers REAL signed envelopes — E2E-encrypted where the protocol says
so — straight into the peer's receive path. Nothing is mocked except
the byte transport: E2E crypto, Ed25519 signatures, replay checks,
inbox threading/read-state, typing TTL, sender-key group crypto, and
the autopilot hook subprocess are all the real code.

Legs (all deterministic — the fake transport is fully synchronous):
  1. direct:   Alice sends "status?" -> Bob's autopilot (a REAL hook
               subprocess) replies, threaded and auto-marked.
  2. inbox:    on Alice's side the reply carries reply_to == the
               question's id; get_thread/unread_count/mark_read work.
  3. channel:  Alice opens a project-linked channel and posts with task
               refs; Bob's autopilot answers; refs round-trip intact on
               both databases with a shared deterministic message id.
  4. typing:   Alice.typing_start(Bob) -> Bob.is_typing(Alice) is True.
  5. loop:     an auto=True message from Alice gets NO autopilot reply
               (auto_guard), so two autopilots can never ping-pong.

Run: python3 -m pytest tests/test_im_e2e.py -q
"""
import json
import os
import sys
import tempfile
import shutil

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

from acp_connector import Connector  # noqa: E402
from autopilot import Autopilot  # noqa: E402


# ------------------------------------------------------------ fake transport

class _FakeLink:
    """In-memory stand-in for a transport connection.

    send_env delivers the REAL envelope (signature + E2E ciphertext
    intact) synchronously into the peer's receive path.
    """

    def __init__(self, peer):
        self.peer = peer
        self.sent = []

    def send_env(self, env):
        self.sent.append(env)
        self.peer._on_frame(self, env)


def _link(a, b):
    """Route every envelope between two connectors, in memory."""
    la, lb = _FakeLink(b), _FakeLink(a)

    def conn_for_a(pid):
        assert pid == b.peer_id, f"no fake route to {pid[:16]}"
        return la

    def conn_for_b(pid):
        assert pid == a.peer_id, f"no fake route to {pid[:16]}"
        return lb

    a._get_conn = conn_for_a
    b._get_conn = conn_for_b


# ------------------------------------------------------------ hook script

_HOOK_SRC = '''"""E2E-test autopilot hook: project-aware answers from the real DB.

Reads the event dict on stdin, answers {"reply": ...} on stdout. It
reaches the agent's own connector.db (read-only) to prove the hook
subprocess path end to end: real process boundary, real database.
"""
import json
import os
import sqlite3
import sys

HOME = "__HOME_B__"


def _db_counts():
    try:
        con = sqlite3.connect(
            "file:%s?mode=ro" % os.path.join(HOME, "connector.db"),
            uri=True, timeout=5)
        try:
            n_projects = con.execute(
                "SELECT COUNT(*) FROM projects").fetchone()[0]
            n_tasks = con.execute(
                "SELECT COUNT(*) FROM tasks"
                " WHERE status != 'completed'").fetchone()[0]
        finally:
            con.close()
        return n_projects, n_tasks
    except Exception:
        return -1, -1


def main():
    try:
        event = json.loads(sys.stdin.read())
    except ValueError:
        return
    text = event.get("text") or ""
    n_projects, n_tasks = _db_counts()
    if event.get("kind") == "group_message":
        reply = ("hook: noted %r in channel %s "
                 "(%d projects, %d open tasks on my side)"
                 % (text, event.get("group_id"), n_projects, n_tasks))
    elif text.strip().lower() == "status?":
        reply = ("hook: status ok - %d projects, %d open tasks"
                 % (n_projects, n_tasks))
    else:
        reply = "hook: acknowledged %r" % text
    sys.stdout.write(json.dumps({"reply": reply}))


main()
'''


def _write_bob_config(home_b, alice_pid, channels=None):
    cfg = {"peers": {alice_pid: {"mode": "hook", "hook": "status_hook"}},
           "channels": channels or {}}
    with open(os.path.join(home_b, "autopilot.json"), "w") as fh:
        json.dump(cfg, fh)


# ------------------------------------------------------------ fixture

@pytest.fixture()
def pair():
    """Two real, mutually-trusting connectors; Bob runs an autopilot."""
    home_a = tempfile.mkdtemp(prefix="im-e2e-alice-")
    home_b = tempfile.mkdtemp(prefix="im-e2e-bob-")
    a = Connector(home_a, "pw-alice", handle="e2e-alice")
    b = Connector(home_b, "pw-bob", handle="e2e-bob")
    _link(a, b)
    # Trust with the peers' REAL keys: E2E + signatures run for real.
    a.store.add_peer(b.peer_id, "e2e-bob",
                     b.identity.ed_pub.hex(), b.identity.x_pub.hex())
    b.store.add_peer(a.peer_id, "e2e-alice",
                     a.identity.ed_pub.hex(), a.identity.x_pub.hex())

    # Bob's autopilot: real hook subprocess, synchronous handling.
    hooks_dir = os.path.join(home_b, "autopilot_hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    with open(os.path.join(hooks_dir, "status_hook.py"), "w") as fh:
        fh.write(_HOOK_SRC.replace("__HOME_B__", home_b))
    _write_bob_config(home_b, a.peer_id)
    # Bob's brain owns a project so the hook has something true to say.
    proj_b = b.project_create("shadow-ops", "e2e project")
    b.task_add(proj_b, "write spec")
    b.task_add(proj_b, "build it")

    ap = Autopilot(home_b, b, groups=b.groups, background=False)
    b.on_message(ap.handle_direct)
    b.groups.on_group_message(ap.handle_group)

    yield a, b, ap, home_a, home_b

    for c in (a, b):
        try:
            c.stop()
        except Exception:
            pass
    shutil.rmtree(home_a, ignore_errors=True)
    shutil.rmtree(home_b, ignore_errors=True)


def _audit_details(store, action, limit=200):
    out = []
    for e in store.list_audit(limit=limit):
        if e["action"] == action:
            try:
                details = json.loads(e["details"])
            except (ValueError, TypeError):
                details = {}
            out.append((e, details))
    return out


# ------------------------------------------------------------ 1+2. direct + inbox

def test_direct_autopilot_reply_is_threaded_and_marked_auto(pair):
    a, b, ap, home_a, home_b = pair

    q1 = a.send_message(b.peer_id, "status?")
    # Bob's autopilot replied synchronously, inside the send above:
    # real hook subprocess -> threaded send -> real E2E -> Alice's inbox.
    inbox = a.inbox(peer_pid=b.peer_id)
    assert len(inbox) == 1, f"expected exactly Bob's reply, got {inbox}"
    reply = inbox[0]
    assert reply["reply_to"] == q1, "reply must thread onto the question"
    assert reply["auto"] == 1, "autopilot replies must carry the auto flag"
    assert "status ok" in reply["text"]
    assert "2 open tasks" in reply["text"], reply["text"]

    # Inbox semantics on Alice's side.
    assert a.unread_count() == 1
    assert [m["message_id"] for m in a.inbox(unread_only=True)] == \
        [reply["message_id"]]
    thread = a.get_thread(q1)
    assert [m["message_id"] for m in thread] == [q1, reply["message_id"]]
    assert [m["text"] for m in thread] == ["status?", reply["text"]]
    a.mark_read(reply["message_id"])
    assert a.unread_count() == 0
    assert a.inbox(unread_only=True) == []

    # Bob audited the decision (metadata only, never message text).
    sent = _audit_details(b.store, "autopilot.reply_sent")
    assert len(sent) == 1
    assert sent[0][0]["target"] == a.peer_id
    assert sent[0][1]["hook"] == "status_hook"


# ------------------------------------------------------------ 3. channel

def test_channel_autopilot_answers_task_post_refs_roundtrip(pair):
    a, b, ap, home_a, home_b = pair
    ga, gb = a.groups, b.groups

    proj = a.project_create("shadow-ops", "channel project")
    t1 = a.task_add(proj, "write spec")
    chan = ga.open_channel("ops", [b.peer_id], project_id=proj,
                           topic="sprint-1")
    assert ga.get_channel(chan)["project_id"] == proj
    # Opt this channel into Bob's autopilot (config is re-read per event).
    _write_bob_config(home_b, a.peer_id,
                      channels={chan: {"mode": "hook",
                                       "hook": "status_hook"}})

    post_id = ga.send_channel_message(chan, "starting on the spec",
                                      refs=[t1])
    # Bob stored the post with refs intact (sender-key crypto ran for
    # real over the fake transport).
    post_b = [m for m in gb.get_channel_history(chan)
              if m["message_id"] == post_id]
    assert post_b, "post missing from Bob's channel history"
    assert post_b[0]["refs"] == [t1]
    assert post_b[0]["reply_to"] is None

    # Bob's autopilot answered the post, threaded, on both databases
    # under the same deterministic message id.
    answers_a = [m for m in ga.get_channel_history(chan)
                 if m["sender_id"] == b.peer_id]
    assert len(answers_a) == 1, "expected exactly one autopilot answer"
    answer = answers_a[0]
    assert answer["reply_to"] == post_id
    assert "noted" in answer["text"] and "starting on the spec" in \
        answer["text"]
    answers_b = [m for m in gb.get_channel_history(chan)
                 if m["message_id"] == answer["message_id"]]
    assert answers_b and answers_b[0]["text"] == answer["text"]

    thread = ga.get_channel_thread(chan, post_id)
    assert [m["message_id"] for m in thread] == [post_id,
                                                answer["message_id"]]


# ------------------------------------------------------------ 4. typing

def test_typing_indicator_end_to_end(pair):
    a, b, ap, home_a, home_b = pair
    assert not b.is_typing(a.peer_id)
    a.typing_start(b.peer_id)
    assert b.is_typing(a.peer_id), \
        "Bob must see Alice's typing indicator (signed plaintext kind)"
    a.typing_stop(b.peer_id)
    assert not b.is_typing(a.peer_id)


# ------------------------------------------------------------ 5. loop guard

def test_loop_guard_ignores_auto_messages(pair):
    a, b, ap, home_a, home_b = pair
    # A normal message first, so the guard leg is not the first event.
    a.send_message(b.peer_id, "status?")
    assert a.unread_count() == 1

    # Now an autopilot-generated message: Bob must NOT answer it.
    a.send_message(b.peer_id, "bot chatter", auto=True)
    assert a.unread_count() == 1, \
        "no reply may come back for an auto=True message"
    skipped = _audit_details(b.store, "autopilot.skipped")
    reasons = [d.get("reason") for _, d in skipped]
    assert "auto_guard" in reasons, f"expected auto_guard, got {reasons}"
