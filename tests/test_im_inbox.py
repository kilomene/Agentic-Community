"""Workstream A: Inbox + Replies tests.

No network: two real Connector instances (servers never started) linked
by a fake in-memory transport that routes MSG/MSG_ACK straight into the
peer's messaging handlers.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_connector import Connector, AcpError
from acp_connector.store import Store
from acp_proto import MSG, MSG_ACK


def _link(a, b):
    """Route _send_e2e between two connectors synchronously, in memory."""
    peers = {a.peer_id: a, b.peer_id: b}
    a.sent_payloads = []
    b.sent_payloads = []

    def make(src):
        def fake_send(kind, to_pid, payload):
            src.sent_payloads.append((kind, dict(payload)))
            peer = peers.get(to_pid)
            assert peer is not None, f"no fake route to {to_pid[:16]}"
            env = {"kind": kind, "from": src.peer_id, "to": to_pid,
                   "ts": int(time.time())}
            if kind == MSG:
                peer.messaging.handle_msg(env, payload)
            elif kind == MSG_ACK:
                peer.messaging.handle_ack(env, payload)
            else:
                raise AssertionError(f"unexpected kind {kind}")
        return fake_send

    a._send_e2e = make(a)
    b._send_e2e = make(b)


@pytest.fixture()
def pair():
    h1 = tempfile.mkdtemp(prefix="im-a-")
    h2 = tempfile.mkdtemp(prefix="im-b-")
    a = Connector(h1, "pw-a", handle="agent-a")
    b = Connector(h2, "pw-b", handle="agent-b")
    _link(a, b)
    a.store.add_peer(b.peer_id, "agent-b", "11" * 32, "aa" * 32)
    b.store.add_peer(a.peer_id, "agent-a", "22" * 32, "bb" * 32)
    yield a, b
    for c in (a, b):
        try:
            c.stop()
        except Exception:
            pass
    shutil.rmtree(h1, ignore_errors=True)
    shutil.rmtree(h2, ignore_errors=True)


def expect_acp_error(fn, code):
    with pytest.raises(AcpError) as ei:
        fn()
    assert ei.value.code == code, f"expected {code}, got {ei.value.code}"
    return ei.value


# ------------------------------------------------------------ migration
def test_migration_from_old_schema(tmp_path):
    """An old DB (messages without new columns) migrates cleanly."""
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE messages(
      message_id   TEXT PRIMARY KEY,
      sender_id    TEXT NOT NULL,
      scope        TEXT NOT NULL,
      scope_id     TEXT,
      text         TEXT NOT NULL,
      timestamp    INTEGER NOT NULL,
      status       TEXT NOT NULL DEFAULT 'delivered',
      created_at   INTEGER NOT NULL
    )""")
    con.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)",
                ("old1", "peer-x", "direct", None, "legacy text",
                 1700000000, "delivered", 1700000000))
    con.commit()
    con.close()

    s = Store(db)
    cols = {r["name"] for r in
            s._db.execute("PRAGMA table_info(messages)").fetchall()}
    assert {"read_at", "reply_to", "auto"} <= cols
    row = s.get_message("old1")
    assert row is not None and row["text"] == "legacy text"
    assert row["read_at"] == 0 and row["reply_to"] is None and row["auto"] == 0
    # idempotent: reopening must not fail or duplicate anything
    s.close()
    s2 = Store(db)
    cols2 = {r["name"] for r in
             s2._db.execute("PRAGMA table_info(messages)").fetchall()}
    assert cols2 == cols
    s2.close()


def test_new_db_has_columns(tmp_path):
    s = Store(str(tmp_path / "new.db"))
    cols = {r["name"] for r in
            s._db.execute("PRAGMA table_info(messages)").fetchall()}
    assert {"read_at", "reply_to", "auto"} <= cols
    s.close()


# ------------------------------------------------------- round trip
def test_send_receive_reply_to_auto(pair):
    a, b = pair
    got = []
    b.messaging.on_message(lambda s, t, m: got.append((s, t, m)))
    m1 = a.messaging.send_message(b.peer_id, "hello", auto=True)
    assert len(got) == 1
    sender, text, msg_id = got[0]
    assert sender == a.peer_id and text == "hello" and msg_id == m1

    # wire: auto only when True, reply_to only when given
    kind, payload = a.sent_payloads[0]
    assert kind == MSG and payload["auto"] is True
    assert "reply_to" not in payload

    # both sides persisted the new fields
    out = a.store.get_message(m1)
    assert out["status"] == "acked" and out["auto"] == 1
    assert out["reply_to"] is None and out["read_at"] != 0
    inn = b.store.get_message(m1)
    assert inn["sender_id"] == a.peer_id and inn["auto"] == 1
    assert inn["reply_to"] is None and inn["read_at"] == 0

    # reply round trip
    m2 = b.messaging.send_reply(a.peer_id, m1, "got it")
    msgs = [p for k, p in b.sent_payloads if k == MSG]
    assert len(msgs) == 1
    payload2 = msgs[0]
    assert payload2["reply_to"] == m1
    assert "auto" not in payload2  # wire stays minimal
    r1 = b.store.get_message(m2)
    assert r1["reply_to"] == m1 and r1["auto"] == 0
    r2 = a.store.get_message(m2)
    assert r2["reply_to"] == m1 and r2["sender_id"] == b.peer_id


def test_plain_send_has_no_optional_wire_fields(pair):
    a, b = pair
    m = a.messaging.send_message(b.peer_id, "plain")
    _kind, payload = a.sent_payloads[0]
    assert set(payload) == {"text", "msg_id"}
    assert a.store.get_message(m)["auto"] == 0


def test_send_reply_unknown_reply_to(pair):
    a, b = pair
    expect_acp_error(lambda: a.messaging.send_reply(b.peer_id, "nope", "x"),
                     "NOT_FOUND")
    expect_acp_error(lambda: a.messaging.send_message(
        b.peer_id, "x", reply_to="nope"), "NOT_FOUND")
    expect_acp_error(lambda: a.messaging.send_message(
        b.peer_id, "x", reply_to=""), "NOT_FOUND")
    expect_acp_error(lambda: a.messaging.send_message(
        b.peer_id, "x", reply_to=123), "NOT_FOUND")


# ----------------------------------------------------------------- thread
def test_thread_three_messages(pair):
    a, b = pair
    m1 = a.messaging.send_message(b.peer_id, "one")
    m2 = b.messaging.send_reply(a.peer_id, m1, "two")
    m3 = a.messaging.send_reply(b.peer_id, m2, "three")
    for store in (a.store, b.store):
        t = store.get_thread(m3)
        assert [m["message_id"] for m in t] == [m1, m2, m3]
        t_root = store.get_thread(m1)
        assert [m["message_id"] for m in t_root] == [m1, m2, m3]
        assert [m["text"] for m in t] == ["one", "two", "three"]
    expect_acp_error(lambda: a.store.get_thread("unknown"), "NOT_FOUND")


def test_thread_dangling_reply_to():
    """A reply_to pointing at nothing stored still yields a 1-msg thread."""
    s = Store(":memory:")
    now = int(time.time())
    s.add_message("lonely", "p", "direct", None, "t", now, "delivered", now,
                  reply_to="ghost")
    t = s.get_thread("lonely")
    assert [m["message_id"] for m in t] == ["lonely"]
    s.close()


# ------------------------------------------------- read state / inbox
def test_read_state_and_inbox(pair):
    a, b = pair
    m1 = a.messaging.send_message(b.peer_id, "one")
    m2 = a.messaging.send_message(b.peer_id, "two")
    # inbound on b: two unread; outbound on a: already "read"
    assert b.store.unread_count() == 2
    assert a.store.unread_count() == 0

    b.store.mark_read(m1)
    assert b.store.unread_count() == 1
    assert b.store.get_message(m1)["read_at"] != 0
    b.store.mark_unread(m1)
    assert b.store.unread_count() == 2
    assert b.store.get_message(m1)["read_at"] == 0

    unread = b.store.list_inbox(unread_only=True)
    assert {m["message_id"] for m in unread} == {m1, m2}
    allb = b.store.list_inbox()
    assert len(allb) == 2
    # newest-first
    assert allb[0]["created_at"] >= allb[1]["created_at"]
    for m in allb:
        assert "read_at" in m and "reply_to" in m and "auto" in m

    # peer filter: inbound from a only
    bypeer = b.store.list_inbox(peer_pid=a.peer_id)
    assert len(bypeer) == 2
    byother = b.store.list_inbox(peer_pid="nobody")
    assert byother == []

    expect_acp_error(lambda: b.store.mark_read("nope"), "NOT_FOUND")
    expect_acp_error(lambda: b.store.mark_unread("nope"), "NOT_FOUND")


def test_list_inbox_newest_first_order():
    s = Store(":memory:")
    s.add_message("m1", "p", "direct", None, "a", 1, "delivered", 100)
    s.add_message("m2", "p", "direct", None, "b", 2, "delivered", 300)
    s.add_message("m3", "p", "direct", None, "c", 3, "delivered", 200)
    got = s.list_inbox(limit=10)
    assert [m["message_id"] for m in got] == ["m2", "m3", "m1"]
    assert [m["message_id"] for m in s.list_inbox(limit=2)] == ["m2", "m3"]
    s.close()


# ------------------------------------------------- inbound edge cases
def test_inbound_garbage_reply_to_dropped(pair):
    a, b = pair
    mid = "f" * 32
    b.messaging.handle_msg({"from": a.peer_id, "ts": int(time.time())},
                           {"msg_id": mid, "text": "garbage field",
                            "reply_to": ["not", "a", "string"]})
    row = b.store.get_message(mid)
    assert row is not None and row["text"] == "garbage field"
    assert row["reply_to"] is None  # field dropped, message kept
    audit = b.store.list_audit(limit=50)
    assert any(e["action"] == "message.bad_reply_to" and
               e["target"] == mid for e in audit)


def test_inbound_auto_flag_stored_as_received(pair):
    a, b = pair
    ts = int(time.time())
    m_true = "a" * 32
    b.messaging.handle_msg({"from": a.peer_id, "ts": ts},
                           {"msg_id": m_true, "text": "auto msg",
                            "auto": True})
    assert b.store.get_message(m_true)["auto"] == 1
    m_str = "b" * 32
    b.messaging.handle_msg({"from": a.peer_id, "ts": ts},
                           {"msg_id": m_str, "text": "fake auto",
                            "auto": "yes"})
    assert b.store.get_message(m_str)["auto"] == 0
    m_absent = "c" * 32
    b.messaging.handle_msg({"from": a.peer_id, "ts": ts},
                           {"msg_id": m_absent, "text": "plain"})
    assert b.store.get_message(m_absent)["auto"] == 0


# ----------------------------------------------------------------- attacks
def test_reply_to_other_peers_message_is_fine(pair):
    """reply_to is a plain reference string; it may name any stored id."""
    a, b = pair
    now = int(time.time())
    b.store.add_message("stranger-msg", "stranger-pid", "direct", None,
                        "from someone else", now, "delivered", now)
    m = b.messaging.send_message(a.peer_id, "referencing it",
                                 reply_to="stranger-msg")
    assert b.store.get_message(m)["reply_to"] == "stranger-msg"
    got = a.store.get_message(m)
    assert got is not None and got["reply_to"] == "stranger-msg"


def test_forged_auto_from_peer_stored_as_received_no_crash(pair):
    """A forged auto:true is informational — stored, never crashes."""
    a, b = pair
    got = []
    b.messaging.on_message(lambda s, t, m: got.append(m))
    b.messaging.handle_msg({"from": a.peer_id, "ts": int(time.time())},
                           {"msg_id": "d" * 32, "text": "i am auto",
                            "auto": True})
    assert got == ["d" * 32]
    assert b.store.get_message("d" * 32)["auto"] == 1
    # non-bool truthy values do not set the flag
    b.messaging.handle_msg({"from": a.peer_id, "ts": int(time.time())},
                           {"msg_id": "e" * 32, "text": "not auto",
                            "auto": 1})
    assert b.store.get_message("e" * 32)["auto"] == 0
