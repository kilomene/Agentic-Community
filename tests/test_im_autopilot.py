"""Workstream D tests: Autopilot — opt-in autonomous agent-to-agent chat.

Covers: config-absent default-off, echo mode replies (threaded when the
API supports it, plain-send fallback otherwise), hook subprocess
contract, malicious-hook recipient confinement, loop guard, token-bucket
rate limiting, poll_events cursor behavior, and graceful degradation
when workstream A/C features (send_reply, auto/reply_to columns) are
absent.

Run: python3 -m pytest tests/test_im_autopilot.py -q
"""
import json
import os
import sqlite3
import sys
import tempfile
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

from autopilot import Autopilot, poll_events  # noqa: E402


# ------------------------------------------------------------ fakes

class FakeAudit:
    def __init__(self):
        self.events = []  # (event, actor, target, result, details)

    def log(self, event, actor="local", target=None, result="ok",
            details=None):
        self.events.append((event, actor, target, result, details or {}))

    def names(self):
        return [e[0] for e in self.events]


class FakeMessaging:
    """Connector-like without send_reply (workstream A absent)."""

    def __init__(self):
        self.cbs = []


class FakeConn:
    """Minimal connector-like: no network, no real Connector."""

    def __init__(self, with_send_reply=False):
        self.audit = FakeAudit()
        self.sent = []          # (kind, recipient, text, reply_to)
        self.messaging = FakeMessaging()
        self.peer_id = "OWNPID"
        if with_send_reply:
            self.messaging.send_reply = self._send_reply

    def _send_reply(self, peer_pid, text, reply_to=None):
        self.sent.append(("direct", peer_pid, text, reply_to))
        return "fake-msg-id"

    def send_message(self, peer_pid, text):
        self.sent.append(("direct", peer_pid, text, None))
        return "fake-msg-id"

    def on_message(self, cb):
        self.messaging.cbs.append(cb)


class FakeGroups:
    def __init__(self, with_send_group_reply=False):
        self.sent = []
        self.cbs = []
        if with_send_group_reply:
            self.send_group_reply = self._send_group_reply

    def _send_group_reply(self, group_id, text, reply_to=None):
        self.sent.append((group_id, text, reply_to))
        return "fake-gid"

    def send_group_message(self, group_id, text):
        self.sent.append((group_id, text, None))
        return "fake-gid"

    def on_group_message(self, cb):
        self.cbs.append(cb)


def make_home(config=None):
    home = tempfile.mkdtemp(prefix="autopilot-home-")
    if config is not None:
        with open(os.path.join(home, "autopilot.json"), "w") as fh:
            json.dump(config, fh)
    return home


def make_autopilot(home, conn, **kw):
    kw.setdefault("background", False)
    ap = Autopilot(home, conn, **kw)
    return ap


# ------------------------------------------------------------ default-off

def test_config_absent_everything_off():
    home = make_home()  # no autopilot.json
    conn = FakeConn(with_send_reply=True)
    ap = make_autopilot(home, conn)
    ap.handle_direct("SOMEPEER", "hello", "m1")
    ap.handle_group("g-1", "SOMEPEER", "hi all", 1)
    assert conn.sent == []
    reasons = [ev[4].get("reason") for ev in conn.audit.events
               if ev[0] == "autopilot.skipped"]
    assert "off" in reasons


def test_unknown_peer_ignored():
    home = make_home({"peers": {"KNOWN": {"mode": "echo"}}})
    conn = FakeConn(with_send_reply=True)
    ap = make_autopilot(home, conn)
    ap.handle_direct("STRANGER", "hello", "m1")
    assert conn.sent == []


# ------------------------------------------------------------ echo mode

def test_echo_threaded_when_send_reply_available():
    home = make_home({"peers": {"PEER1": {"mode": "echo"}}})
    conn = FakeConn(with_send_reply=True)
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "ping", "msg-42")
    assert len(conn.sent) == 1
    kind, recipient, text, reply_to = conn.sent[0]
    assert recipient == "PEER1"          # reply goes to the event source
    assert text == "echo: ping"
    assert reply_to == "msg-42"          # threaded via send_reply
    sent_audits = [e for e in conn.audit.events
                   if e[0] == "autopilot.reply_sent"]
    assert len(sent_audits) == 1
    assert sent_audits[0][2] == "PEER1"


def test_echo_falls_back_to_plain_send():
    home = make_home({"peers": {"PEER1": {"mode": "echo"}}})
    conn = FakeConn(with_send_reply=False)  # workstream A absent
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "ping", "msg-42")
    assert len(conn.sent) == 1
    kind, recipient, text, reply_to = conn.sent[0]
    assert recipient == "PEER1"
    assert text == "echo: ping"
    assert reply_to is None  # plain send: no threading available


def test_threaded_via_send_message_kwargs_workstream_a():
    """Workstream A as landed: send_message(..., reply_to=..., auto=...)
    is detected via signature inspection — no send_reply needed."""

    class AConn(FakeConn):
        def send_message(self, peer_pid, text, *, reply_to=None,
                         auto=False):
            self.sent.append(("direct", peer_pid, text, reply_to, auto))
            return "x"

    home = make_home({"peers": {"PEER1": {"mode": "echo"}}})
    conn = AConn(with_send_reply=False)
    # drop the send_reply attr the base class may have set
    if hasattr(conn.messaging, "send_reply"):
        delattr(conn.messaging, "send_reply")
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "ping", "msg-42")
    assert len(conn.sent) == 1
    kind, recipient, text, reply_to, auto = conn.sent[0]
    assert recipient == "PEER1"
    assert reply_to == "msg-42"   # threaded
    assert auto is True           # marked as autopilot-generated


def test_echo_group_channel():
    home = make_home({"channels": {"g-abc": {"mode": "echo"}}})
    conn = FakeConn()
    groups = FakeGroups()
    ap = make_autopilot(home, conn, groups=groups)
    ap.handle_group("g-abc", "PEER1", "hello channel", 7)
    assert len(groups.sent) == 1
    gid, text, reply_to = groups.sent[0]
    assert gid == "g-abc"
    assert text == "echo: hello channel"


def test_group_reply_threaded_when_api_available():
    home = make_home({"channels": {"g-abc": {"mode": "echo"}}})
    conn = FakeConn()
    groups = FakeGroups(with_send_group_reply=True)  # workstream C present
    ap = make_autopilot(home, conn, groups=groups)
    ap._handle_event({"kind": "group_message", "sender": "PEER1",
                      "text": "yo", "msg_id": "gm-9", "reply_to": None,
                      "auto": False, "group_id": "g-abc",
                      "channel": {"name": "c", "project_id": None}})
    assert groups.sent[0] == ("g-abc", "echo: yo", "gm-9")


def test_group_threaded_via_send_channel_message_workstream_c():
    """Workstream C as landed: send_channel_message(..., reply_to=...)
    is detected via signature inspection."""

    class CGroups(FakeGroups):
        def send_channel_message(self, group_id, text, reply_to=None,
                                 refs=None):
            self.sent.append((group_id, text, reply_to))
            return "x"

    home = make_home({"channels": {"g-abc": {"mode": "echo"}}})
    conn = FakeConn()
    groups = CGroups()
    ap = make_autopilot(home, conn, groups=groups)
    ap.handle_group("g-abc", "PEER1", "hello channel", 7)
    assert groups.sent[0] == ("g-abc", "echo: hello channel", None)
    # with a resolvable msg_id the reply is threaded:
    ap._handle_event({"kind": "group_message", "sender": "PEER1",
                      "text": "yo", "msg_id": "gm-9", "reply_to": None,
                      "auto": False, "group_id": "g-abc",
                      "channel": {"name": "c", "project_id": None}})
    assert groups.sent[1] == ("g-abc", "echo: yo", "gm-9")


def test_own_group_message_never_answered():
    home = make_home({"channels": {"g-abc": {"mode": "echo"}}})
    conn = FakeConn()  # peer_id == "OWNPID"
    groups = FakeGroups()
    ap = make_autopilot(home, conn, groups=groups)
    ap.handle_group("g-abc", "OWNPID", "my own message", 3)
    assert groups.sent == []


# ------------------------------------------------------------ hooks

def write_hook(home, name, body):
    d = os.path.join(home, "autopilot_hooks")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name + ".py")
    with open(p, "w") as fh:
        fh.write(body)
    return p


def test_hook_json_reply():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "h1"}}})
    write_hook(home, "h1",
               "import sys, json\n"
               "ev = json.load(sys.stdin)\n"
               "print(json.dumps({'reply': 'hi ' + ev['sender']}))\n")
    conn = FakeConn(with_send_reply=True)
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")
    assert len(conn.sent) == 1
    assert conn.sent[0][1] == "PEER1"
    assert conn.sent[0][2] == "hi PEER1"


def test_hook_bare_text_reply():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "h2"}}})
    write_hook(home, "h2", "print('just some words')\n")
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")
    assert conn.sent[0][2] == "just some words"


def test_hook_empty_stdout_no_reply():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "h3"}}})
    write_hook(home, "h3", "import sys\nsys.stdin.read()\n")
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")
    assert conn.sent == []
    assert "autopilot.no_reply" in conn.audit.names()


def test_hook_timeout_kills_no_reply():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "slow"}}})
    write_hook(home, "slow",
               "import time\ntime.sleep(30)\nprint('too late')\n")
    conn = FakeConn()
    ap = make_autopilot(home, conn, hook_timeout=1)
    start = time.time()
    ap.handle_direct("PEER1", "hello", "m1")
    elapsed = time.time() - start
    assert conn.sent == []
    assert "autopilot.hook_timeout" in conn.audit.names()
    assert elapsed < 20  # hook was killed, we did not wait out its sleep


def test_hook_missing_script_no_reply():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "nope"}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")  # no hooks dir at all
    assert conn.sent == []
    assert "autopilot.skipped" in conn.audit.names()


def test_hook_name_path_traversal_rejected():
    home = make_home({"peers": {"PEER1": {"mode": "hook",
                                          "hook": "../evil"}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")
    assert conn.sent == []
    # invalid hook name -> policy invalid -> treated as off
    assert "autopilot.skipped" in conn.audit.names()


def test_malicious_hook_cannot_redirect_recipient():
    home = make_home({"peers": {"PEER1": {"mode": "hook", "hook": "evil"}}})
    write_hook(home, "evil",
               "import json\n"
               "print(json.dumps({'reply': 'x', 'to': 'someone-else'}))\n")
    conn = FakeConn(with_send_reply=True)
    ap = make_autopilot(home, conn)
    ap.handle_direct("PEER1", "hello", "m1")
    assert len(conn.sent) == 1
    kind, recipient, text, reply_to = conn.sent[0]
    assert recipient == "PEER1"  # the "to" field is ignored
    assert text == "x"


def test_hook_sees_only_event_kind_in_env():
    # The hook's environment must carry no secrets: only ACP_EVENT_KIND
    # (CPython's subprocess may additionally inject LC_CTYPE for locale
    # coercion — that is a locale variable, not a secret).
    os.environ["AUTOPILOT_TEST_SECRET"] = "s3cr3t-marker"
    try:
        home = make_home({"peers": {"PEER1": {"mode": "hook",
                                              "hook": "env"}}})
        write_hook(home, "env",
                   "import os, json\n"
                   "print(json.dumps({'reply': json.dumps(sorted(os.environ))}))\n")
        conn = FakeConn()
        ap = make_autopilot(home, conn)
        ap.handle_direct("PEER1", "hello", "m1")
        seen = json.loads(conn.sent[0][2])
        assert "ACP_EVENT_KIND" in seen
        assert "AUTOPILOT_TEST_SECRET" not in seen
        assert "PATH" not in seen
    finally:
        del os.environ["AUTOPILOT_TEST_SECRET"]


# ------------------------------------------------------------ loop guard

def _event(sender="PEER1", auto=False):
    return {"kind": "message", "sender": sender, "text": "hi",
            "msg_id": "m-loop", "reply_to": None, "auto": auto,
            "group_id": None, "channel": None}


def test_loop_guard_blocks_auto_when_not_opted_in():
    home = make_home({"peers": {"PEER1": {"mode": "echo",
                                          "reply_to_auto": False}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap._handle_event(_event(auto=True))
    assert conn.sent == []
    skips = [ev for ev in conn.audit.events if ev[0] == "autopilot.skipped"]
    reasons = [ev[4].get("reason") for ev in skips]
    assert "auto_guard" in reasons


def test_loop_guard_allows_auto_when_opted_in():
    home = make_home({"peers": {"PEER1": {"mode": "echo",
                                          "reply_to_auto": True}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap._handle_event(_event(auto=True))
    assert len(conn.sent) == 1


def test_non_auto_always_flows():
    home = make_home({"peers": {"PEER1": {"mode": "echo",
                                          "reply_to_auto": False}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap._handle_event(_event(auto=False))
    assert len(conn.sent) == 1


# ------------------------------------------------------------ rate limit

def test_rate_limit_token_bucket():
    home = make_home({"peers": {"PEER1": {"mode": "echo",
                                          "max_per_min": 3}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    for i in range(10):
        ap.handle_direct("PEER1", "msg %d" % i, "m-%d" % i)
    assert len(conn.sent) == 3
    limited = [e for e in conn.audit.events
               if e[0] == "autopilot.rate_limited"]
    assert len(limited) == 7


def test_rate_limit_is_per_peer():
    home = make_home({"peers": {"A": {"mode": "echo", "max_per_min": 1},
                                "B": {"mode": "echo", "max_per_min": 1}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("A", "one", "m1")
    ap.handle_direct("A", "two", "m2")   # rate-limited
    ap.handle_direct("B", "one", "m3")   # separate bucket
    recipients = [s[1] for s in conn.sent]
    assert recipients == ["A", "B"]


# ------------------------------------------------------------ poll_events

def _seed_db(home, with_new_columns=False):
    db = os.path.join(home, "connector.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE messages(message_id TEXT PRIMARY KEY,"
                " sender_id TEXT, scope TEXT, scope_id TEXT, text TEXT,"
                " timestamp INTEGER, status TEXT, created_at INTEGER)")
    if with_new_columns:
        con.execute("ALTER TABLE messages ADD COLUMN reply_to TEXT")
        con.execute("ALTER TABLE messages ADD COLUMN auto INTEGER"
                    " NOT NULL DEFAULT 0")
    con.execute("CREATE TABLE group_history(message_id TEXT PRIMARY KEY,"
                " group_id TEXT, epoch INTEGER, seq INTEGER,"
                " sender_id TEXT, text TEXT, ts INTEGER, created_at INTEGER)")
    con.execute("CREATE TABLE group_chats(group_id TEXT PRIMARY KEY,"
                " name TEXT)")
    now = int(time.time())
    if with_new_columns:
        con.execute("INSERT INTO messages(message_id,sender_id,scope,"
                    "text,timestamp,status,created_at,reply_to,auto)"
                    " VALUES('dm-in-1','PEER1','direct','hello',?,?,?,"
                    "'dm-0',1)", (now, "delivered", now))
    else:
        con.execute("INSERT INTO messages(message_id,sender_id,scope,"
                    "text,timestamp,status,created_at)"
                    " VALUES('dm-in-1','PEER1','direct','hello',?,?,?)",
                    (now, "delivered", now))
    # own outbound row must NOT be returned (status != delivered)
    con.execute("INSERT INTO messages(message_id,sender_id,scope,"
                "text,timestamp,status,created_at)"
                " VALUES('dm-out-1','OWNPID','direct','my msg',?,?,?)",
                (now, "sent", now))
    con.execute("INSERT INTO group_chats VALUES('g-1','club')")
    con.execute("INSERT INTO group_history VALUES"
                "('gm-1','g-1',1,1,'PEER2','hey all',?,?)", (now, now))
    con.execute("INSERT INTO group_history VALUES"
                "('gm-2','g-1',1,2,'OWNPID','my group msg',?,?)",
                (now, now))
    con.commit()
    con.close()


def test_poll_events_cursor_semantics():
    home = make_home()
    _seed_db(home)
    cur_path = os.path.join(home, "cursor.json")
    events, cursor = poll_events(home, cur_path)
    by_id = {e["msg_id"]: e for e in events}
    assert "dm-in-1" in by_id          # inbound direct
    assert "dm-out-1" not in by_id     # own outbound excluded
    assert "gm-1" in by_id             # inbound group
    assert "gm-2" not in by_id         # own group message excluded
    e = by_id["dm-in-1"]
    assert e["kind"] == "message" and e["sender"] == "PEER1"
    assert e["auto"] is False and e["reply_to"] is None  # cols absent
    g = by_id["gm-1"]
    assert g["kind"] == "group_message" and g["group_id"] == "g-1"
    assert g["channel"]["name"] == "club"
    # second poll: cursor holds, nothing new
    events2, _ = poll_events(home, cur_path)
    assert events2 == []
    # new row after cursor shows up
    con = sqlite3.connect(os.path.join(home, "connector.db"))
    now = int(time.time()) + 5
    con.execute("INSERT INTO messages(message_id,sender_id,scope,text,"
                "timestamp,status,created_at)"
                " VALUES('dm-in-2','PEER1','direct','again',?,?,?)",
                (now, "delivered", now))
    con.commit()
    con.close()
    events3, _ = poll_events(home, cur_path)
    assert [e["msg_id"] for e in events3] == ["dm-in-2"]


def test_poll_events_with_workstream_a_columns():
    home = make_home()
    _seed_db(home, with_new_columns=True)
    cur_path = os.path.join(home, "cursor.json")
    events, _ = poll_events(home, cur_path)
    e = {x["msg_id"]: x for x in events}["dm-in-1"]
    assert e["auto"] is True
    assert e["reply_to"] == "dm-0"


def test_poll_events_no_db():
    home = make_home()
    cur_path = os.path.join(home, "cursor.json")
    events, cursor = poll_events(home, cur_path)
    assert events == []


# ------------------------------------------------------------ defense

def test_minimal_connector_no_attrs():
    """No messaging attr, no audit, no peer_id: graceful fallback."""

    class Bare:
        def send_message(self, peer_pid, text):
            self.last = (peer_pid, text)
            return "x"

    home = make_home({"peers": {"P": {"mode": "echo"}}})
    bare = Bare()
    ap = make_autopilot(home, bare)
    ap.handle_direct("P", "yo", "m1")  # must not crash
    assert bare.last == ("P", "echo: yo")


def test_bad_config_mode_treated_as_off():
    home = make_home({"peers": {"P": {"mode": "banana"}}})
    conn = FakeConn()
    ap = make_autopilot(home, conn)
    ap.handle_direct("P", "yo", "m1")
    assert conn.sent == []


def test_background_mode_threads():
    home = make_home({"peers": {"P": {"mode": "echo"}}})
    conn = FakeConn()
    ap = Autopilot(home, conn, background=True)
    ap.handle_direct("P", "yo", "m1")
    ap.join_pending(timeout=10)
    assert len(conn.sent) == 1
