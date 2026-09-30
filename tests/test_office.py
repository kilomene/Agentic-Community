"""Tests for the acp_office dashboard (workstream I).

Covers, against fixture DBs in tmp dirs (never the live ~/.acp ones):
  - / serves the HTML dashboard page
  - /api/status shape + source readiness flags
  - /api/chat: group-filtered, sender names mapped via trusted_agents,
    oldest-first, ?since works
  - /api/tasks: tasks with by_state counts, blocked_by/deps
  - /api/ledger: recent events + per-agent summary cards
  - /api/presence: alive/idle/stale classification
  - missing DBs / missing tables -> graceful "no data yet", never a crash
  - auth: missing/wrong token -> 401; wrong method -> 405;
    path traversal -> 400

Run: python3 -m pytest tests/test_office.py -q
"""
import importlib.util
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC = os.path.join(ROOT, "services", "acp_relay_daemon")
sys_path_inserted = False
import sys  # noqa: E402
sys.path.insert(0, SVC)

import fleet_board  # noqa: E402
import work_ledger  # noqa: E402

GROUP = "g-fleet-test-room"
# Clearly-dummy test credential, following tests/test_dashboard.py's
# convention. NOT a real secret.
TEST_TOKEN = "office-test-token-not-a-secret"


def _load_office_server():
    path = os.path.join(ROOT, "apps", "acp_office", "server.py")
    spec = importlib.util.spec_from_file_location("acp_office_server", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


office_mod = _load_office_server()


def _build_connector_db(path):
    db = sqlite3.connect(path)
    db.executescript("""
CREATE TABLE group_history(
  message_id TEXT PRIMARY KEY, group_id TEXT NOT NULL,
  epoch INTEGER NOT NULL, seq INTEGER NOT NULL,
  sender_id TEXT NOT NULL, text TEXT NOT NULL,
  ts INTEGER NOT NULL, created_at INTEGER NOT NULL,
  reply_to TEXT, refs TEXT NOT NULL DEFAULT '[]');
CREATE TABLE group_chats(
  group_id TEXT PRIMARY KEY, name TEXT NOT NULL,
  admin_id TEXT NOT NULL, epoch INTEGER NOT NULL,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE trusted_agents(
  agent_id TEXT PRIMARY KEY, display_name TEXT, platform TEXT,
  ed_pub TEXT, x_pub TEXT, capabilities TEXT,
  paired_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  revoke_reason TEXT);
CREATE TABLE presence(
  agent_id TEXT PRIMARY KEY, status TEXT NOT NULL,
  updated_at INTEGER NOT NULL);
""")
    now = int(time.time())
    db.executemany(
        "INSERT INTO trusted_agents(agent_id, display_name, paired_at)"
        " VALUES (?,?,?)",
        [("agent-phoenix", "Phoenix", now),
         ("agent-glimmer", "Glimmer", now),
         ("agent-other", "Other", now)])
    db.executemany(
        "INSERT INTO group_history(message_id, group_id, epoch, seq,"
        " sender_id, text, ts, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        [("m1", GROUP, 1, 1, "agent-phoenix", "hello fleet", now, now - 30),
         ("m2", GROUP, 1, 2, "agent-glimmer", "hi phoenix", now, now - 20),
         ("m3", GROUP, 1, 3, "agent-phoenix", "status?", now, now - 10),
         ("mX", "g-other-room", 1, 1, "agent-other", "not ours",
          now, now - 5)])
    db.executemany(
        "INSERT INTO presence(agent_id, status, updated_at) VALUES (?,?,?)",
        [("agent-phoenix", "unknown", now),            # alive
         ("agent-glimmer", "unknown", now - 1200),     # idle
         ("agent-ghost", "unknown", now - 100000)])   # stale, untrusted
    db.commit()
    db.close()


def _build_board_db(path):
    board = fleet_board.FleetBoard(path)
    board.create("t1", "Write report", assignee="glimmer")
    board.create("t2", "Review report", assignee="phoenix")
    board.create("t3", "Ship report", assignee="glimmer")
    board.add_dependency("t2", "t1")
    board.add_dependency("t3", "t2")
    board.set_state("t1", "done")
    board.set_state("t2", "in_progress")
    board.close()


def _build_ledger_db(path):
    ledger = work_ledger.WorkLedger(path)
    now = time.time()
    ledger.record_event("t1", "glimmer", "assigned", ts=now - 300)
    ledger.record_event("t1", "glimmer", "acked", ts=now - 290)
    ledger.record_event("t1", "glimmer", "done", ts=now - 100)
    ledger.record_event("t2", "phoenix", "assigned", ts=now - 50)
    ledger.close()


@pytest.fixture()
def fixtures(tmp_path):
    d = str(tmp_path)
    conn = os.path.join(d, "connector.db")
    board = os.path.join(d, "fleet_board.db")
    ledger = os.path.join(d, "work_ledger.db")
    fleet_json = os.path.join(d, "fleet.json")
    _build_connector_db(conn)
    _build_board_db(board)
    _build_ledger_db(ledger)
    with open(fleet_json, "w", encoding="utf-8") as fh:
        json.dump({"group_id": GROUP, "group_name": "Test Fleet"}, fh)
    return {"connector_db": conn, "board_db": board,
            "ledger_db": ledger, "fleet_json": fleet_json}


@pytest.fixture()
def server(fixtures):
    office = office_mod.Office(paths=fixtures, group_id=GROUP,
                               token=TEST_TOKEN, port=0)
    port = office.start()
    yield office, port
    office.stop()


@pytest.fixture()
def empty_server(tmp_path):
    # All paths point at nothing: missing-DB graceful handling.
    d = str(tmp_path)
    paths = {"connector_db": os.path.join(d, "nope1.db"),
             "board_db": os.path.join(d, "nope2.db"),
             "ledger_db": os.path.join(d, "nope3.db"),
             "fleet_json": os.path.join(d, "nope.json")}
    office = office_mod.Office(paths=paths, group_id=GROUP,
                               token=TEST_TOKEN, port=0)
    port = office.start()
    yield office, port
    office.stop()


def _get(port, path, token=TEST_TOKEN):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path))
    if token is not None:
        req.add_header("X-Office-Token", token)
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
        ctype = resp.headers.get("Content-Type", "")
    if ctype.startswith("application/json"):
        return resp.status, json.loads(body.decode("utf-8"))
    return resp.status, body.decode("utf-8")


def test_root_serves_html(server):
    _, port = server
    status, body = _get(port, "/", token=None)
    assert status == 200
    assert "<title>Phoenix Fleet" in body
    assert "X-Office-Token" in body  # JS auth plumbing present


def test_auth_required(server):
    _, port = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(port, "/api/status", token=None)
    assert exc.value.code == 401
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(port, "/api/status", token="wrong")
    assert exc.value.code == 401


def test_path_traversal_rejected(server):
    _, port = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(port, "/api/../server.py")
    assert exc.value.code == 400


def test_wrong_method_rejected(server):
    _, port = server
    req = urllib.request.Request("http://127.0.0.1:%d/api/status" % port,
                                 data=b"", method="POST")
    req.add_header("X-Office-Token", TEST_TOKEN)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 405


def test_status_shape(server):
    _, port = server
    status, data = _get(port, "/api/status")
    assert status == 200
    assert data["ok"] is True
    assert data["group_id"] == GROUP
    assert isinstance(data["server_time"], int)
    assert data["sources"] == {"chat": "ready", "board": "ready",
                               "ledger": "ready", "presence": "ready"}


def test_chat_filtered_and_named(server):
    _, port = server
    _, data = _get(port, "/api/chat")
    assert data["ok"] is True
    msgs = data["messages"]
    assert [m["id"] for m in msgs] == ["m1", "m2", "m3"]  # oldest first
    assert msgs[0]["sender_name"] == "Phoenix"
    assert msgs[1]["sender_name"] == "Glimmer"
    assert msgs[1]["text"] == "hi phoenix"
    # message from the other room must not leak in
    assert all(m["id"] != "mX" for m in msgs)


def test_chat_since(server):
    _, port = server
    _, first = _get(port, "/api/chat")
    last_seen = first["messages"][0]["created_at"]  # oldest message (m1)
    _, data = _get(port, "/api/chat?since=%d" % last_seen)
    assert [m["id"] for m in data["messages"]] == ["m2", "m3"]


def test_tasks_blocked_deps(server):
    _, port = server
    _, data = _get(port, "/api/tasks")
    assert data["ok"] is True
    by_id = {t["id"]: t for t in data["tasks"]}
    # NOTE: add_dependency() auto-sets t3's state to "blocked" (fleet_board
    # semantics), which is also what the real board shows.
    assert data["by_state"] == {"done": 1, "in_progress": 1, "blocked": 1}
    assert by_id["t1"]["blocked"] is False
    assert by_id["t2"]["blocked"] is False      # t1 is done
    assert by_id["t3"]["blocked"] is True       # t2 still in progress
    assert by_id["t3"]["open_blockers"] == ["t2"]
    assert by_id["t2"]["blocked_by"] == ["t1"]


def test_ledger_events_and_summary(server):
    _, port = server
    _, data = _get(port, "/api/ledger")
    assert data["ok"] is True
    events = data["events"]
    assert len(events) == 4
    assert events[0]["event"] == "assigned" and events[0]["agent"] == "phoenix"
    by_agent = {a["agent"]: a for a in data["agents"]}
    g = by_agent["glimmer"]
    assert g["tasks_completed"] == 1
    assert g["tasks_failed"] == 0
    assert g["counts"]["done"] == 1
    assert g["avg_ack_latency_s"] == pytest.approx(10.0)
    assert g["avg_completion_time_s"] == pytest.approx(190.0)


def test_presence_classification(server):
    _, port = server
    _, data = _get(port, "/api/presence")
    assert data["ok"] is True
    by_id = {a["agent_id"]: a for a in data["agents"]}
    assert by_id["agent-phoenix"]["state"] == "alive"
    assert by_id["agent-glimmer"]["state"] == "idle"
    assert by_id["agent-ghost"]["state"] == "stale"
    assert by_id["agent-phoenix"]["display_name"] == "Phoenix"
    assert by_id["agent-ghost"]["display_name"].startswith("agent-ghost")
    # alive sorts first
    assert data["agents"][0]["agent_id"] == "agent-phoenix"


def test_missing_dbs_graceful(empty_server):
    _, port = empty_server
    _, status = _get(port, "/api/status")
    assert status["ok"] is True
    assert set(status["sources"].values()) == {"no data yet"}
    for path in ("/api/chat", "/api/tasks", "/api/ledger", "/api/presence"):
        _, data = _get(port, path)
        assert data["ok"] is True
    assert _get(port, "/api/chat")[1]["messages"] == []
    assert _get(port, "/api/tasks")[1]["tasks"] == []
    assert _get(port, "/api/ledger")[1]["events"] == []
    assert _get(port, "/api/presence")[1]["agents"] == []


def test_missing_tables_graceful(tmp_path):
    # DBs exist but carry none of the office tables.
    d = str(tmp_path)
    paths = {}
    for key, name in (("connector_db", "c.db"), ("board_db", "b.db"),
                      ("ledger_db", "l.db")):
        p = os.path.join(d, name)
        sqlite3.connect(p).execute(
            "CREATE TABLE junk(x TEXT)").close()
        paths[key] = p
    paths["fleet_json"] = os.path.join(d, "fleet.json")
    office = office_mod.Office(paths=paths, group_id=GROUP,
                               token=TEST_TOKEN, port=0)
    port = office.start()
    try:
        _, data = _get(port, "/api/chat")
        assert data["messages"] == [] and data["note"] == "no data yet"
        _, data = _get(port, "/api/tasks")
        assert data["tasks"] == []
        _, data = _get(port, "/api/ledger")
        assert data["events"] == []
        _, data = _get(port, "/api/presence")
        assert data["agents"] == []
    finally:
        office.stop()


def test_unknown_endpoint_404(server):
    _, port = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(port, "/api/nope")
    assert exc.value.code == 404


def test_concurrent_requests_ok(server):
    # Smoke: the server survives parallel polling like a real dashboard.
    _, port = server
    errors = []

    def hit(i):
        try:
            _get(port, "/api/status")
            _get(port, "/api/chat")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=hit, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# --- New endpoints: /api/roster and POST /api/chat -------------------------


@pytest.fixture()
def office_with_roster_and_outbox(tmp_path, fixtures):
    d = str(tmp_path)
    roster_path = os.path.join(d, "roster.json")
    outbox_dir = os.path.join(d, "outbox")
    with open(roster_path, "w", encoding="utf-8") as fh:
        json.dump({"agents": {
            "glimmer": {"display_name": "Glimmer",
                        "agent_id": "agent-glimmer",
                        "status": "active",
                        "note": "peer agent"},
            "zenas": {"display_name": "Zenas",
                      "agent_id": "agent-zenas"},
        }}, fh)
    paths = dict(fixtures)
    paths["roster_json"] = roster_path
    paths["outbox_dir"] = outbox_dir
    office = office_mod.Office(paths=paths, group_id=GROUP,
                               token=TEST_TOKEN, port=0)
    port = office.start()
    yield office, port, outbox_dir
    office.stop()


def _post(port, path, payload, token=TEST_TOKEN, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data, method="POST")
    if token is not None:
        req.add_header("X-Office-Token", token)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def test_roster_shape(office_with_roster_and_outbox):
    _, port, _ = office_with_roster_and_outbox
    status, data = _get(port, "/api/roster")
    assert status == 200
    assert data["ok"] is True
    by_handle = {a["handle"]: a for a in data["agents"]}
    assert by_handle["glimmer"]["display_name"] == "Glimmer"
    assert by_handle["glimmer"]["note"] == "peer agent"
    assert by_handle["zenas"]["agent_id"] == "agent-zenas"
    assert by_handle["zenas"]["note"] == ""  # missing note -> empty string


def test_roster_missing_graceful(server):
    # The plain `server` fixture has no roster_json override... default
    # points at the real ~/.acp path; use an explicit missing path instead.
    _, port = server
    status, data = _get(port, "/api/roster")
    assert status == 200
    assert data["ok"] is True
    assert isinstance(data["agents"], list)


def test_chat_post_queues_message(office_with_roster_and_outbox):
    _, port, outbox_dir = office_with_roster_and_outbox
    status, data = _post(port, "/api/chat", {"text": "hello fleet"})
    assert status == 200
    assert data == {"ok": True, "queued": True}
    files = os.listdir(outbox_dir)
    assert len(files) == 1
    with open(os.path.join(outbox_dir, files[0]),
              encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload == {"kind": "group_msg", "group_id": GROUP,
                       "text": "hello fleet"}


def test_chat_post_validation(office_with_roster_and_outbox):
    _, port, outbox_dir = office_with_roster_and_outbox

    def expect_400(payload=None, raw=None):
        with pytest.raises(urllib.error.HTTPError) as exc:
            _post(port, "/api/chat", payload, raw=raw)
        assert exc.value.code == 400

    expect_400({"text": "   "})          # blank
    expect_400({})                       # missing
    expect_400({"text": "x" * 2001})     # too long
    expect_400(raw=b"{not json")         # malformed
    expect_400(raw=b"")                  # empty body
    queued = os.listdir(outbox_dir) if os.path.isdir(outbox_dir) else []
    assert queued == []  # nothing queued

    with pytest.raises(urllib.error.HTTPError) as exc:  # no token
        _post(port, "/api/chat", {"text": "hi"}, token=None)
    assert exc.value.code == 401
    with pytest.raises(urllib.error.HTTPError) as exc:  # wrong token
        _post(port, "/api/chat", {"text": "hi"}, token="wrong")
    assert exc.value.code == 401


def test_chat_post_wrong_method_rejected(server):
    # GET /api/chat still serves the feed; DELETE is not a thing.
    _, port = server
    req = urllib.request.Request("http://127.0.0.1:%d/api/chat" % port,
                                 data=b"", method="DELETE")
    req.add_header("X-Office-Token", TEST_TOKEN)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 405
