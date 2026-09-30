"""acp_office server: read-only fleet dashboard over stdlib HTTP.

Sources (all opened read-only, never written):
  connector_db  ~/.acp/acp-home/connector.db
                group_history (group_id = Phoenix Fleet room),
                trusted_agents (sender_id -> display name), presence.
  board_db      ~/.acp/state/fleet_board.db (workstream E task board)
  ledger_db     ~/.acp/state/work_ledger.db (workstream H work ledger)
  fleet_json    ~/.acp/state/fleet.json (fleet room id/name)

Endpoints (all GET, all under /api/ require X-Office-Token):
  /                      HTML dashboard page (no data embedded)
  /api/status            server time + which sources have data
  /api/chat              group chat messages (oldest first)
  /api/tasks             task board grouped by state, with blocked/deps
  /api/ledger            recent work events + per-agent summaries
  /api/presence          fleet roster presence: alive/idle/stale

Missing/empty DBs or tables are handled gracefully: the endpoint
returns an empty collection plus a "no data yet" note, never a crash.
"""
import hmac
import importlib.util
import json
import os
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

DEFAULT_PORT = 18081
DEFAULT_GROUP_ID = "g-15efNv3ApB98VRUX34zlZi"  # Phoenix Fleet room
MAX_BODY = 1024 * 1024

# Presence thresholds (seconds since last_seen).
ALIVE_AFTER_S = 300
IDLE_AFTER_S = 3600


def _load_ui():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "acp_office_ui", os.path.join(here, "ui.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ui = _load_ui()


def default_paths():
    """Default source paths. Env overrides exist for tests/embedders."""
    acp_home = os.environ.get("ACP_HOME", os.path.expanduser("~/.acp"))
    state_dir = os.environ.get("ACP_STATE_DIR",
                               os.path.join(acp_home, "state"))
    conn_home = os.environ.get("ACP_OFFICE_CONNECTOR_HOME",
                               os.path.join(acp_home, "acp-home"))
    return {
        "connector_db": os.environ.get(
            "ACP_OFFICE_CONNECTOR_DB",
            os.path.join(conn_home, "connector.db")),
        "board_db": os.environ.get(
            "ACP_OFFICE_BOARD_DB",
            os.path.join(state_dir, "fleet_board.db")),
        "ledger_db": os.environ.get(
            "ACP_OFFICE_LEDGER_DB",
            os.path.join(state_dir, "work_ledger.db")),
        "fleet_json": os.environ.get(
            "ACP_OFFICE_FLEET_JSON",
            os.path.join(state_dir, "fleet.json")),
    }


def _open_ro(path):
    """Open a sqlite file strictly read-only. None when absent/unusable."""
    if not path or not os.path.isfile(path):
        return None
    try:
        db = sqlite3.connect("file:%s?mode=ro" % path, uri=True,
                             check_same_thread=False, timeout=10)
        db.execute("PRAGMA query_only = ON")
        db.row_factory = sqlite3.Row
        return db
    except sqlite3.Error:
        return None


def _has_table(db, name):
    try:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone()
        return row is not None
    except sqlite3.Error:
        return False


class Office:
    """Read-only fleet office dashboard bound to source DB paths."""

    def __init__(self, paths=None, group_id=None, token=None,
                 host="127.0.0.1", port=DEFAULT_PORT):
        self.paths = dict(default_paths())
        if paths:
            self.paths.update(paths)
        self.group_id = group_id or self._group_id_from_fleet_json() \
            or DEFAULT_GROUP_ID
        self.token = token or secrets.token_urlsafe(32)
        self.host = host
        self.port = port
        self._lock = threading.RLock()
        self._httpd = None
        self._thread = None

    # ------------------------------------------------------------- sources
    def _group_id_from_fleet_json(self):
        try:
            with open(self.paths["fleet_json"], "r",
                      encoding="utf-8") as fh:
                data = json.load(fh)
            gid = data.get("group_id")
            return gid if isinstance(gid, str) and gid else None
        except (OSError, ValueError):
            return None

    # ----------------------------------------------------------------- net
    def start(self):
        """Bind and serve in a daemon thread. Returns the bound port."""
        office = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "ACPOffice/1.0"

            def log_message(self, *args):  # keep test output clean
                pass

            def do_GET(self):
                office._handle(self, "GET")

            def do_POST(self):
                office._handle(self, "POST")

            def do_PUT(self):
                office._handle(self, "PUT")

            def do_DELETE(self):
                office._handle(self, "DELETE")

            def do_PATCH(self):
                office._handle(self, "PATCH")

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True, name="acp-office")
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None

    # -------------------------------------------------------------- router
    _GET_HANDLERS = {
        "/api/status": "api_status",
        "/api/chat": "api_chat",
        "/api/tasks": "api_tasks",
        "/api/ledger": "api_ledger",
        "/api/presence": "api_presence",
    }

    def _handle(self, req, method):
        try:
            split = urlsplit(req.path)
            raw_path = split.path or "/"
            if ".." in [seg for seg in unquote(raw_path).split("/")]:
                self._plain(req, 400, "bad path")
                return
            if raw_path == "/":
                if method != "GET":
                    self._json(req, {"ok": False, "code": "NOT_FOUND"}, 405)
                    return
                self._serve_ui(req)
                return
            if not raw_path.startswith("/api/"):
                self._json(req, {"ok": False, "code": "NOT_FOUND"}, 404)
                return
            if not self._authorized(req):
                self._json(req, {"ok": False, "code": "UNAUTHORIZED",
                                 "detail": "missing or wrong X-Office-Token"},
                           401)
                return
            if method != "GET":
                self._json(req, {"ok": False, "code": "METHOD_NOT_ALLOWED"},
                           405)
                return
            if raw_path in self._GET_HANDLERS:
                getattr(self, self._GET_HANDLERS[raw_path])(
                    req, parse_qs(split.query))
            else:
                self._json(req, {"ok": False, "code": "NOT_FOUND"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:  # never crash the server thread
            try:
                self._json(req, {"ok": False, "code": "INTERNAL",
                                 "detail": str(e)}, 500)
            except Exception:
                pass

    # ------------------------------------------------------------ plumbing
    def _authorized(self, req):
        token = req.headers.get("X-Office-Token")
        if not token:
            return False
        return hmac.compare_digest(token, self.token)

    def _serve_ui(self, req):
        page = _ui.render_page().encode("utf-8")
        req.send_response(200)
        req.send_header("Content-Type", "text/html; charset=utf-8")
        req.send_header("Content-Length", str(len(page)))
        req.end_headers()
        req.wfile.write(page)

    def _json(self, req, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        req.send_response(status)
        req.send_header("Content-Type", "application/json; charset=utf-8")
        req.send_header("Content-Length", str(len(body)))
        req.end_headers()
        req.wfile.write(body)

    def _plain(self, req, status, text):
        body = text.encode("utf-8")
        req.send_response(status)
        req.send_header("Content-Type", "text/plain; charset=utf-8")
        req.send_header("Content-Length", str(len(body)))
        req.end_headers()
        req.wfile.write(body)

    def _limit(self, query, default=100, maximum=500):
        try:
            n = int((query.get("limit") or [str(default)])[0])
        except (TypeError, ValueError):
            n = default
        return max(1, min(n, maximum))

    # --------------------------------------------------------------- data
    def _sender_names(self, db):
        """agent_id -> display_name from trusted_agents (revoked excluded)."""
        names = {}
        try:
            for r in db.execute(
                    "SELECT agent_id, display_name FROM trusted_agents"
                    " WHERE revoked=0"):
                names[r["agent_id"]] = r["display_name"] or r["agent_id"]
        except sqlite3.Error:
            pass
        return names

    # -------------------------------------------------------------- API
    def api_status(self, req, query):
        sources = {}
        for key, table in (("chat", "group_history"),
                           ("board", "tasks"),
                           ("ledger", "work_events")):
            path = self.paths["connector_db"] if key == "chat" \
                else self.paths["board_db"] if key == "board" \
                else self.paths["ledger_db"]
            db = _open_ro(path)
            ok = db is not None and _has_table(db, table)
            if db is not None:
                db.close()
            sources[key] = "ready" if ok else "no data yet"
        presence_ok = False
        db = _open_ro(self.paths["connector_db"])
        if db is not None and _has_table(db, "presence"):
            presence_ok = True
        db.close() if db is not None else None
        sources["presence"] = "ready" if presence_ok else "no data yet"
        self._json(req, {
            "ok": True,
            "server_time": int(time.time()),
            "group_id": self.group_id,
            "sources": sources,
        })

    def api_chat(self, req, query):
        limit = self._limit(query, default=100)
        try:
            since = int((query.get("since") or ["0"])[0])
        except (TypeError, ValueError):
            since = 0
        db = _open_ro(self.paths["connector_db"])
        if db is None or not _has_table(db, "group_history"):
            if db is not None:
                db.close()
            self._json(req, {"ok": True, "messages": [],
                             "note": "no data yet", "group_id": self.group_id})
            return
        names = self._sender_names(db)
        rows = db.execute(
            "SELECT message_id, sender_id, text, ts, created_at, reply_to"
            " FROM group_history WHERE group_id=? AND created_at > ?"
            " ORDER BY created_at DESC LIMIT ?",
            (self.group_id, since, limit)).fetchall()
        db.close()
        msgs = []
        for r in rows:
            sid = r["sender_id"]
            msgs.append({
                "id": r["message_id"],
                "sender_id": sid,
                "sender_name": names.get(sid, sid[:12] + "..."),
                "text": r["text"],
                "ts": r["ts"],
                "created_at": r["created_at"],
                "reply_to": r["reply_to"],
            })
        msgs.reverse()  # oldest first
        self._json(req, {"ok": True, "messages": msgs,
                         "group_id": self.group_id})

    def api_tasks(self, req, query):
        db = _open_ro(self.paths["board_db"])
        if db is None or not _has_table(db, "tasks"):
            if db is not None:
                db.close()
            self._json(req, {"ok": True, "tasks": [], "by_state": {},
                             "note": "no data yet"})
            return
        have_deps = _has_table(db, "task_deps")
        tasks = []
        for r in db.execute(
                "SELECT id, title, assignee, state, due, resume_state,"
                " created_at, updated_at FROM tasks"
                " ORDER BY created_at ASC").fetchall():
            blocked_by = []
            if have_deps:
                blocked_by = [x[0] for x in db.execute(
                    "SELECT blocker_id FROM task_deps WHERE task_id=?"
                    " ORDER BY blocker_id", (r["id"],)).fetchall()]
            tasks.append({
                "id": r["id"], "title": r["title"],
                "assignee": r["assignee"], "state": r["state"],
                "due": r["due"], "resume_state": r["resume_state"],
                "created_at": r["created_at"], "updated_at": r["updated_at"],
                "blocked_by": blocked_by,
            })
        db.close()
        state_of = {t["id"]: t["state"] for t in tasks}
        for t in tasks:
            open_blockers = [b for b in t["blocked_by"]
                             if state_of.get(b) not in ("done",)]
            t["blocked"] = bool(open_blockers)
            t["open_blockers"] = open_blockers
        by_state = {}
        for t in tasks:
            by_state[t["state"]] = by_state.get(t["state"], 0) + 1
        self._json(req, {"ok": True, "tasks": tasks, "by_state": by_state})

    def api_ledger(self, req, query):
        limit = self._limit(query, default=100)
        db = _open_ro(self.paths["ledger_db"])
        if db is None or not _has_table(db, "work_events"):
            if db is not None:
                db.close()
            self._json(req, {"ok": True, "events": [], "agents": [],
                             "note": "no data yet"})
            return
        rows = db.execute(
            "SELECT task_id, agent, event, ts, detail FROM work_events"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        events = [{"task_id": r["task_id"], "agent": r["agent"],
                   "event": r["event"], "ts": r["ts"],
                   "detail": r["detail"]} for r in rows]
        agents = []
        for (agent,) in db.execute(
                "SELECT DISTINCT agent FROM work_events ORDER BY agent"):
            agents.append(self._agent_summary(db, agent))
        db.close()
        self._json(req, {"ok": True, "events": events, "agents": agents})

    def _agent_summary(self, db, agent):
        """Mirror of WorkLedger.summary_for_agent, read-only."""
        counts = {}
        for ev, n in db.execute(
                "SELECT event, COUNT(*) FROM work_events WHERE agent=?"
                " GROUP BY event", (agent,)).fetchall():
            counts[ev] = n

        def _first(task_id, event):
            r = db.execute(
                "SELECT MIN(ts) FROM work_events WHERE task_id=?"
                " AND agent=? AND event=?",
                (task_id, agent, event)).fetchone()
            return r[0]

        task_ids = [r[0] for r in db.execute(
            "SELECT DISTINCT task_id FROM work_events WHERE agent=?",
            (agent,)).fetchall()]
        completed = failed = 0
        ack_lat, done_lat = [], []
        for tid in task_ids:
            a, k, d = (_first(tid, e) for e in ("assigned", "acked", "done"))
            if d is not None:
                completed += 1
            if _first(tid, "failed") is not None:
                failed += 1
            if a is not None and k is not None:
                ack_lat.append(k - a)
            if d is not None and (k or a) is not None:
                done_lat.append(d - (k if k is not None else a))
        return {
            "agent": agent,
            "counts": counts,
            "tasks_completed": completed,
            "tasks_failed": failed,
            "avg_ack_latency_s": (sum(ack_lat) / len(ack_lat)
                                  if ack_lat else None),
            "avg_completion_time_s": (sum(done_lat) / len(done_lat)
                                      if done_lat else None),
        }

    def api_presence(self, req, query):
        db = _open_ro(self.paths["connector_db"])
        agents = {}
        now = time.time()
        if db is not None:
            names = self._sender_names(db)
            for aid in names:
                agents[aid] = {"agent_id": aid,
                               "display_name": names[aid],
                               "last_seen": None}
            if _has_table(db, "presence"):
                for r in db.execute(
                        "SELECT agent_id, status, updated_at FROM presence"):
                    a = agents.setdefault(
                        r["agent_id"],
                        {"agent_id": r["agent_id"],
                         "display_name": names.get(r["agent_id"],
                                                   r["agent_id"][:12]
                                                   + "..."),
                         "last_seen": None})
                    a["last_seen"] = r["updated_at"]
            db.close()
        roster = self._read_roster_agents()
        for handle, entry in roster.items():
            aid = entry.get("agent_id")
            if aid and aid in agents:
                continue
            agents[aid or handle] = {
                "agent_id": aid,
                "display_name": entry.get("display_name") or handle,
                "handle": handle,
                "last_seen": entry.get("last_seen"),
            }
        out = []
        for a in agents.values():
            ls = a.get("last_seen")
            age = (now - ls) if isinstance(ls, (int, float)) else None
            if age is None:
                state = "stale"
            elif age <= ALIVE_AFTER_S:
                state = "alive"
            elif age <= IDLE_AFTER_S:
                state = "idle"
            else:
                state = "stale"
            a["state"] = state
            a["age_s"] = int(age) if age is not None else None
            out.append(a)
        out.sort(key=lambda x: (x["state"] != "alive",
                                x["age_s"] if x["age_s"] is not None else 1e18))
        self._json(req, {"ok": True, "agents": out})

    def _read_roster_agents(self):
        """fleet.json roster agents, if the file carries an agents map."""
        try:
            with open(self.paths["fleet_json"], "r",
                      encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        agents = data.get("agents")
        return agents if isinstance(agents, dict) else {}
