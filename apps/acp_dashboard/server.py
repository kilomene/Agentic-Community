"""acp_dashboard: web UI + JSON REST API for an ACP 1.0 Connector.

A real web UI backed by a REAL Connector instance: every endpoint reads
or mutates live connector state (peers, messages, files, projects,
permissions, pairing, presence, audit). Stdlib only: ThreadingHTTPServer
serving a single-page app (see ui.py — inline HTML/CSS/JS, no CDN, works
offline).

Security:
  - binds 127.0.0.1 by default (override with --host at your own risk);
  - every /api/* call needs the X-ACP-Token header (startup token passed
    as --token or generated and printed once); missing/wrong -> 401;
  - mutations are POST-only (wrong method -> 405);
  - request bodies capped at 1 MiB; no filesystem is served, and any
    path containing a ".." segment is rejected outright.

Run:  python3 apps/acp_dashboard/__main__.py --home DIR [--port N]
      [--host 127.0.0.1] [--token TOKEN] [--lang en] [--passphrase ...]
      (passphrase also via ACP_PASSPHRASE env, else interactive prompt)
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

try:
    from acp_i18n import t, available_langs
except ImportError:  # pragma: no cover - defensive
    def t(key, lang="en"):
        return key

    def available_langs():
        return ["en"]


def _load_ui():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "acp_dashboard_ui", os.path.join(here, "ui.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ui = _load_ui()

MAX_BODY = 1024 * 1024
_UNKNOWN = "__unknown__"


def _acp_error_to_status(code):
    return {"NOT_FOUND": 404, "POLICY_DENIED": 403}.get(code, 400)


class Dashboard:
    """Web dashboard bound to one Connector instance."""

    def __init__(self, connector, token=None, host="127.0.0.1", port=0,
                 lang="en"):
        self.conn = connector
        self.token = token or secrets.token_urlsafe(32)
        self.host = host
        self.port = port
        self.default_lang = lang if lang in available_langs() else "en"
        # Sent-message -> peer attribution. The messages table does not
        # store the recipient, so the dashboard keeps its own mapping
        # (CREATE TABLE IF NOT EXISTS on the connector DB, own connection).
        self._db = sqlite3.connect(connector.store.path,
                                   check_same_thread=False, timeout=10)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_msg_peer("
            "message_id TEXT PRIMARY KEY, peer_id TEXT NOT NULL)")
        self._db.commit()
        self._lock = threading.RLock()
        self._httpd = None
        self._thread = None
        self._backfill_mapping()
        connector.on_message(self._on_inbound_message)

    # ------------------------------------------------------- message mapping
    def _on_inbound_message(self, sender_pid, text, msg_id):
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO dashboard_msg_peer(message_id,"
                " peer_id) VALUES (?,?)", (msg_id, sender_pid))
            self._db.commit()

    def _backfill_mapping(self):
        me = self.conn.peer_id
        with self._lock:
            for m in self.conn.store.list_messages(limit=100000):
                if m["sender_id"] != me:
                    self._db.execute(
                        "INSERT OR IGNORE INTO dashboard_msg_peer("
                        "message_id, peer_id) VALUES (?,?)",
                        (m["message_id"], m["sender_id"]))
            self._db.commit()

    def _map_message(self, msg_id, peer_id):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO dashboard_msg_peer(message_id,"
                " peer_id) VALUES (?,?)", (msg_id, peer_id))
            self._db.commit()

    def _peer_for_message(self, msg_id):
        with self._lock:
            r = self._db.execute(
                "SELECT peer_id FROM dashboard_msg_peer WHERE message_id=?",
                (msg_id,)).fetchone()
            return r[0] if r else None

    # ------------------------------------------------------------------ net
    def start(self):
        """Bind and serve in a daemon thread. Returns the bound port."""
        dash = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "ACPDashboard/1.0"

            def log_message(self, *args):  # keep test output clean
                pass

            def do_GET(self):
                dash._handle(self, "GET")

            def do_POST(self):
                dash._handle(self, "POST")

            def do_PUT(self):
                dash._handle(self, "PUT")

            def do_DELETE(self):
                dash._handle(self, "DELETE")

            def do_PATCH(self):
                dash._handle(self, "PATCH")

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True, name="acp-dashboard")
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
        try:
            self._db.commit()
            self._db.close()
        except Exception:
            pass

    # ---------------------------------------------------------------- router
    _GET_HANDLERS = {
        "/api/status": "api_status",
        "/api/peers": "api_peers",
        "/api/conversations": "api_conversations",
        "/api/files": "api_files",
        "/api/projects": "api_projects",
        "/api/tasks": "api_tasks",
        "/api/permissions": "api_permissions",
        "/api/pairings": "api_pairings",
        "/api/audit": "api_audit",
        "/api/presence": "api_presence_list",
    }
    _POST_HANDLERS = {
        "/api/message/send": "api_message_send",
        "/api/file/send": "api_file_send",
        "/api/permission/grant": "api_permission_grant",
        "/api/permission/revoke": "api_permission_revoke",
        "/api/peer/revoke": "api_peer_revoke",
        "/api/presence": "api_presence_set",
        "/api/pair/initiate": "api_pair_initiate",
        "/api/pair/confirm": "api_pair_confirm",
        "/api/project/create": "api_project_create",
        "/api/task/add": "api_task_add",
        "/api/task/update": "api_task_update",
    }

    def _handle(self, req, method):
        try:
            split = urlsplit(req.path)
            raw_path = split.path or "/"
            # Path traversal: reject outright (nothing is served from disk,
            # but be explicit).
            if ".." in [seg for seg in unquote(raw_path).split("/")]:
                self._plain(req, 400, "bad path")
                return
            if raw_path == "/":
                if method != "GET":
                    self._json(req, {"ok": False}, 405)
                    return
                self._serve_ui(req, split)
                return
            if not raw_path.startswith("/api/"):
                self._json(req, {"ok": False, "code": "NOT_FOUND"}, 404)
                return
            lang = self._req_lang(req)
            if not self._authorized(req):
                self._json(req, {"ok": False, "code": "UNAUTHORIZED",
                                 "detail": t("err_unauthorized", lang)}, 401)
                return
            if method == "GET" and raw_path in self._GET_HANDLERS:
                fn = getattr(self, self._GET_HANDLERS[raw_path])
                fn(req, parse_qs(split.query), lang)
            elif method == "POST" and raw_path in self._POST_HANDLERS:
                body = self._read_json(req, lang)
                if body is None:
                    return  # error already sent
                fn = getattr(self, self._POST_HANDLERS[raw_path])
                fn(req, body, lang)
            elif raw_path in self._GET_HANDLERS or \
                    raw_path in self._POST_HANDLERS:
                self._json(req, {"ok": False, "code": "METHOD_NOT_ALLOWED",
                                 "detail": t("err_method", lang)}, 405)
            else:
                self._json(req, {"ok": False, "code": "NOT_FOUND",
                                 "detail": t("err_not_found", lang)}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:  # never crash the server thread
            try:
                self._json(req, {"ok": False, "code": "INTERNAL",
                                 "detail": str(e)}, 500)
            except Exception:
                pass

    # -------------------------------------------------------------- plumbing
    def _req_lang(self, req):
        q = parse_qs(urlsplit(req.path).query)
        if q.get("lang", [None])[0] in available_langs():
            return q["lang"][0]
        cookie = req.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("acp_lang="):
                c = part.strip()[len("acp_lang="):]
                if c in available_langs():
                    return c
        return self.default_lang

    def _authorized(self, req):
        token = req.headers.get("X-ACP-Token")
        if not token:
            return False
        return hmac.compare_digest(token, self.token)

    def _serve_ui(self, req, split):
        q = parse_qs(split.query)
        lang = q.get("lang", [None])[0]
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if lang in available_langs():
            headers["Set-Cookie"] = \
                "acp_lang=%s; Path=/; SameSite=Lax" % lang
        else:
            lang = self._req_lang(req)
        page = _ui.render_page(lang).encode("utf-8")
        req.send_response(200)
        for k, v in headers.items():
            req.send_header(k, v)
        req.send_header("Content-Length", str(len(page)))
        req.end_headers()
        req.wfile.write(page)

    def _json(self, req, obj, status=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        req.send_response(status)
        req.send_header("Content-Type", "application/json; charset=utf-8")
        req.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            req.send_header(k, v)
        req.end_headers()
        req.wfile.write(body)

    def _plain(self, req, status, text):
        body = text.encode("utf-8")
        req.send_response(status)
        req.send_header("Content-Type", "text/plain; charset=utf-8")
        req.send_header("Content-Length", str(len(body)))
        req.end_headers()
        req.wfile.write(body)

    def _read_json(self, req, lang):
        try:
            length = int(req.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._json(req, {"ok": False, "code": "TOO_LARGE"}, 413)
            return None
        raw = req.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(req, {"ok": False, "code": "BAD_JSON",
                             "detail": t("err_invalid_input", lang)}, 400)
            return None
        if not isinstance(data, dict):
            self._json(req, {"ok": False, "code": "BAD_JSON",
                             "detail": t("err_invalid_input", lang)}, 400)
            return None
        return data

    def _acp_fail(self, req, e, lang):
        # Import here to avoid a hard dependency at module import time.
        from acp_connector import AcpError  # noqa: F401
        self._json(req, {"ok": False, "code": e.code,
                         "detail": e.detail or ""},
                   _acp_error_to_status(e.code))

    # ------------------------------------------------------------ API: read
    def api_status(self, req, query, lang):
        c = self.conn
        n_msgs = len(c.store.list_messages(limit=100000))
        n_projects = len(self._q("SELECT project_id FROM projects"))
        n_tasks = len(self._q("SELECT task_id FROM tasks"))
        n_transfers = len(self._q("SELECT transfer_id FROM transfers"))
        try:
            presence = c.presence.get(c.peer_id)["status"]
        except Exception:
            presence = "unknown"
        self._json(req, {
            "ok": True,
            "handle": c.handle,
            "peer_id": c.peer_id,
            "presence": presence,
            "server_time": int(time.time()),
            "counts": {
                "peers": len(c.store.list_peers()),
                "messages": n_msgs,
                "projects": n_projects,
                "tasks": n_tasks,
                "transfers": n_transfers,
            },
        })

    def _q(self, sql, args=(), limit=500):
        with self._lock:
            cur = self._db.execute(sql + " LIMIT %d" % int(limit), args)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def api_peers(self, req, query, lang):
        c = self.conn
        out = []
        for p in c.store.list_peers(include_revoked=True):
            try:
                pres = c.presence.get(p["agent_id"])["status"]
            except Exception:
                pres = "unknown"
            out.append({
                "agent_id": p["agent_id"],
                "display_name": p["display_name"],
                "platform": p["platform"],
                "presence": pres,
                "revoked": bool(p["revoked"]),
                "revoke_reason": p["revoke_reason"],
                "paired_at": p["paired_at"],
            })
        self._json(req, {"ok": True, "peers": out})

    def api_conversations(self, req, query, lang):
        c = self.conn
        me = c.peer_id
        peers = {p["agent_id"]: p
                 for p in c.store.list_peers(include_revoked=True)}
        convs = {}
        order = []
        for m in c.store.list_messages(limit=2000):
            if m["sender_id"] == me:
                pid = self._peer_for_message(m["message_id"]) or _UNKNOWN
                direction = "out"
            else:
                pid = m["sender_id"]
                direction = "in"
            if pid not in convs:
                convs[pid] = []
                order.append(pid)
            convs[pid].append({
                "id": m["message_id"],
                "direction": direction,
                "sender": m["sender_id"],
                "text": m["text"],
                "timestamp": m["timestamp"],
                "status": m["status"],
                "created_at": m["created_at"],
            })
        result = []
        for pid in order:
            msgs = sorted(convs[pid], key=lambda x: x["created_at"])
            p = peers.get(pid, {})
            result.append({
                "peer_id": pid,
                "handle": p.get("display_name") or None,
                "revoked": bool(p.get("revoked", False)),
                "messages": msgs[-100:],
                "last_at": msgs[-1]["created_at"],
            })
        result.sort(key=lambda x: x["last_at"], reverse=True)
        self._json(req, {"ok": True, "conversations": result[:50]})

    def api_files(self, req, query, lang):
        rows = self._q("SELECT transfer_id, direction, peer_id, name, size,"
                       " sha256, chunk_size, count, received, state, path,"
                       " created_at FROM transfers"
                       " ORDER BY created_at DESC", limit=200)
        self._json(req, {"ok": True, "transfers": rows})

    def api_projects(self, req, query, lang):
        rows = self._q("SELECT project_id, name, description, created_by,"
                       " created_at FROM projects ORDER BY created_at DESC",
                       limit=200)
        out = []
        for r in rows:
            n = self._q("SELECT COUNT(*) AS n FROM tasks WHERE project_id=?",
                        (r["project_id"],), limit=1)[0]["n"]
            out.append({
                "project_id": r["project_id"],
                "title": r["name"],
                "notes": r["description"],
                "created_by": r["created_by"],
                "created_at": r["created_at"],
                "task_count": n,
            })
        self._json(req, {"ok": True, "projects": out})

    def api_tasks(self, req, query, lang):
        pid = (query.get("project_id") or [None])[0]
        if pid:
            rows = self._q("SELECT task_id, project_id, title, description,"
                           " owner, status, priority, created_by, created_at,"
                           " updated_at FROM tasks WHERE project_id=?"
                           " ORDER BY created_at", (pid,), limit=500)
        else:
            rows = self._q("SELECT task_id, project_id, title, description,"
                           " owner, status, priority, created_by, created_at,"
                           " updated_at FROM tasks ORDER BY created_at DESC",
                           limit=500)
        out = [{
            "task_id": r["task_id"], "project_id": r["project_id"],
            "title": r["title"], "notes": r["description"],
            "assignee": r["owner"], "status": r["status"],
            "priority": r["priority"], "created_by": r["created_by"],
            "created_at": r["created_at"], "updated_at": r["updated_at"],
        } for r in rows]
        self._json(req, {"ok": True, "tasks": out})

    def api_permissions(self, req, query, lang):
        peer = (query.get("peer") or [None])[0]
        if peer:
            rows = self.conn.list_permissions(peer)
        else:
            rows = self._q("SELECT agent_id, scope, granted, context,"
                           " granted_by, expires_at FROM permissions",
                           limit=1000)
        out = [{
            "agent_id": r["agent_id"], "scope": r["scope"],
            "granted": bool(r["granted"]), "context": r["context"],
            "granted_by": r["granted_by"], "expires_at": r["expires_at"],
        } for r in rows]
        self._json(req, {"ok": True, "permissions": out})

    def api_pairings(self, req, query, lang):
        rows = self.conn.store.list_pairing_sessions()
        out = [{
            "session_id": r["session_id"], "role": r["role"],
            "peer_id": r["peer_id"], "state": r["state"],
            "expires_at": r["expires_at"], "created_at": r["created_at"],
        } for r in rows]
        self._json(req, {"ok": True, "sessions": out})

    def api_audit(self, req, query, lang):
        try:
            limit = int((query.get("limit") or ["120"])[0])
        except ValueError:
            limit = 120
        limit = max(1, min(limit, 1000))
        rows = self.conn.audit_log(limit=limit)
        out = [{
            "event_id": r["event_id"], "timestamp": r["timestamp"],
            "actor": r["actor"], "action": r["action"], "target": r["target"],
            "result": r["result"], "details": r["details"],
        } for r in rows]
        self._json(req, {"ok": True, "events": out})

    def api_presence_list(self, req, query, lang):
        # GET /api/presence -> presence table
        rows = self.conn.list_presence()
        self._json(req, {"ok": True, "presence": [dict(r) for r in rows]})

    # --------------------------------------------------------- API: mutate
    def api_message_send(self, req, body, lang):
        from acp_connector import AcpError
        peer = body.get("peer")
        text = body.get("text")
        if not peer or not isinstance(text, str) or not text:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        c = self.conn
        try:
            c._require_peer(peer)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return

        # send_message blocks up to 30 s waiting for MSG_ACK; run it in the
        # background and answer 202. The message row is stored before the
        # ACK wait, so it shows up in /api/conversations immediately.
        # Attribution (message -> peer) is recorded twice: a fast path
        # below for the instant 202 response, and reliably here in the
        # background thread, because under load the row may be stored
        # after the fast path's short window expires.
        def _bg():
            mid = None
            try:
                mid = c.send_message(peer, text)
            except AcpError as e:
                c.audit.log("dashboard.send_failed", actor=peer,
                            result="failed",
                            details={"code": e.code, "detail": e.detail})
            if mid is None:
                mid = self._await_recent_sent(text, timeout=10.0)
            if mid:
                self._map_message(mid, peer)

        threading.Thread(target=_bg, daemon=True,
                         name="acp-dash-send").start()
        msg_id = self._await_recent_sent(text, timeout=2.0)
        if msg_id:
            self._map_message(msg_id, peer)
        c.audit.log("dashboard.message_queued", actor=peer, result="ok",
                    details={})
        self._json(req, {"ok": True, "queued": True, "peer": peer,
                         "message_id": msg_id}, 202)

    def _await_recent_sent(self, text, timeout=2.0):
        me = self.conn.peer_id
        deadline = time.time() + timeout
        while time.time() < deadline:
            for m in self.conn.store.list_messages(limit=20):
                if m["sender_id"] == me and m["text"] == text and \
                        m["created_at"] >= int(deadline - timeout) - 2:
                    return m["message_id"]
            time.sleep(0.1)
        return None

    def api_file_send(self, req, body, lang):
        from acp_connector import AcpError
        peer = body.get("peer")
        path = body.get("path")
        if not peer or not path:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        c = self.conn
        try:
            c._require_peer(peer)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        if not os.path.isfile(path):
            self._json(req, {"ok": False, "code": "NOT_FOUND",
                             "detail": t("err_not_found", lang)}, 404)
            return

        def _bg():
            try:
                c.send_file(peer, path)
            except AcpError as e:
                c.audit.log("dashboard.file_failed", actor=peer,
                            result="failed",
                            details={"code": e.code, "detail": e.detail})

        threading.Thread(target=_bg, daemon=True,
                         name="acp-dash-file").start()
        c.audit.log("dashboard.file_queued", actor=peer, result="ok",
                    details={"path": os.path.basename(path)})
        self._json(req, {"ok": True, "queued": True, "peer": peer,
                         "path": path}, 202)

    def api_permission_grant(self, req, body, lang):
        from acp_connector import AcpError, PERMS
        peer, scope = body.get("peer"), body.get("scope")
        if not peer or not scope:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        if scope not in PERMS:
            self._json(req, {"ok": False, "code": "UNKNOWN_SCOPE",
                             "detail": t("err_unknown_scope", lang)}, 400)
            return
        try:
            self.conn.grant_permission(peer, scope)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "peer": peer, "scope": scope})

    def api_permission_revoke(self, req, body, lang):
        peer, scope = body.get("peer"), body.get("scope")
        if not peer or not scope:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        self.conn.revoke_permission(peer, scope)
        self._json(req, {"ok": True, "peer": peer, "scope": scope})

    def api_peer_revoke(self, req, body, lang):
        from acp_connector import AcpError
        peer = body.get("peer")
        if not peer:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            self.conn.revoke_peer(peer)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "peer": peer, "revoked": True})

    def api_presence_set(self, req, body, lang):
        # POST /api/presence {state} -> set local presence.
        from acp_connector import AcpError
        from acp_connector.presence import VALID_STATES
        state = body.get("state")
        if state not in VALID_STATES:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            self.conn.set_presence(state)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "state": state})

    def api_pair_initiate(self, req, body, lang):
        from acp_connector import AcpError
        host, port = body.get("host"), body.get("port")
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
        if not host or not port:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            session = self.conn.pair_initiate(host, port)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "session_id": session.session_id,
                         "state": session.state})

    def api_pair_confirm(self, req, body, lang):
        from acp_connector import AcpError
        session_id, code = body.get("session_id"), body.get("code")
        if not session_id or not code:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        session = self.conn.pairing.get_session(session_id)
        if session is None:
            self._json(req, {"ok": False, "code": "NOT_FOUND",
                             "detail": t("err_not_found", lang)}, 404)
            return
        try:
            session.confirm(code)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "session_id": session_id,
                         "state": session.state})

    def api_project_create(self, req, body, lang):
        from acp_connector import AcpError
        title = body.get("title")
        notes = body.get("notes") or ""
        if not title:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            proj_id = self.conn.project_create(title, notes)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "project_id": proj_id})

    def api_task_add(self, req, body, lang):
        from acp_connector import AcpError
        project_id = body.get("project_id")
        title = body.get("title")
        assignee = body.get("assignee") or None
        notes = body.get("notes") or ""
        if not project_id or not title:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            task_id = self.conn.task_add(project_id, title, assignee, notes)
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "task_id": task_id})

    def api_task_update(self, req, body, lang):
        from acp_connector import AcpError
        task_id = body.get("task_id")
        if not task_id:
            self._json(req, {"ok": False, "code": "BAD_INPUT",
                             "detail": t("err_invalid_input", lang)}, 400)
            return
        try:
            self.conn.task_update(task_id, status=body.get("status"),
                                  notes=body.get("notes"))
        except AcpError as e:
            self._acp_fail(req, e, lang)
            return
        self._json(req, {"ok": True, "task_id": task_id})
