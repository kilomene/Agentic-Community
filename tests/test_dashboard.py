"""Dashboard tests: a real paired Connector pair driven over HTTP.

Spins up two real Connector instances on localhost, pairs them, then
exercises every dashboard REST endpoint (read round-trips plus all
mutations), including attack cases:

- missing / wrong token        -> 401
- path traversal (/api/../x)   -> 400
- wrong HTTP method            -> 405
- unknown /api/* path          -> 404
- malformed JSON body          -> 400
- unknown peer                 -> 404
- unknown permission scope     -> 400
- invalid presence state       -> 400

Run: python3 -m pytest tests/test_dashboard.py -q
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_connector import Connector  # noqa: E402


def _load_dashboard_server():
    # Loaded by file location under a unique module name: tests run in
    # one pytest process and another worker's tests/test_backend.py
    # already claims the bare ``server`` module name for
    # services/acp_api/server.py.
    import importlib.util
    path = os.path.join(ROOT, "apps", "acp_dashboard", "server.py")
    spec = importlib.util.spec_from_file_location("acp_dashboard_server",
                                                  path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


Dashboard = _load_dashboard_server().Dashboard

TOKEN = "dash-test-token-0123456789abcdef"


def wait_until(fn, timeout=30, interval=0.2, what="condition"):
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


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home1 = tempfile.mkdtemp(prefix="acp-dash-c1-")
        cls.home2 = tempfile.mkdtemp(prefix="acp-dash-c2-")
        cls.c1 = Connector(cls.home1, "dash-passphrase-one", handle="dash-one")
        cls.c2 = Connector(cls.home2, "dash-passphrase-two", handle="dash-two")
        port1 = cls.c1.start_server("127.0.0.1", 0)
        port2 = cls.c2.start_server("127.0.0.1", 0)
        assert port1 and port2

        # Pair c1 -> c2 (same handshake as tests/test_connector.py).
        ev = threading.Event()
        sessions = []
        cls.c2.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
        s1 = cls.c1.pair_initiate("127.0.0.1", port2)
        assert ev.wait(30), "responder never got pair_request"
        s2 = sessions[0]
        s2.accept()
        wait_until(lambda: s1.state == "await_code", what="challenge")
        s1.confirm(s2.code)
        wait_until(lambda: s1.state == "done" and s2.state == "done",
                   what="pairing completion")

        cls.dash = Dashboard(cls.c1, token=TOKEN)
        cls.port = cls.dash.start()
        cls.base = "http://127.0.0.1:%d" % cls.port
        # wait until the HTTP server answers
        wait_until(lambda: cls._raw("GET", "/api/status")[0] == 200,
                   what="dashboard http")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.dash.stop()
        except Exception:
            pass
        try:
            cls.c1.stop()
        except Exception:
            pass
        try:
            cls.c2.stop()
        except Exception:
            pass
        shutil.rmtree(cls.home1, ignore_errors=True)
        shutil.rmtree(cls.home2, ignore_errors=True)

    # ------------------------------------------------------------------ http
    @classmethod
    def _raw(cls, method, path, body=None, raw=None, token=TOKEN):
        data = None
        headers = {}
        if token is not None:
            headers["X-ACP-Token"] = token
        if raw is not None:
            data = raw.encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(cls.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    @classmethod
    def api(cls, method, path, body=None, raw=None, token=TOKEN):
        status, data, headers = cls._raw(method, path, body=body, raw=raw,
                                         token=token)
        try:
            obj = json.loads(data.decode("utf-8")) if data else None
        except ValueError:
            obj = None
        return status, obj, headers

    def get(self, path, **kw):
        return self.api("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.api("POST", path, body=body, **kw)

    # ------------------------------------------------------------- attack
    def test_attack_bad_json_400(self):
        status, obj, _ = self.post("/api/presence", raw="{not-json")
        self.assertEqual(status, 400)

    def test_attack_method_not_allowed_405(self):
        status, obj, _ = self.get("/api/message/send")
        self.assertEqual(status, 405)
        status, obj, _ = self.post("/api/status", body={})
        self.assertEqual(status, 405)
        status, obj, _ = self.get("/api/presence")
        self.assertEqual(status, 200)  # GET is the read side; sanity

    def test_attack_no_token_401(self):
        status, obj, _ = self.get("/api/status", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(obj["code"], "UNAUTHORIZED")

    def test_attack_post_no_token_401(self):
        status, obj, _ = self.post("/api/presence", {"state": "busy"},
                                   token=None)
        self.assertEqual(status, 401)

    def test_attack_traversal_400(self):
        for p in ("/api/../status", "/api/%2e%2e/status",
                  "/api/%2E%2E/%2E%2E/etc/passwd"):
            status, _, _ = self._raw("GET", p)
            self.assertEqual(status, 400, p)

    def test_attack_unknown_api_404(self):
        status, obj, _ = self.get("/api/definitely-not-here")
        self.assertEqual(status, 404)

    def test_attack_unknown_peer_404(self):
        status, obj, _ = self.post("/api/message/send",
                                   {"peer": "no-such-peer",
                                    "text": "hello?"})
        self.assertEqual(status, 404)

    def test_attack_unknown_scope_400(self):
        status, obj, _ = self.post(
            "/api/permission/grant",
            {"peer": self.c2.peer_id, "scope": "bogus_scope"})
        self.assertEqual(status, 400)
        self.assertEqual(obj["code"], "UNKNOWN_SCOPE")

    def test_attack_wrong_token_401(self):
        status, obj, _ = self.get("/api/status", token="wrong-token")
        self.assertEqual(status, 401)

    # ----------------------------------------------------------------- read
    def test_audit_lists_events(self):
        status, obj, _ = self.get("/api/audit?limit=50")
        self.assertEqual(status, 200)
        self.assertTrue(obj["ok"])
        self.assertIsInstance(obj["events"], list)
        self.assertGreater(len(obj["events"]), 0)
        ev = obj["events"][0]
        for k in ("event_id", "action", "timestamp"):
            self.assertIn(k, ev)

    def test_conversations_inbound_attribution(self):
        text = "inbound-%d" % time.time()
        self.c2.send_message(self.c1.peer_id, text)

        def find():
            status, obj, _ = self.get("/api/conversations")
            if status != 200:
                return None
            for conv in obj["conversations"]:
                if conv["peer_id"] != self.c2.peer_id:
                    continue
                for m in conv["messages"]:
                    if m["text"] == text and m["direction"] == "in":
                        return m
            return None

        m = wait_until(find, what="inbound message in conversations")
        self.assertEqual(m["sender"], self.c2.peer_id)

    def test_pairings_lists_done_session(self):
        status, obj, _ = self.get("/api/pairings")
        self.assertEqual(status, 200)
        mine = [s for s in obj["sessions"]
                if s["peer_id"] == self.c2.peer_id]
        self.assertTrue(mine, obj["sessions"])
        self.assertEqual(mine[0]["state"], "done")

    def test_peers_lists_paired(self):
        status, obj, _ = self.get("/api/peers")
        self.assertEqual(status, 200)
        peers = {p["agent_id"]: p for p in obj["peers"]}
        self.assertIn(self.c2.peer_id, peers)
        self.assertFalse(peers[self.c2.peer_id]["revoked"])

    def test_status_ok(self):
        status, obj, _ = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(obj["ok"])
        self.assertEqual(obj["handle"], "dash-one")
        self.assertEqual(obj["peer_id"], self.c1.peer_id)
        self.assertGreaterEqual(obj["counts"]["peers"], 1)

    # --------------------------------------------------------------- mutate
    def test_file_send_roundtrip(self):
        fname = "dash-payload-%d.bin" % int(time.time())
        content = b"ACP-DASHBOARD-FILE-TEST:" * 2048
        src = os.path.join(self.home1, fname)
        with open(src, "wb") as f:
            f.write(content)
        status, obj, _ = self.post("/api/file/send",
                                   {"peer": self.c2.peer_id, "path": src})
        self.assertEqual(status, 202)
        self.assertTrue(obj["queued"])

        def done():
            status, obj, _ = self.get("/api/files")
            if status != 200:
                return None
            for t in obj["transfers"]:
                if t["name"] == fname and t["state"] == "done":
                    return t
            return None

        t = wait_until(done, timeout=60, what="file transfer done")
        dest = os.path.join(self.c2.incoming_dir, fname)
        self.assertTrue(os.path.isfile(dest), dest)
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), content)

    def test_message_send_roundtrip(self):
        text = "dashboard-hello-%d" % int(time.time())
        status, obj, _ = self.post("/api/message/send",
                                   {"peer": self.c2.peer_id, "text": text})
        self.assertEqual(status, 202)
        self.assertTrue(obj["queued"])

        def find():
            status, obj, _ = self.get("/api/conversations")
            if status != 200:
                return None
            for conv in obj["conversations"]:
                if conv["peer_id"] != self.c2.peer_id:
                    continue
                for m in conv["messages"]:
                    if m["text"] == text and m["direction"] == "out":
                        return m
            return None

        m = wait_until(find, what="sent message in conversations")
        self.assertEqual(m["sender"], self.c1.peer_id)

    def test_permissions_grant_revoke(self):
        peer = self.c2.peer_id
        status, obj, _ = self.post("/api/permission/grant",
                                   {"peer": peer, "scope": "family_read"})
        self.assertEqual(status, 200)
        self.assertTrue(obj["ok"])

        def granted():
            status, obj, _ = self.get("/api/permissions?peer=" + peer)
            if status != 200:
                return None
            rows = [r for r in obj["permissions"]
                    if r["scope"] == "family_read" and r["granted"]]
            return rows or None

        self.assertTrue(wait_until(granted, what="grant visible"))
        status, obj, _ = self.post("/api/permission/revoke",
                                   {"peer": peer, "scope": "family_read"})
        self.assertEqual(status, 200)

        def revoked():
            status, obj, _ = self.get("/api/permissions?peer=" + peer)
            if status != 200:
                return None
            rows = [r for r in obj["permissions"]
                    if r["scope"] == "family_read" and r["granted"]]
            return not rows or None

        self.assertTrue(wait_until(revoked, what="revoke visible"))

    def test_presence_set_and_list(self):
        status, obj, _ = self.post("/api/presence", {"state": "busy"})
        self.assertEqual(status, 200)
        self.assertEqual(obj["state"], "busy")
        status, obj, _ = self.get("/api/presence")
        self.assertEqual(status, 200)
        mine = [p for p in obj["presence"]
                if p.get("agent_id") == self.c1.peer_id]
        self.assertTrue(mine)
        self.assertEqual(mine[0]["status"], "busy")
        # invalid state rejected
        status, obj, _ = self.post("/api/presence", {"state": "zzz"})
        self.assertEqual(status, 400)
        # restore
        status, obj, _ = self.post("/api/presence", {"state": "online"})
        self.assertEqual(status, 200)

    def test_project_task_flow(self):
        title = "dash-proj-%d" % int(time.time())
        status, obj, _ = self.post("/api/project/create",
                                   {"title": title, "notes": "n"})
        self.assertEqual(status, 200)
        pid = obj["project_id"]
        status, obj, _ = self.post("/api/task/add",
                                   {"project_id": pid, "title": "t1"})
        self.assertEqual(status, 200)
        tid = obj["task_id"]
        status, obj, _ = self.post("/api/task/update",
                                   {"task_id": tid, "status": "done"})
        self.assertEqual(status, 200)
        status, obj, _ = self.get("/api/tasks?project_id=" + pid)
        self.assertEqual(status, 200)
        tasks = {t["task_id"]: t for t in obj["tasks"]}
        self.assertIn(tid, tasks)
        self.assertEqual(tasks[tid]["status"], "done")
        self.assertEqual(tasks[tid]["project_id"], pid)

    def test_ui_lang_yo_sets_cookie(self):
        # The UI itself is public (no token); ?lang= re-renders + cookie.
        status, data, headers = self._raw("GET", "/?lang=yo", token=None)
        self.assertEqual(status, 200)
        body = data.decode("utf-8")
        self.assertIn("Ẹlẹgbẹ́", body)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("acp_lang=yo", cookie)

    def test_zz_peer_revoke(self):
        # Last: revoking the peer ends this fixture's usefulness.
        status, obj, _ = self.post("/api/peer/revoke",
                                   {"peer": self.c2.peer_id})
        self.assertEqual(status, 200)
        self.assertTrue(obj["revoked"])
        status, obj, _ = self.get("/api/peers")
        peers = {p["agent_id"]: p for p in obj["peers"]}
        self.assertTrue(peers[self.c2.peer_id]["revoked"])


if __name__ == "__main__":
    unittest.main()
