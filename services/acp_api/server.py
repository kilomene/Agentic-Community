"""acp_api server — public key directory + presence (stdlib only).

Endpoints (JSON in, JSON out):
  POST /v1/register   {handle, ipub, x_pub}      -> 200 | 400 | 409
  GET  /v1/resolve?handle=NAME                    -> 200 | 400 | 404
  POST /v1/presence    {handle, state, ts, sig}    -> 200 | 400 | 401 | 404
  GET  /v1/presence?handle=NAME                   -> 200 | 400 | 404
  GET  /healthz                                    -> 200

Storage: SQLite at services/acp_api/data/registry.db (created if missing):
  handles(handle TEXT PK, ipub BLOB, x_pub BLOB, created_at INT, updated_at INT)
  presence(handle TEXT PK, state TEXT, ts INT, sig TEXT)

Keys are base62-encoded on the wire (32-byte Ed25519 identity key `ipub`,
32-byte X25519 key `x_pub`; leading zero bytes are restored on decode).
Presence `sig` = b62(Ed25519_sign(identity_key, canonical({handle,state,ts}))).

The directory holds public keys and presence metadata only. It never sees
message content (see docs/SECURITY.md).
"""
import json
import os
import re
import sqlite3
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "packages"))

from acp_crypto import ed25519_verify
from acp_proto import b62encode, b62decode, canonical

VERSION = "1.0"
HANDLE_RE = re.compile(r"^[a-z0-9_]{3,32}$")
PRESENCE_STATES = frozenset({"online", "away", "busy", "offline"})
FRESHNESS_S = 300
MAX_BODY = 64 * 1024


class ApiError(Exception):
    """HTTP error with a JSON-serializable message."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def default_db_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "data", "registry.db")


def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS handles("
            "handle TEXT PRIMARY KEY, ipub BLOB NOT NULL, x_pub BLOB NOT NULL,"
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS presence("
            "handle TEXT PRIMARY KEY, state TEXT NOT NULL,"
            "ts INTEGER NOT NULL, sig TEXT NOT NULL)")
        conn.commit()
    finally:
        conn.close()


def decode_key(s, name):
    """Decode a b62 public key, restoring to exactly 32 bytes."""
    if not isinstance(s, str) or not s:
        raise ApiError(400, "%s must be a non-empty base62 string" % name)
    try:
        raw = b62decode(s)
    except (ValueError, KeyError):
        raise ApiError(400, "%s is not valid base62" % name)
    if len(raw) > 32:
        raise ApiError(400, "%s decodes to more than 32 bytes" % name)
    return raw.rjust(32, b"\x00")


def decode_sig(s):
    if not isinstance(s, str) or not s:
        raise ApiError(401, "sig must be a non-empty base62 string")
    try:
        raw = b62decode(s)
    except (ValueError, KeyError):
        raise ApiError(401, "sig is not valid base62")
    if len(raw) > 64:
        raise ApiError(401, "sig decodes to more than 64 bytes")
    return raw.rjust(64, b"\x00")


class ApiServer(ThreadingHTTPServer):
    def __init__(self, server_address, db_path):
        super().__init__(server_address, ApiHandler)
        self.db_path = db_path


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "acp_api/1.0"

    # -- plumbing ----------------------------------------------------

    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _db(self):
        conn = sqlite3.connect(self.server.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _send(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "bad Content-Length")
        if n > MAX_BODY:
            raise ApiError(400, "body too large")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            raise ApiError(400, "empty body")
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "body is not valid JSON")
        if not isinstance(obj, dict):
            raise ApiError(400, "body must be a JSON object")
        return obj

    def _query_handle(self):
        q = parse_qs(urlparse(self.path).query)
        handle = q.get("handle", [None])[0]
        if not handle:
            raise ApiError(400, "missing ?handle=")
        if not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        return handle

    def _route(self):
        path = urlparse(self.path).path
        try:
            if self.command == "GET":
                if path == "/healthz":
                    return self._send(200, {"ok": True, "version": VERSION})
                if path == "/v1/resolve":
                    return self._resolve()
                if path == "/v1/presence":
                    return self._get_presence()
                if path in ("/v1/register",):
                    return self._send(405, {"error": "method_not_allowed"})
            elif self.command == "POST":
                if path == "/v1/register":
                    return self._register()
                if path == "/v1/presence":
                    return self._set_presence()
                if path in ("/v1/resolve", "/v1/presence", "/healthz"):
                    return self._send(405, {"error": "method_not_allowed"})
            return self._send(404, {"error": "not_found"})
        except ApiError as e:
            return self._send(e.status, {"error": e.message})
        except BrokenPipeError:
            pass
        except Exception:
            traceback.print_exc()
            try:
                return self._send(500, {"error": "internal"})
            except BrokenPipeError:
                pass

    do_GET = _route
    do_POST = _route
    do_PUT = _route
    do_DELETE = _route
    do_PATCH = _route

    # -- endpoints ---------------------------------------------------

    def _register(self):
        body = self._read_json()
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "handle must match [a-z0-9_]{3,32}")
        ipub = decode_key(body.get("ipub"), "ipub")
        x_pub = decode_key(body.get("x_pub"), "x_pub")
        now = int(time.time())
        conn = self._db()
        try:
            try:
                conn.execute(
                    "INSERT INTO handles(handle, ipub, x_pub, created_at, updated_at)"
                    " VALUES (?,?,?,?,?)", (handle, ipub, x_pub, now, now))
                conn.commit()
            except sqlite3.IntegrityError:
                raise ApiError(409, "handle already registered")
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle})

    def _resolve(self):
        handle = self._query_handle()
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT handle, ipub, x_pub, updated_at FROM handles WHERE handle=?",
                (handle,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return self._send(404, {"error": "unknown_handle"})
        return self._send(200, {
            "handle": row["handle"],
            "ipub": b62encode(row["ipub"]),
            "x_pub": b62encode(row["x_pub"]),
            "updated_at": row["updated_at"],
        })

    def _set_presence(self):
        body = self._read_json()
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        state = body.get("state")
        if state not in PRESENCE_STATES:
            raise ApiError(400, "state must be one of %s"
                           % sorted(PRESENCE_STATES))
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        sig = decode_sig(body.get("sig"))
        now = int(time.time())
        if abs(now - ts) > FRESHNESS_S:
            raise ApiError(401, "presence timestamp outside +-300s window")
        conn = self._db()
        try:
            row = conn.execute("SELECT ipub FROM handles WHERE handle=?",
                               (handle,)).fetchone()
            if row is None:
                raise ApiError(404, "unknown_handle")
            msg = canonical({"handle": handle, "state": state, "ts": ts})
            if not ed25519_verify(bytes(row["ipub"]), msg, sig):
                raise ApiError(401, "bad signature")
            conn.execute(
                "INSERT OR REPLACE INTO presence(handle, state, ts, sig)"
                " VALUES (?,?,?,?)", (handle, state, ts, body["sig"]))
            conn.commit()
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle,
                                "state": state, "ts": ts})

    def _get_presence(self):
        handle = self._query_handle()
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT handle, state, ts FROM presence WHERE handle=?",
                (handle,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return self._send(404, {"error": "unknown_handle"})
        return self._send(200, {"handle": row["handle"],
                                "state": row["state"], "ts": row["ts"]})


# -- lifecycle --------------------------------------------------------

def run(host="127.0.0.1", port=8080, db_path=None):
    """Start the API server in a background thread.

    Returns (server, thread). Shut down gracefully with
    graceful_shutdown(server, thread).
    """
    db_path = db_path or default_db_path()
    init_db(db_path)
    server = ApiServer((host, port), db_path)
    thread = threading.Thread(target=server.serve_forever,
                              name="acp-api", daemon=True)
    thread.start()
    return server, thread


def graceful_shutdown(server, thread, timeout=5):
    server.shutdown()
    server.server_close()
    thread.join(timeout)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="acp_api directory + presence")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--db", default=None,
                   help="SQLite path (default services/acp_api/data/registry.db)")
    args = p.parse_args(argv)
    server, thread = run(args.host, args.port, args.db)
    print("acp_api listening on %s:%d (db %s)"
          % (args.host, args.port, server.db_path), flush=True)
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        graceful_shutdown(server, thread)
        print("acp_api stopped", flush=True)


if __name__ == "__main__":
    main()
