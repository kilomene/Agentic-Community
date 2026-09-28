"""acp_api server — public key directory + presence + agent registry +
identity verification + analytics (stdlib only).

Endpoints (JSON in, JSON out):
  POST /v1/register                  {handle, ipub, x_pub}        -> 200|400|409
  GET  /v1/resolve?handle=NAME                                      -> 200|400|404
  POST /v1/presence   [key: presence:write]
                       {handle, state, ts, sig}                    -> 200|400|401|404
  GET  /v1/presence?handle=NAME                                    -> 200|400|404

  POST /v1/listings   [key: listings:write]
                       {handle, display_name, capabilities[], owner,
                        metadata{}, ts, sig}                       -> 200|400|401|403|404|429
  GET  /v1/listings/search?q=&capability=&owner=&limit=&cursor=     -> 200|400
  GET  /v1/listings/{handle}                                       -> 200|400|404
  DELETE /v1/listings/{handle} [key: listings:write]
                       {handle, ts, sig}                          -> 200|400|401|403|404|429

  GET  /v1/verify/authority                                        -> 200
  POST /v1/verify/request [key: verify:request]
                       {handle, level, statement, ts, sig}         -> 200|400|401|403|404|429
  GET  /v1/verify/{handle}                                         -> 200|404
  POST /v1/verify/revoke {handle, reason, ts, authority_sig}       -> 200|400|401
  GET  /v1/verify/revoked                                          -> 200

  POST /v1/analytics/report [key: analytics:write]
                       {handle, day, counters{}, ts, sig}          -> 200|400|401|403|404|429
  GET  /v1/analytics/{handle}?days=N                               -> 200|400|404
  GET  /v1/analytics/{handle}/export?format=csv&days=N             -> 200|400|404

  GET  /healthz                                                    -> 200

Auth: keyed routes require `Authorization: Bearer <key>` where the key
was issued by the operator (`python -m acp_api keys create`).  Missing
or unknown key -> 401, missing scope -> 403, exhausted token bucket ->
429 with Retry-After.

Listing `sig` = b62(Ed25519_sign(identity_priv,
canonical({handle, display_name, capabilities, owner, metadata, ts})));
delete sig = b62(Ed25519_sign(identity_priv, canonical({handle, ts}))).
Analytics report sig = b62(Ed25519_sign(identity_priv,
canonical({handle, day, counters, ts}))).
Verification request: statement = canonical({agent_id, level,
external_ref, ts}) signed by the agent's registered identity key.

Storage: SQLite at services/acp_api/data/registry.db (created if missing).
The directory holds public keys and metadata only — never message or
file content (see docs/SECURITY.md, docs/ANALYTICS.md).
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

# Dual-mode import: works both as `import server` (tests put
# services/acp_api on sys.path) and as `python -m acp_api` (package).
try:
    from . import keys as api_keys
    from . import verify as verify_mod
except ImportError:  # pragma: no cover - top-level import mode
    import keys as api_keys
    import verify as verify_mod

VERSION = "1.0"
HANDLE_RE = re.compile(r"^[a-z0-9_]{3,32}$")
CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,39}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PRESENCE_STATES = frozenset({"online", "away", "busy", "offline"})
FRESHNESS_S = 300
MAX_BODY = 64 * 1024
SEARCH_DEFAULT_LIMIT = 20
SEARCH_MAX_LIMIT = 100
METADATA_MAX_BYTES = 4096

ANALYTICS_METRICS = frozenset({
    "messages_sent", "messages_received",
    "bytes_sent", "bytes_received",
    "files_completed", "pairings", "calls_placed", "uptime_days",
})


class ApiError(Exception):
    """HTTP error with a JSON-serializable message and optional headers."""

    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


def default_db_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "data", "registry.db")


def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS handles("
            "handle TEXT PRIMARY KEY, ipub BLOB NOT NULL, x_pub BLOB NOT NULL,"
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS presence("
            "handle TEXT PRIMARY KEY, state TEXT NOT NULL,"
            "ts INTEGER NOT NULL, sig TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS listings("
            "handle TEXT PRIMARY KEY, display_name TEXT NOT NULL,"
            "capabilities TEXT NOT NULL DEFAULT '[]',"
            "owner TEXT NOT NULL DEFAULT '',"
            "metadata TEXT NOT NULL DEFAULT '{}',"
            "ts INTEGER NOT NULL, listing_sig TEXT NOT NULL,"
            "updated_at INTEGER NOT NULL)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_listings_updated"
            " ON listings(updated_at DESC, handle ASC)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verify_badges("
            "handle TEXT PRIMARY KEY, agent_id TEXT NOT NULL,"
            "level TEXT NOT NULL, external_ref TEXT NOT NULL DEFAULT '',"
            "issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,"
            "authority_sig TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verify_revocations("
            "handle TEXT PRIMARY KEY, reason TEXT NOT NULL,"
            "revoked_at INTEGER NOT NULL, authority_sig TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS analytics("
            "handle TEXT NOT NULL, day TEXT NOT NULL, name TEXT NOT NULL,"
            "value INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL,"
            "PRIMARY KEY(handle, day, name))")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analytics_handle"
            " ON analytics(handle, day)")
        api_keys.ensure_schema(conn)
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


def _check_fresh(ts, what="timestamp"):
    now = int(time.time())
    if abs(now - ts) > FRESHNESS_S:
        raise ApiError(401, "%s outside +-300s window" % what)


def _like_escape(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ApiServer(ThreadingHTTPServer):
    def __init__(self, server_address, db_path):
        super().__init__(server_address, ApiHandler)
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(db_path))
        self.authority_priv, self.authority_pub = \
            verify_mod.load_authority(db_dir)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "acp_api/1.0"

    # -- plumbing ----------------------------------------------------

    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _db(self):
        conn = sqlite3.connect(self.server.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _send(self, status, obj, headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, text, content_type="text/csv"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "bad Content-Length")
        if n < 0:
            # read(negative) would read until EOF and hang the handler
            # thread on a keep-alive connection.
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

    def _path_handle(self, prefix):
        """Extract and validate the {handle} segment after prefix."""
        path = urlparse(self.path).path
        handle = path[len(prefix):]
        if "/" in handle or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle in path")
        return handle

    def _require_key(self, scope):
        """Bearer auth + scope check + token-bucket rate limit.

        401 unknown/missing key, 403 missing scope, 429 exhausted.
        Returns the key record.
        """
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            raise ApiError(
                401, "missing bearer api key"
                     " (Authorization: Bearer <key>)")
        raw = auth[len("Bearer "):].strip()
        rec = api_keys.lookup_key(self.server.db_path, raw)
        if rec is None:
            raise ApiError(401, "invalid api key")
        if scope not in rec["scopes"]:
            raise ApiError(403, "api key lacks scope '%s'" % scope)
        try:
            api_keys.consume_rate(self.server.db_path, rec["key_hash"],
                                  rec["per_min"])
        except api_keys.RateLimited as e:
            raise ApiError(429, "rate limit exceeded",
                           headers={"Retry-After": str(e.retry_after)})
        return rec

    def _get_ipub(self, conn, handle):
        row = conn.execute("SELECT ipub FROM handles WHERE handle=?",
                           (handle,)).fetchone()
        if row is None:
            raise ApiError(404, "unknown_handle")
        return bytes(row["ipub"])

    # -- routing -----------------------------------------------------

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
                if path == "/v1/listings/search":
                    return self._search_listings()
                if path.startswith("/v1/listings/"):
                    return self._get_listing(path)
                if path == "/v1/verify/authority":
                    return self._verify_authority()
                if path == "/v1/verify/revoked":
                    return self._verify_revoked()
                if path.startswith("/v1/verify/"):
                    return self._get_badge(path)
                if path.startswith("/v1/analytics/"):
                    if path.endswith("/export"):
                        return self._export_analytics(path)
                    return self._get_analytics(path)
            elif self.command == "POST":
                if path == "/v1/register":
                    return self._register()
                if path == "/v1/presence":
                    return self._set_presence()
                if path == "/v1/listings":
                    return self._publish_listing()
                if path == "/v1/verify/request":
                    return self._verify_request()
                if path == "/v1/verify/revoke":
                    return self._verify_revoke()
                if path == "/v1/analytics/report":
                    return self._report_analytics()
            elif self.command == "DELETE":
                if path.startswith("/v1/listings/"):
                    return self._delete_listing(path)
            if self.command in ("GET", "POST", "DELETE", "PUT", "PATCH"):
                known = ("/healthz", "/v1/register", "/v1/resolve",
                         "/v1/presence", "/v1/listings",
                         "/v1/listings/search", "/v1/verify/authority",
                         "/v1/verify/request", "/v1/verify/revoke",
                         "/v1/verify/revoked", "/v1/analytics/report")
                if path in known or path.startswith(
                        ("/v1/listings/", "/v1/verify/", "/v1/analytics/")):
                    return self._send(405, {"error": "method_not_allowed"})
            return self._send(404, {"error": "not_found"})
        except ApiError as e:
            return self._send(e.status, {"error": e.message},
                              headers=e.headers)
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

    # -- directory: register / resolve ---------------------------------

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

    # -- presence ------------------------------------------------------

    def _set_presence(self):
        self._require_key("presence:write")
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
        _check_fresh(ts, "presence timestamp")
        conn = self._db()
        try:
            ipub = self._get_ipub(conn, handle)
            msg = canonical({"handle": handle, "state": state, "ts": ts})
            if not ed25519_verify(ipub, msg, sig):
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

    # -- registry: listings --------------------------------------------

    def _validate_listing_fields(self, body):
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "handle must match [a-z0-9_]{3,32}")
        display_name = body.get("display_name")
        if not isinstance(display_name, str) or not 1 <= len(display_name) <= 64:
            raise ApiError(400, "display_name must be 1..64 chars")
        capabilities = body.get("capabilities")
        if not isinstance(capabilities, list) or len(capabilities) > 32:
            raise ApiError(400, "capabilities must be a list (max 32)")
        for c in capabilities:
            if not isinstance(c, str) or not CAPABILITY_RE.match(c):
                raise ApiError(400, "bad capability: %r" % (c,))
        owner = body.get("owner")
        if not isinstance(owner, str) or not 1 <= len(owner) <= 64:
            raise ApiError(400, "owner must be 1..64 chars")
        metadata = body.get("metadata")
        if not isinstance(metadata, dict):
            raise ApiError(400, "metadata must be an object")
        if len(canonical(metadata)) > METADATA_MAX_BYTES:
            raise ApiError(400, "metadata too large (max 4KB canonical)")
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        return handle, display_name, capabilities, owner, metadata, ts

    def _publish_listing(self):
        self._require_key("listings:write")
        body = self._read_json()
        handle, display_name, capabilities, owner, metadata, ts = \
            self._validate_listing_fields(body)
        sig = decode_sig(body.get("sig"))
        _check_fresh(ts, "listing timestamp")
        conn = self._db()
        try:
            ipub = self._get_ipub(conn, handle)
            msg = canonical({"handle": handle, "display_name": display_name,
                             "capabilities": capabilities, "owner": owner,
                             "metadata": metadata, "ts": ts})
            if not ed25519_verify(ipub, msg, sig):
                raise ApiError(401, "bad signature")
            now = int(time.time())
            conn.execute(
                "INSERT OR REPLACE INTO listings(handle, display_name,"
                " capabilities, owner, metadata, ts, listing_sig, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (handle, display_name, json.dumps(capabilities), owner,
                 json.dumps(metadata), ts, body["sig"], now))
            conn.commit()
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle,
                                "updated_at": now})

    def _listing_row(self, row):
        return {
            "handle": row["handle"],
            "display_name": row["display_name"],
            "capabilities": json.loads(row["capabilities"]),
            "owner": row["owner"],
            "metadata": json.loads(row["metadata"]),
            "ts": row["ts"],
            "listing_sig": row["listing_sig"],
            "updated_at": row["updated_at"],
        }

    def _get_listing(self, path):
        handle = self._path_handle("/v1/listings/")
        conn = self._db()
        try:
            row = conn.execute(
                "SELECT * FROM listings WHERE handle=?", (handle,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return self._send(404, {"error": "unknown_handle"})
        return self._send(200, self._listing_row(row))

    def _delete_listing(self, path):
        self._require_key("listings:write")
        handle = self._path_handle("/v1/listings/")
        body = self._read_json()
        if body.get("handle") != handle:
            raise ApiError(400, "body handle must match path handle")
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        sig = decode_sig(body.get("sig"))
        _check_fresh(ts, "listing timestamp")
        conn = self._db()
        try:
            ipub = self._get_ipub(conn, handle)
            msg = canonical({"handle": handle, "ts": ts})
            if not ed25519_verify(ipub, msg, sig):
                raise ApiError(401, "bad signature")
            cur = conn.execute("DELETE FROM listings WHERE handle=?",
                               (handle,))
            conn.commit()
            if cur.rowcount == 0:
                raise ApiError(404, "no listing for handle")
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle})

    def _search_listings(self):
        q = parse_qs(urlparse(self.path).query)
        qstr = q.get("q", [None])[0]
        capability = q.get("capability", [None])[0]
        owner = q.get("owner", [None])[0]
        limit_s = q.get("limit", [str(SEARCH_DEFAULT_LIMIT)])[0]
        cursor = q.get("cursor", [None])[0]
        try:
            limit = int(limit_s)
        except (TypeError, ValueError):
            raise ApiError(400, "limit must be an integer")
        if not 1 <= limit <= SEARCH_MAX_LIMIT:
            raise ApiError(400, "limit must be 1..%d" % SEARCH_MAX_LIMIT)
        if capability is not None and not CAPABILITY_RE.match(capability):
            raise ApiError(400, "bad capability filter")
        cur_ts, cur_handle = None, None
        if cursor:
            try:
                ts_s, h = cursor.split(":", 1)
                cur_ts, cur_handle = int(ts_s), h
            except (ValueError, TypeError):
                raise ApiError(400, "bad cursor (want updated_at:handle)")
            if not HANDLE_RE.match(cur_handle):
                raise ApiError(400, "bad cursor (want updated_at:handle)")

        conds, args = [], []
        if cur_ts is not None:
            conds.append("(updated_at < ? OR (updated_at = ? AND handle > ?))")
            args += [cur_ts, cur_ts, cur_handle]
        if qstr:
            esc = "%" + _like_escape(qstr) + "%"
            conds.append(
                "(display_name LIKE ? ESCAPE '\\' OR capabilities LIKE ?"
                " ESCAPE '\\' OR owner LIKE ? ESCAPE '\\'"
                " OR metadata LIKE ? ESCAPE '\\')")
            args += [esc, esc, esc, esc]
        if capability:
            # exact member match inside the JSON array text: ["cap",...]
            conds.append("capabilities LIKE ?")
            args.append('%"' + capability + '"%')
        if owner:
            conds.append("owner LIKE ? ESCAPE '\\'")
            args.append("%" + _like_escape(owner) + "%")
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        sql = ("SELECT * FROM listings %s ORDER BY updated_at DESC,"
               " handle ASC LIMIT ?" % where)
        args.append(limit + 1)

        conn = self._db()
        try:
            rows = conn.execute(sql, args).fetchall()
        finally:
            conn.close()
        items = [self._listing_row(r) for r in rows[:limit]]
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = "%d:%s" % (last["updated_at"], last["handle"])
        return self._send(200, {"listings": items,
                                "next_cursor": next_cursor})

    # -- identity verification -----------------------------------------

    def _verify_authority(self):
        return self._send(200, {
            "authority_pub": b62encode(self.server.authority_pub)})

    def _verify_request(self):
        self._require_key("verify:request")
        body = self._read_json()
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        level = body.get("level")
        if level not in verify_mod.VERIFY_LEVELS:
            raise ApiError(400, "level must be one of %s"
                           % list(verify_mod.VERIFY_LEVELS))
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        statement = body.get("statement")
        if not isinstance(statement, dict):
            raise ApiError(400, "statement must be an object")
        sig = decode_sig(body.get("sig"))
        _check_fresh(ts, "verification timestamp")

        conn = self._db()
        try:
            ipub = self._get_ipub(conn, handle)
            agent_id = b62encode(ipub)
            # the statement must describe this handle's key, this level,
            # and this timestamp — nothing else is attested
            if statement.get("agent_id") != agent_id:
                raise ApiError(400, "statement agent_id does not match"
                                    " the registered key for handle")
            if statement.get("level") != level:
                raise ApiError(400, "statement level does not match")
            if statement.get("ts") != ts:
                raise ApiError(400, "statement ts does not match")
            external_ref = statement.get("external_ref", "")
            if level == "self":
                if external_ref not in ("", None):
                    raise ApiError(400, "level 'self' takes no external_ref")
                external_ref = ""
            else:  # owner-linked
                if not isinstance(external_ref, str) or not \
                        1 <= len(external_ref) <= 128:
                    raise ApiError(400, "owner-linked needs external_ref"
                                        " (1..128 chars)")
            msg = canonical({"agent_id": agent_id, "level": level,
                             "external_ref": external_ref, "ts": ts})
            if not ed25519_verify(ipub, msg, sig):
                raise ApiError(401, "bad signature")
            now = int(time.time())
            payload = verify_mod.badge_payload(
                handle, agent_id, level, external_ref, now)
            badge = verify_mod.sign_badge(self.server.authority_priv,
                                          payload)
            conn.execute(
                "INSERT OR REPLACE INTO verify_badges(handle, agent_id, level,"
                " external_ref, issued_at, expires_at, authority_sig)"
                " VALUES (?,?,?,?,?,?,?)",
                (handle, agent_id, level, external_ref, now,
                 payload["expires_at"], badge["authority_sig"]))
            # a fresh attestation supersedes any earlier revocation
            conn.execute("DELETE FROM verify_revocations WHERE handle=?",
                         (handle,))
            conn.commit()
        finally:
            conn.close()
        return self._send(200, badge)

    def _get_badge(self, path):
        handle = self._path_handle("/v1/verify/")
        conn = self._db()
        try:
            rev = conn.execute(
                "SELECT handle, reason, revoked_at FROM verify_revocations"
                " WHERE handle=?", (handle,)).fetchone()
            if rev is not None:
                return self._send(200, {
                    "handle": rev["handle"], "revoked": True,
                    "reason": rev["reason"], "revoked_at": rev["revoked_at"]})
            row = conn.execute(
                "SELECT handle, agent_id, level, external_ref, issued_at,"
                " expires_at, authority_sig FROM verify_badges"
                " WHERE handle=?", (handle,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return self._send(404, {"error": "no_badge"})
        return self._send(200, dict(row))

    def _verify_revoke(self):
        body = self._read_json()
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        reason = body.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 256:
            raise ApiError(400, "reason must be 1..256 chars")
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        sig_b62 = body.get("authority_sig")
        sig = decode_sig(sig_b62 if isinstance(sig_b62, str) else None)
        _check_fresh(ts, "revocation timestamp")
        msg = canonical({"handle": handle, "reason": reason, "ts": ts})
        if not ed25519_verify(self.server.authority_pub, msg, sig):
            raise ApiError(401, "bad authority signature")
        now = int(time.time())
        conn = self._db()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO verify_revocations(handle, reason,"
                " revoked_at, authority_sig) VALUES (?,?,?,?)",
                (handle, reason, now, sig_b62))
            conn.commit()
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle,
                                "revoked_at": now})

    def _verify_revoked(self):
        conn = self._db()
        try:
            rows = conn.execute(
                "SELECT handle, reason, revoked_at FROM verify_revocations"
                " ORDER BY revoked_at DESC").fetchall()
        finally:
            conn.close()
        return self._send(200, {"revoked": [dict(r) for r in rows]})

    # -- analytics -----------------------------------------------------

    def _validate_day(self, day):
        if not isinstance(day, str) or not DAY_RE.match(day):
            raise ApiError(400, "day must be YYYY-MM-DD")
        try:
            today = time.strftime("%Y-%m-%d", time.gmtime())
            if day > today or day < "2020-01-01":
                raise ApiError(400, "day out of range")
        except ApiError:
            raise
        except Exception:
            raise ApiError(400, "bad day")

    def _report_analytics(self):
        self._require_key("analytics:write")
        body = self._read_json()
        handle = body.get("handle")
        if not isinstance(handle, str) or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        day = body.get("day")
        self._validate_day(day)
        counters = body.get("counters")
        if not isinstance(counters, dict) or not counters:
            raise ApiError(400, "counters must be a non-empty object")
        if len(counters) > 32:
            raise ApiError(400, "too many counters (max 32)")
        for name, value in counters.items():
            if name not in ANALYTICS_METRICS:
                raise ApiError(400, "unknown metric: %r" % (name,))
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                raise ApiError(400, "counter %r must be a non-negative int"
                               % (name,))
        ts = body.get("ts")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ApiError(400, "ts must be an integer unix timestamp")
        sig = decode_sig(body.get("sig"))
        _check_fresh(ts, "analytics timestamp")
        conn = self._db()
        try:
            ipub = self._get_ipub(conn, handle)
            msg = canonical({"handle": handle, "day": day,
                             "counters": counters, "ts": ts})
            if not ed25519_verify(ipub, msg, sig):
                raise ApiError(401, "bad signature")
            now = int(time.time())
            for name, value in counters.items():
                conn.execute(
                    "INSERT OR REPLACE INTO analytics(handle, day, name,"
                    " value, updated_at) VALUES (?,?,?,?,?)",
                    (handle, day, name, value, now))
            conn.commit()
        finally:
            conn.close()
        return self._send(200, {"ok": True, "handle": handle, "day": day,
                                "stored": len(counters)})

    def _analytics_sums(self, handle, days):
        q = parse_qs(urlparse(self.path).query)
        try:
            days = int(q.get("days", [str(days)])[0])
        except (TypeError, ValueError):
            raise ApiError(400, "days must be an integer")
        if not 1 <= days <= 365:
            raise ApiError(400, "days must be 1..365")
        if not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle")
        conn = self._db()
        try:
            exists = conn.execute(
                "SELECT 1 FROM handles WHERE handle=?", (handle,)).fetchone()
            if exists is None:
                raise ApiError(404, "unknown_handle")
            today = time.strftime("%Y-%m-%d", time.gmtime())
            rows = conn.execute(
                "SELECT name, SUM(value) AS total FROM analytics"
                " WHERE handle=? AND day > date(?, ? || ' days')"
                " GROUP BY name",
                (handle, today, "-%d" % days)).fetchall()
        finally:
            conn.close()
        return days, today, {r["name"]: r["total"] for r in rows}

    def _get_analytics(self, path):
        handle = self._path_handle("/v1/analytics/")
        days, today, sums = self._analytics_sums(handle, 30)
        from_day = time.strftime(
            "%Y-%m-%d",
            time.gmtime(time.time() - (days - 1) * 86400))
        return self._send(200, {"handle": handle, "days": days,
                                "from_day": from_day, "to_day": today,
                                "counters": sums})

    def _export_analytics(self, path):
        prefix = "/v1/analytics/"
        handle = path[len(prefix):-len("/export")]
        if "/" in handle or not HANDLE_RE.match(handle):
            raise ApiError(400, "invalid handle in path")
        q = parse_qs(urlparse(self.path).query)
        fmt = q.get("format", ["csv"])[0]
        if fmt not in ("csv", "json"):
            raise ApiError(400, "format must be csv or json")
        days, today, sums = self._analytics_sums(handle, 30)
        if fmt == "json":
            from_day = time.strftime(
                "%Y-%m-%d",
                time.gmtime(time.time() - (days - 1) * 86400))
            return self._send(200, {"handle": handle, "days": days,
                                    "from_day": from_day, "to_day": today,
                                    "counters": sums})
        conn = self._db()
        try:
            rows = conn.execute(
                "SELECT day, name, value FROM analytics"
                " WHERE handle=? AND day > date(?, ? || ' days')"
                " ORDER BY day ASC, name ASC",
                (handle, today, "-%d" % days)).fetchall()
        finally:
            conn.close()
        lines = ["handle,day,metric,value"]
        for r in rows:
            lines.append("%s,%s,%s,%d"
                         % (handle, r["day"], r["name"], r["value"]))
        return self._send_text(200, "\n".join(lines) + "\n")


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
    p = argparse.ArgumentParser(
        description="acp_api directory + registry + verification + analytics")
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
