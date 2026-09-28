"""keys.py — API keys for third-party access to acp_api (stdlib only).

Key format: ``acp_`` + 32 base62 chars (192 bits of entropy).
The server stores only sha256(key) + name + scopes + per_min +
created_at; the raw key is shown once at creation and never stored.

Scopes:
  registry:read   — (reserved; public reads need no key today)
  listings:write  — POST/DELETE /v1/listings
  presence:write  — POST /v1/presence
  analytics:read  — (reserved; public reads need no key today)
  analytics:write — POST /v1/analytics/report
  verify:request  — POST /v1/verify/request

Rate limiting: per-key token bucket refilled at per_min tokens/minute.
Bursts beyond the bucket return 429 with a Retry-After hint.

CLI (run from services/):
  python -m acp_api keys create --scopes listings:write --rate 60 --name bot
  python -m acp_api keys list
  python -m acp_api keys revoke acp_XXXX
"""
import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
import time

# make acp_crypto / acp_proto importable whether this module is loaded
# as acp_api.keys (python -m acp_api) or as top-level keys (tests)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "packages"))

from acp_crypto import random_bytes
from acp_proto import b62encode

VALID_SCOPES = frozenset({
    "registry:read",
    "listings:write",
    "presence:write",
    "analytics:read",
    "analytics:write",
    "verify:request",
})

KEY_PREFIX = "acp_"
KEY_BODY_LEN = 32


class KeyError_(Exception):
    pass


class RateLimited(Exception):
    """Raised by consume_rate: .retry_after (int seconds)."""

    def __init__(self, retry_after):
        super().__init__("rate limit exceeded")
        self.retry_after = int(retry_after)


def ensure_schema(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS api_keys("
        "key_hash TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',"
        "scopes TEXT NOT NULL, per_min INTEGER NOT NULL,"
        "created_at INTEGER NOT NULL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rate_buckets("
        "key_hash TEXT PRIMARY KEY, tokens REAL NOT NULL,"
        "ts REAL NOT NULL)")


def generate_api_key():
    """-> 'acp_' + 32 base62 chars."""
    while True:
        body = b62encode(random_bytes(24))
        if len(body) > KEY_BODY_LEN:
            continue  # 24 bytes can encode to 33 chars; retry
        return KEY_PREFIX + body.rjust(KEY_BODY_LEN, "0")


def key_hash(raw_key):
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _open(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def create_key(db_path, name="", scopes=(), per_min=60):
    """Create a key. Returns (raw_key, record dict). Raises KeyError_."""
    scopes = list(scopes)
    bad = [s for s in scopes if s not in VALID_SCOPES]
    if bad:
        raise KeyError_("unknown scopes: %s (valid: %s)"
                        % (bad, sorted(VALID_SCOPES)))
    if not isinstance(per_min, int) or isinstance(per_min, bool) \
            or not 1 <= per_min <= 100000:
        raise KeyError_("per_min must be an int in 1..100000")
    raw = generate_api_key()
    now = int(time.time())
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        conn.execute(
            "INSERT INTO api_keys(key_hash, name, scopes, per_min,"
            " created_at) VALUES (?,?,?,?,?)",
            (key_hash(raw), name or "", json.dumps(sorted(set(scopes))),
             per_min, now))
        conn.commit()
    finally:
        conn.close()
    return raw, {"name": name or "", "scopes": sorted(set(scopes)),
                 "per_min": per_min, "created_at": now,
                 "key_hash": key_hash(raw)}


def list_keys(db_path):
    """-> [{name, scopes, per_min, created_at, key_prefix}] (no raw keys)."""
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        rows = conn.execute(
            "SELECT key_hash, name, scopes, per_min, created_at FROM api_keys"
            " ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return [{"key_hash": r["key_hash"][:12] + "...",
             "name": r["name"], "scopes": json.loads(r["scopes"]),
             "per_min": r["per_min"], "created_at": r["created_at"]}
            for r in rows]


def revoke_key(db_path, key_or_prefix):
    """Revoke by full key or unique hash prefix. Returns True if removed."""
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        if key_or_prefix.startswith(KEY_PREFIX):
            target = key_hash(key_or_prefix)
            cur = conn.execute("DELETE FROM api_keys WHERE key_hash=?",
                               (target,))
        else:
            cur = conn.execute(
                "DELETE FROM api_keys WHERE key_hash LIKE ?",
                (key_or_prefix + "%",))
        n = cur.rowcount
        conn.execute("DELETE FROM rate_buckets WHERE key_hash LIKE ?",
                     (key_or_prefix + "%",))
        conn.commit()
        return n > 0
    finally:
        conn.close()


def lookup_key(db_path, raw_key):
    """-> record dict {name, scopes, per_min, created_at, key_hash} or None."""
    if not isinstance(raw_key, str) or not raw_key.startswith(KEY_PREFIX):
        return None
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        row = conn.execute(
            "SELECT key_hash, name, scopes, per_min, created_at FROM api_keys"
            " WHERE key_hash=?", (key_hash(raw_key),)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"key_hash": row["key_hash"], "name": row["name"],
            "scopes": json.loads(row["scopes"]), "per_min": row["per_min"],
            "created_at": row["created_at"]}


def consume_rate(db_path, key_hash_hex, per_min):
    """Token bucket: consume 1 token. Raises RateLimited on exhaustion."""
    now = time.time()
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        row = conn.execute(
            "SELECT tokens, ts FROM rate_buckets WHERE key_hash=?",
            (key_hash_hex,)).fetchone()
        if row is None:
            tokens, ts = float(per_min), now
        else:
            tokens = min(float(per_min),
                         float(row["tokens"])
                         + (now - float(row["ts"])) * per_min / 60.0)
        if tokens < 1.0:
            retry_after = max(
                1, math.ceil((1.0 - tokens) * 60.0 / per_min))
            conn.execute(
                "INSERT OR REPLACE INTO rate_buckets(key_hash, tokens, ts)"
                " VALUES (?,?,?)", (key_hash_hex, tokens, now))
            conn.commit()
            raise RateLimited(retry_after)
        tokens -= 1.0
        conn.execute(
            "INSERT OR REPLACE INTO rate_buckets(key_hash, tokens, ts)"
            " VALUES (?,?,?)", (key_hash_hex, tokens, now))
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------- CLI

def _default_db():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "data", "registry.db")


def main(argv=None):
    p = argparse.ArgumentParser(prog="acp_api keys",
                                description="Manage acp_api third-party keys")
    # --db is accepted before or after the subcommand
    argv = list(argv) if argv is not None else sys.argv[1:]
    db_path = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--db" and i + 1 < len(argv):
            db_path = argv[i + 1]
            i += 2
        elif argv[i].startswith("--db="):
            db_path = argv[i][len("--db="):]
            i += 1
        else:
            rest.append(argv[i])
            i += 1
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="issue a new API key")
    c.add_argument("--scopes", required=True,
                   help="comma-separated scopes, e.g. listings:write,presence:write")
    c.add_argument("--rate", type=int, default=60,
                   help="requests per minute (default 60)")
    c.add_argument("--name", default="", help="human label for the key")

    sub.add_parser("list", help="list issued keys (hashes only)")

    r = sub.add_parser("revoke", help="revoke a key")
    r.add_argument("key_or_prefix", help="full key or unique hash prefix")

    args = p.parse_args(rest)
    db_path = db_path or _default_db()
    # make sure the DB (and key tables) exist
    conn = _open(db_path)
    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    if args.cmd == "create":
        scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        try:
            raw, rec = create_key(db_path, name=args.name,
                                  scopes=scopes, per_min=args.rate)
        except KeyError_ as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        print("API key (shown once — store it now):")
        print(raw)
        print("name=%s scopes=%s per_min=%d created_at=%d"
              % (rec["name"], ",".join(rec["scopes"]), rec["per_min"],
                 rec["created_at"]))
        return 0
    if args.cmd == "list":
        items = list_keys(db_path)
        if not items:
            print("(no keys)")
        for it in items:
            print("%s  name=%s scopes=%s per_min=%d created_at=%d"
                  % (it["key_hash"], it["name"] or "-",
                     ",".join(it["scopes"]), it["per_min"],
                     it["created_at"]))
        return 0
    if args.cmd == "revoke":
        ok = revoke_key(db_path, args.key_or_prefix)
        print("revoked" if ok else "not found")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
