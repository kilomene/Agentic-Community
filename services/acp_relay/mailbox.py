"""Offline message mailbox for acp_relay: SQLite-backed store-and-forward.

When the relay's dispatch() targets a peer that is not currently
connected, the raw envelope frame bytes are stored here instead of
being dropped. On the peer's next hello/reconnect the relay drains the
queued frames in FIFO order BEFORE any new traffic, marks them
in-flight, and deletes them once the client confirms receipt with a
``mailbox_ack`` control frame. Frames never acked are retried on the
next reconnect.

What is stored:
  * only ACP envelope frames (never control frames such as ping,
    mailbox_ack, or relay-link frames);
  * the ORIGINAL signed bytes — the relay cannot forge or re-sign, so
    the recipient's normal signature verification still applies on
    delivery (defense in depth: even a poisoned mailbox entry is
    rejected by the recipient with INVALID_SIG).

Bounds (all configurable; defaults match the ACP v2 spec):
  * per-recipient: 1000 envelopes AND 25 MiB — oldest-first eviction;
  * per-frame TTL: 7 days (expired frames are dropped, never delivered);
  * global envelope cap (default 100k) as an anti-spam backstop so one
    sender cannot fill the disk with queues for bogus pids.

Counters (stored in the DB, monotonic): stored, delivered (acked),
evicted (cap), expired (ttl), oversize_refused, global_cap_refused.

Thread-safe: one re-entrant lock serializes all access.
"""
import os
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mailbox(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient  TEXT NOT NULL,
  sender     TEXT NOT NULL,
  kind       TEXT NOT NULL,
  ts         INTEGER NOT NULL,
  expiry     INTEGER NOT NULL,
  size       INTEGER NOT NULL,
  state      TEXT NOT NULL DEFAULT 'queued',
  frame      BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient
  ON mailbox(recipient, state, id);
CREATE TABLE IF NOT EXISTS mailbox_counters(
  name  TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);
"""

_COUNTERS = ("stored", "acked", "evicted", "expired",
             "oversize_refused", "global_cap_refused")


def _row(r):
    return dict(r) if r is not None else None


class Mailbox:
    def __init__(self, db_path, max_per_recipient=1000,
                 max_bytes_per_recipient=25 * 1024 * 1024,
                 default_ttl_s=7 * 86400, global_max_envelopes=100000):
        self.db_path = str(db_path)
        parent = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(parent, exist_ok=True)
        self.max_per_recipient = int(max_per_recipient)
        self.max_bytes_per_recipient = int(max_bytes_per_recipient)
        self.default_ttl_s = int(default_ttl_s)
        self.global_max_envelopes = int(global_max_envelopes)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            for name in _COUNTERS:
                self._db.execute(
                    "INSERT OR IGNORE INTO mailbox_counters(name, value)"
                    " VALUES (?, 0)", (name,))
            self._db.commit()

    def close(self):
        with self._lock:
            self._db.commit()
            self._db.close()

    # ------------------------------------------------------------ counters
    def _bump(self, name, delta=1):
        self._db.execute(
            "UPDATE mailbox_counters SET value = value + ? WHERE name=?",
            (delta, name))

    def counters(self):
        with self._lock:
            return {r["name"]: r["value"] for r in
                    self._db.execute("SELECT name, value FROM"
                                     " mailbox_counters").fetchall()}

    # --------------------------------------------------------------- store
    def store(self, recipient, sender, kind, frame: bytes, ts=None,
              ttl_s=None):
        """Store one envelope frame. Returns the mailbox id, or None if
        refused (oversize single frame / global cap). Evicts oldest
        frames first when the per-recipient caps would be exceeded."""
        if not isinstance(frame, (bytes, bytearray)) or not frame:
            raise ValueError("frame must be non-empty bytes")
        now = int(time.time())
        ts = now if ts is None else int(ts)
        ttl = self.default_ttl_s if ttl_s is None else int(ttl_s)
        size = len(frame)
        with self._lock:
            if size > self.max_bytes_per_recipient:
                self._bump("oversize_refused")
                self._db.commit()
                return None
            total = self._db.execute(
                "SELECT COUNT(*) AS n FROM mailbox").fetchone()["n"]
            if total >= self.global_max_envelopes:
                self._bump("global_cap_refused")
                self._db.commit()
                return None
            cur = self._db.execute(
                "INSERT INTO mailbox(recipient, sender, kind, ts, expiry,"
                " size, state, frame) VALUES (?,?,?,?,?,?, 'queued', ?)",
                (recipient, sender, kind, ts, ts + ttl, size,
                 bytes(frame)))
            mid = cur.lastrowid
            self._bump("stored")
            self._enforce_caps_locked(recipient)
            self._db.commit()
            return mid

    def _enforce_caps_locked(self, recipient):
        """Oldest-first eviction until both per-recipient caps hold."""
        while True:
            r = self._db.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b"
                " FROM mailbox WHERE recipient=?", (recipient,)).fetchone()
            if r["n"] <= self.max_per_recipient and \
               r["b"] <= self.max_bytes_per_recipient:
                return
            old = self._db.execute(
                "SELECT id FROM mailbox WHERE recipient=? ORDER BY id ASC"
                " LIMIT 1", (recipient,)).fetchone()
            if old is None:
                return
            self._db.execute("DELETE FROM mailbox WHERE id=?",
                             (old["id"],))
            self._bump("evicted")

    # --------------------------------------------------------------- drain
    def pending(self, recipient, now=None):
        """FIFO list of deliverable (non-expired) queued frames.

        Expired frames are dropped here and counted. Returns list of
        dicts with id/sender/kind/ts/expiry/size/frame.
        """
        now = int(time.time()) if now is None else now
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM mailbox WHERE recipient=? AND expiry <= ?"
                " RETURNING id", (recipient, now))
            expired = cur.fetchall()
            if expired:
                self._bump("expired", len(expired))
            rows = self._db.execute(
                "SELECT id, sender, kind, ts, expiry, size, frame"
                " FROM mailbox WHERE recipient=? AND state='queued'"
                " AND expiry > ? ORDER BY id ASC",
                (recipient, now)).fetchall()
            self._db.commit()
            return [_row(r) for r in rows]

    def mark_inflight(self, ids):
        with self._lock:
            for mid in ids:
                self._db.execute(
                    "UPDATE mailbox SET state='inflight' WHERE id=?", (mid,))
            self._db.commit()

    def reset_inflight(self, recipient):
        """Queued <- inflight: call on (re)connect so frames from a dead
        connection are retried instead of stuck."""
        with self._lock:
            self._db.execute(
                "UPDATE mailbox SET state='queued' WHERE recipient=?"
                " AND state='inflight'", (recipient,))
            self._db.commit()

    def ack(self, recipient, ids):
        """Delete frames the recipient confirmed. Only rows belonging to
        *recipient* are touched (a client cannot ack another pid's
        mail). Returns the number deleted."""
        ids = [int(i) for i in ids]
        if not ids:
            return 0
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM mailbox WHERE recipient=? AND id IN (%s)"
                % ",".join("?" * len(ids)), [recipient] + ids)
            n = cur.rowcount
            if n:
                self._bump("acked", n)
            self._db.commit()
            return n

    def delete_ids(self, ids):
        """Unconditional delete (used after custody transfer to a
        federated relay)."""
        ids = [int(i) for i in ids]
        if not ids:
            return 0
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM mailbox WHERE id IN (%s)"
                % ",".join("?" * len(ids)), ids)
            n = cur.rowcount
            self._db.commit()
            return n

    # ---------------------------------------------------------------- info
    def count(self, recipient):
        """-> (envelope_count, byte_count) for a recipient."""
        with self._lock:
            r = self._db.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b"
                " FROM mailbox WHERE recipient=?", (recipient,)).fetchone()
            return r["n"], r["b"]

    def prune_expired(self, now=None):
        """Drop all expired frames across recipients. Returns count."""
        now = int(time.time()) if now is None else now
        with self._lock:
            cur = self._db.execute("DELETE FROM mailbox WHERE expiry <= ?",
                                   (now,))
            n = cur.rowcount
            if n:
                self._bump("expired", n)
            self._db.commit()
            return n
