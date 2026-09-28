"""Local, privacy-respecting usage analytics for acp_connector.

Counts only — this module records aggregate counters in the connector's
own SQLite database (table ``metric_counters``), bucketed by UTC day.
Message text, file names, peer identities beyond counts, and any other
content are NEVER recorded here.

Tracked metrics:
  messages_sent / messages_received   number of envelopes
  bytes_sent / bytes_received         payload bytes moved
  files_completed                     finished file transfers
  pairings                            completed pairings
  calls_placed                        outbound calls placed
  uptime_days                         1 per day the connector heartbeats

Wiring (one line, done by the operator / final pass — the Connector
class itself is untouched, import lazily):

    from acp_connector.analytics import Analytics
    connector.analytics = Analytics(connector)

The interesting hooks (messaging.send_message, files.handle_done,
pairing completion, ...) call e.g. ``connector.analytics.message_sent(n)``
when the attribute exists.

Opt-in directory reporting: ``analytics.report(...)`` POSTs the day's
counters to the acp_api server (sig-auth, counts only).  Nothing leaves
the machine unless the operator calls it.

See docs/ANALYTICS.md for the privacy model.
"""
import datetime
import json
import sqlite3
import threading
import time
import urllib.request

METRICS = (
    "messages_sent", "messages_received",
    "bytes_sent", "bytes_received",
    "files_completed", "pairings", "calls_placed", "uptime_days",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS metric_counters(
  name  TEXT NOT NULL,
  day   TEXT NOT NULL,
  value INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(name, day)
);
"""


def _utc_day(ts=None):
    if ts is None:
        ts = time.time()
    return datetime.datetime.fromtimestamp(
        ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d")


class Analytics:
    """Day-bucketed counters living in the connector's SQLite database."""

    def __init__(self, connector):
        self._connector = connector
        self._path = connector.store.path
        self._lock = threading.RLock()
        with self._lock:
            conn = sqlite3.connect(self._path, timeout=10)
            try:
                conn.execute("PRAGMA busy_timeout=10000")
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------ internals
    def _conn(self):
        conn = sqlite3.connect(self._path, timeout=10)
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    # ------------------------------------------------------------- recording
    def record(self, name, n=1, day=None):
        """Increment counter ``name`` by ``n`` for ``day`` (UTC)."""
        if name not in METRICS:
            raise ValueError("unknown metric: %r" % (name,))
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValueError("n must be a non-negative int")
        day = day or _utc_day()
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT INTO metric_counters(name, day, value)"
                    " VALUES (?,?,?)"
                    " ON CONFLICT(name, day) DO UPDATE"
                    " SET value = value + excluded.value",
                    (name, day, n))
                conn.commit()
            finally:
                conn.close()

    def message_sent(self, nbytes=0):
        self.record("messages_sent", 1)
        if nbytes:
            self.record("bytes_sent", int(nbytes))

    def message_received(self, nbytes=0):
        self.record("messages_received", 1)
        if nbytes:
            self.record("bytes_received", int(nbytes))

    def file_completed(self):
        self.record("files_completed", 1)

    def pairing_completed(self):
        self.record("pairings", 1)

    def call_placed(self):
        self.record("calls_placed", 1)

    def heartbeat(self):
        """Mark the connector alive today. Idempotent: one uptime_day
        per day no matter how often it is called."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO metric_counters(name, day, value)"
                    " VALUES ('uptime_days', ?, 1)", (_utc_day(),))
                conn.commit()
            finally:
                conn.close()

    # --------------------------------------------------------------- reading
    def get(self, name, days=30):
        """Total for ``name`` over the last ``days`` days (incl. today)."""
        if name not in METRICS:
            raise ValueError("unknown metric: %r" % (name,))
        cutoff = _utc_day(time.time() - (days - 1) * 86400)
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT COALESCE(SUM(value),0) FROM metric_counters"
                    " WHERE name=? AND day >= ?",
                    (name, cutoff)).fetchone()
                return int(row[0])
            finally:
                conn.close()

    def summary(self, days=30):
        """Local API: aggregate counters for the last ``days`` days.

        Returns {"days", "from_day", "to_day", "counters": {name: total}}.
        Counts only — no content ever appears here.
        """
        if not isinstance(days, int) or isinstance(days, bool) \
                or not 1 <= days <= 365:
            raise ValueError("days must be 1..365")
        cutoff = _utc_day(time.time() - (days - 1) * 86400)
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT name, SUM(value) FROM metric_counters"
                    " WHERE day >= ? GROUP BY name", (cutoff,)).fetchall()
            finally:
                conn.close()
        counters = {name: 0 for name in METRICS}
        for name, total in rows:
            counters[name] = int(total)
        return {"days": days, "from_day": cutoff,
                "to_day": _utc_day(), "counters": counters}

    def daily(self, name, days=30):
        """Per-day series for one metric: [(day, value), ...] ascending."""
        if name not in METRICS:
            raise ValueError("unknown metric: %r" % (name,))
        cutoff = _utc_day(time.time() - (days - 1) * 86400)
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT day, value FROM metric_counters"
                    " WHERE name=? AND day >= ? ORDER BY day ASC",
                    (name, cutoff)).fetchall()
            finally:
                conn.close()
        return [(r[0], int(r[1])) for r in rows]

    def reset(self, name=None, day=None):
        """Operator tool: clear counters (all, one metric, or one day)."""
        with self._lock:
            conn = self._conn()
            try:
                if name is None:
                    conn.execute("DELETE FROM metric_counters")
                elif day is None:
                    conn.execute("DELETE FROM metric_counters WHERE name=?",
                                 (name,))
                else:
                    conn.execute(
                        "DELETE FROM metric_counters WHERE name=? AND day=?",
                        (name, day))
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------ opt-in reporting
    def report(self, base_url, handle, sign_priv, day=None, timeout=10,
               api_key=None):
        """Opt-in: POST today's counters to the acp_api directory.

        Sig-auth over canonical({handle, day, counters, ts}) with the
        connector identity key, plus the operator's API key (the
        analytics:write scope) as a Bearer token.  Only aggregate
        counts leave the machine — never message or file content.
        Returns the server's response dict.
        """
        from acp_crypto import ed25519_sign
        from acp_proto import b62encode, canonical

        day = day or _utc_day()
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT name, value FROM metric_counters WHERE day=?",
                    (day,)).fetchall()
            finally:
                conn.close()
        counters = {r[0]: int(r[1]) for r in rows}
        ts = int(time.time())
        msg = canonical({"handle": handle, "day": day,
                         "counters": counters, "ts": ts})
        body = {"handle": handle, "day": day, "counters": counters,
                "ts": ts, "sig": b62encode(ed25519_sign(sign_priv, msg))}
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = "Bearer " + api_key
        req = urllib.request.Request(
            base_url.rstrip("/") + "/v1/analytics/report", data=data,
            headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
