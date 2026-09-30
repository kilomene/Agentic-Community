"""Work ledger — append-only diligence record for fleet task lifecycle.

Every task the head assigns to a fleet agent moves through a
lifecycle: assigned -> acked -> in_progress -> done | failed (or
blocked at any point). This module records one row per observed
transition in a SQLite database and answers the diligence questions
the office dashboard needs:

- what happened to task <id>?
- what has @handle been doing? how fast do they ack? complete?
- how many tasks completed / failed per agent?

The ledger is append-only: the public API offers insert
(:meth:`WorkLedger.record_event`) and queries. There is no
update/delete API; the explicit :meth:`WorkLedger.update` /
:meth:`WorkLedger.delete` stubs raise :exc:`TypeError`.

Storage: a SQLite database, stdlib only. Default location is
``~/.acp/state/work_ledger.db``. Tests pass an explicit path
(usually a temp file) and must never touch the live state dir.

Event types: ``assigned``, ``acked``, ``in_progress``, ``done``,
``failed``, ``blocked``. ``in_progress`` and ``blocked`` have no
fleet-block wire kind today (blocks only carry task_assign /
task_ack / task_done / task_failed); they are recorded
programmatically via :meth:`WorkLedger.record_event` when the
head learns about them through other channels.
"""

import os
import sqlite3
import time

VALID_EVENTS = ("assigned", "acked", "in_progress",
                "done", "failed", "blocked")

SCHEMA = """
CREATE TABLE IF NOT EXISTS work_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id   TEXT NOT NULL,
    agent     TEXT NOT NULL,
    event     TEXT NOT NULL,
    ts        REAL NOT NULL,
    detail    TEXT,
    dedupe_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_work_events_task
    ON work_events (task_id, id);
CREATE INDEX IF NOT EXISTS idx_work_events_agent
    ON work_events (agent, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_work_events_dedupe
    ON work_events (dedupe_key);
"""


def default_db_path():
    """Default ledger database path: ~/.acp/state/work_ledger.db."""
    return os.path.expanduser(os.path.join("~", ".acp", "state",
                                           "work_ledger.db"))


class WorkLedger:
    """Append-only task lifecycle ledger backed by SQLite."""

    def __init__(self, path=None):
        self.path = path or default_db_path()
        if self.path != ":memory:":
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self):
        self._conn.close()

    # -- append-only enforcement -------------------------------------
    def update(self, *args, **kwargs):
        raise TypeError("work ledger is append-only: updates are not "
                        "supported")

    def delete(self, *args, **kwargs):
        raise TypeError("work ledger is append-only: deletes are not "
                        "supported")

    # -- writes -------------------------------------------------------
    def record_event(self, task_id, agent, event, detail=None,
                     ts=None, dedupe_key=None):
        """Append one lifecycle event. Returns the row id, or None when
        ``dedupe_key`` names an event already recorded (the insert is
        skipped, keeping repeated room scans from duplicating rows)."""
        if event not in VALID_EVENTS:
            raise ValueError("unknown event %r (valid: %s)"
                             % (event, ", ".join(VALID_EVENTS)))
        task_id = str(task_id)
        agent = str(agent).lstrip("@").lower()
        row_ts = float(ts) if ts is not None else time.time()
        if dedupe_key is not None:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO work_events"
                " (task_id, agent, event, ts, detail, dedupe_key)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, agent, event, row_ts, detail, dedupe_key))
            self._conn.commit()
            return cur.lastrowid if cur.rowcount else None
        cur = self._conn.execute(
            "INSERT INTO work_events (task_id, agent, event, ts, detail)"
            " VALUES (?, ?, ?, ?, ?)",
            (task_id, agent, event, row_ts, detail))
        self._conn.commit()
        return cur.lastrowid

    # -- queries ------------------------------------------------------
    def events_for_task(self, task_id):
        """All events for a task, oldest first."""
        cur = self._conn.execute(
            "SELECT task_id, agent, event, ts, detail FROM work_events"
            " WHERE task_id = ? ORDER BY id ASC", (str(task_id),))
        return [dict(r) for r in cur.fetchall()]

    def events_for_agent(self, agent):
        """All events for an agent handle, oldest first."""
        cur = self._conn.execute(
            "SELECT task_id, agent, event, ts, detail FROM work_events"
            " WHERE agent = ? ORDER BY id ASC",
            (str(agent).lstrip("@").lower(),))
        return [dict(r) for r in cur.fetchall()]

    def _first_ts(self, task_id, agent, event):
        cur = self._conn.execute(
            "SELECT MIN(ts) FROM work_events"
            " WHERE task_id = ? AND agent = ? AND event = ?",
            (str(task_id), str(agent).lstrip("@").lower(), event))
        return cur.fetchone()[0]

    def summary_for_agent(self, agent):
        """Per-agent diligence summary::

            {"agent": ...,
             "counts": {"assigned": n, "acked": n, ...},
             "tasks_completed": n, "tasks_failed": n,
             "avg_ack_latency_s": float|None,
             "avg_completion_time_s": float|None}

        ``avg_ack_latency_s`` averages (first acked - first assigned)
        over tasks that have both. ``avg_completion_time_s``
        averages (first done - first acked, or first assigned when no
        ack) over completed tasks. Tasks with a single event never
        contribute a latency.
        """
        handle = str(agent).lstrip("@").lower()
        cur = self._conn.execute(
            "SELECT event, COUNT(*) FROM work_events"
            " WHERE agent = ? GROUP BY event", (handle,))
        counts = {e: 0 for e in VALID_EVENTS}
        for event, n in cur.fetchall():
            counts[event] = n
        cur = self._conn.execute(
            "SELECT DISTINCT task_id FROM work_events WHERE agent = ?",
            (handle,))
        task_ids = [r[0] for r in cur.fetchall()]
        completed = failed = 0
        ack_latencies = []
        completion_times = []
        for tid in task_ids:
            assigned = self._first_ts(tid, handle, "assigned")
            acked = self._first_ts(tid, handle, "acked")
            done = self._first_ts(tid, handle, "done")
            if done is not None:
                completed += 1
            if self._first_ts(tid, handle, "failed") is not None:
                failed += 1
            if assigned is not None and acked is not None:
                ack_latencies.append(acked - assigned)
            if done is not None:
                base = acked if acked is not None else assigned
                if base is not None:
                    completion_times.append(done - base)
        return {
            "agent": handle,
            "counts": counts,
            "tasks_completed": completed,
            "tasks_failed": failed,
            "avg_ack_latency_s": (
                sum(ack_latencies) / len(ack_latencies)
                if ack_latencies else None),
            "avg_completion_time_s": (
                sum(completion_times) / len(completion_times)
                if completion_times else None),
        }
