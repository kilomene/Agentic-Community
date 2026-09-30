"""Shared fleet task board with dependencies (workstream E).

Head-side SQLite board tracking every task the head assigns in the fleet
room: who owns it, what state it is in, and what it is blocked on.

Database: ``~/.acp/state/fleet_board.db`` by default (``ACP_STATE_DIR``
env var overrides the state dir); pass an explicit path for tests.

Task states::

    open -> assigned -> acked -> in_progress -> done | failed
                                   \-> blocked -/        (waiting on deps)

``blocked`` is a waiting state, not a terminal one: a task enters it when
a dependency is added whose blocker is not ``done`` yet, and returns to
its pre-block state (``resume_state``) when every blocker is ``done``.
Terminal states are ``done`` and ``failed`` — nothing leaves them without
an explicit operator override (``set_state(..., force=True)``).

Readiness rule (documented choice): a blocker satisfies a dependency ONLY
when it is ``done``. A ``failed`` blocker NEVER auto-unblocks its
dependents — they stay ``blocked`` until the head intervenes: re-run the
blocker as a new task and re-point the dependency, ``remove_dependency``,
or an operator ``set_state(..., force=True)`` override. The board will
never silently unblock work on top of a failure.

Stdlib only.
"""

import datetime
import os
import sqlite3

STATES = ("open", "assigned", "acked", "in_progress",
          "done", "failed", "blocked")
TERMINAL = ("done", "failed")

_VALID_TRANSITIONS = {
    "open": {"assigned", "acked", "blocked", "done", "failed"},
    "assigned": {"acked", "in_progress", "blocked", "done", "failed"},
    "acked": {"in_progress", "blocked", "done", "failed"},
    "in_progress": {"blocked", "done", "failed"},
    "blocked": {"open", "assigned", "acked", "in_progress",
                "done", "failed"},
    "done": set(),
    "failed": set(),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    assignee     TEXT,
    state        TEXT NOT NULL DEFAULT 'open',
    due          TEXT,
    resume_state TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_deps (
    task_id    TEXT NOT NULL,
    blocker_id TEXT NOT NULL,
    PRIMARY KEY (task_id, blocker_id)
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee);
CREATE INDEX IF NOT EXISTS idx_deps_blocker ON task_deps(blocker_id);
"""


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def default_db_path():
    """Default board location: $ACP_STATE_DIR/fleet_board.db."""
    state_dir = os.environ.get("ACP_STATE_DIR",
                               os.path.expanduser("~/.acp/state"))
    return os.path.join(state_dir, "fleet_board.db")


class FleetBoard:
    """SQLite-backed fleet task board. One instance per db path."""

    def __init__(self, db_path=None):
        self.db_path = db_path or default_db_path()
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self):
        self._conn.close()

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    def _blocked_by(self, task_id):
        cur = self._conn.execute(
            "SELECT blocker_id FROM task_deps WHERE task_id=? "
            "ORDER BY blocker_id", (task_id,))
        return [r[0] for r in cur.fetchall()]

    def _dependents_of(self, blocker_id):
        cur = self._conn.execute(
            "SELECT task_id FROM task_deps WHERE blocker_id=? "
            "ORDER BY task_id", (blocker_id,))
        return [r[0] for r in cur.fetchall()]

    def _row_to_dict(self, row, dependents=False):
        d = {"id": row["id"],
             "title": row["title"],
             "assignee": row["assignee"],
             "state": row["state"],
             "due": row["due"],
             "resume_state": row["resume_state"],
             "created_at": row["created_at"],
             "updated_at": row["updated_at"],
             "blocked_by": self._blocked_by(row["id"])}
        if dependents:
            d["dependents"] = self._dependents_of(row["id"])
        return d

    def get(self, task_id):
        """Full task dict (with blocked_by and dependents), or None."""
        cur = self._conn.execute("SELECT * FROM tasks WHERE id=?",
                                 (task_id,))
        row = cur.fetchone()
        return self._row_to_dict(row, dependents=True) if row else None

    def list(self, state=None, assignee=None):
        """All tasks, optionally filtered; ordered by due then created."""
        if state is not None and state not in STATES:
            raise ValueError("bad state %r" % (state,))
        query = "SELECT * FROM tasks"
        clauses, params = [], []
        if state is not None:
            clauses.append("state=?")
            params.append(state)
        if assignee is not None:
            clauses.append("assignee=?")
            params.append(assignee)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY due IS NULL, due, created_at"
        cur = self._conn.execute(query, params)
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def dependents(self, blocker_id):
        """Task ids that list blocker_id as a dependency."""
        return self._dependents_of(blocker_id)

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------

    def create(self, task_id, title, assignee=None, due=None,
               state="open"):
        """Create a task. Raises ValueError on duplicate id / bad state."""
        if not task_id or not isinstance(task_id, str):
            raise ValueError("task_id must be a non-empty string")
        if not title:
            raise ValueError("title must be non-empty")
        if state not in STATES:
            raise ValueError("bad state %r" % (state,))
        if isinstance(due, datetime.datetime):
            due = due.isoformat()
        now = _utcnow()
        try:
            self._conn.execute(
                "INSERT INTO tasks (id, title, assignee, state, due, "
                "resume_state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                (task_id, title, assignee, state,
                 str(due) if due is not None else None, now, now))
        except sqlite3.IntegrityError:
            raise ValueError("task %r already exists" % (task_id,))
        self._conn.commit()
        return self.get(task_id)

    def assign(self, task_id, handle):
        """Set the assignee; open -> assigned. A blocked task stays
        blocked (assignment does not clear unmet dependencies)."""
        t = self.get(task_id)
        if t is None:
            raise ValueError("unknown task %r" % (task_id,))
        if t["state"] in TERMINAL:
            raise ValueError("task %r is %s; re-create it to reassign"
                             % (task_id, t["state"]))
        handle = (handle or "").strip().lstrip("@").lower() or None
        new_state = "assigned" if t["state"] == "open" else t["state"]
        self._conn.execute(
            "UPDATE tasks SET assignee=?, state=?, updated_at=? "
            "WHERE id=?", (handle, new_state, _utcnow(), task_id))
        self._conn.commit()
        return self.get(task_id)

    def set_state(self, task_id, state, force=False):
        """Set a task's state. Returns True only when the state actually
        changed (idempotent for repeated room scans). Raises ValueError
        on unknown task/state, on leaving a terminal state, or on an
        illegal transition — unless force=True (operator override)."""
        if state not in STATES:
            raise ValueError("bad state %r" % (state,))
        t = self.get(task_id)
        if t is None:
            raise ValueError("unknown task %r" % (task_id,))
        cur = t["state"]
        if cur == state:
            return False
        if not force:
            if cur in TERMINAL:
                raise ValueError("task %r is %s (terminal)"
                                 % (task_id, cur))
            if state not in _VALID_TRANSITIONS[cur]:
                raise ValueError("illegal transition %s -> %s"
                                 % (cur, state))
        resume = t["resume_state"]
        if state == "blocked" and cur != "blocked":
            resume = cur  # remember where to resume after unblock
        elif cur == "blocked":
            resume = None
        self._conn.execute(
            "UPDATE tasks SET state=?, resume_state=?, updated_at=? "
            "WHERE id=?", (state, resume, _utcnow(), task_id))
        self._conn.commit()
        return True

    def add_dependency(self, task_id, blocker_id):
        """Record that task_id is blocked by blocker_id. Returns True
        when newly added, False when already recorded. A task whose
        blocker is not done moves to ``blocked`` (resume state kept)."""
        if task_id == blocker_id:
            raise ValueError("a task cannot block itself")
        task = self.get(task_id)
        if task is None:
            raise ValueError("unknown task %r" % (task_id,))
        blocker = self.get(blocker_id)
        if blocker is None:
            raise ValueError("unknown blocker %r" % (blocker_id,))
        if task["state"] in TERMINAL:
            raise ValueError("task %r is %s; cannot add dependencies"
                             % (task_id, task["state"]))
        if self._would_cycle(task_id, blocker_id):
            raise ValueError("dependency %s -> %s would create a cycle"
                             % (task_id, blocker_id))
        exists = self._conn.execute(
            "SELECT 1 FROM task_deps WHERE task_id=? AND blocker_id=?",
            (task_id, blocker_id)).fetchone()
        if exists:
            return False
        self._conn.execute(
            "INSERT INTO task_deps (task_id, blocker_id) VALUES (?, ?)",
            (task_id, blocker_id))
        self._conn.commit()
        if blocker["state"] != "done" and task["state"] != "blocked":
            self.set_state(task_id, "blocked")
        return True

    def remove_dependency(self, task_id, blocker_id):
        """Drop a dependency (operator recovery path, e.g. after a
        blocker failed and the head decides to proceed anyway). Returns
        True when something was removed; the task is unblocked if its
        remaining blockers are all done."""
        cur = self._conn.execute(
            "DELETE FROM task_deps WHERE task_id=? AND blocker_id=?",
            (task_id, blocker_id))
        self._conn.commit()
        if cur.rowcount:
            self._unblock(task_id)
            return True
        return False

    def _would_cycle(self, task_id, blocker_id):
        """True if task_id is already a (transitive) blocker of
        blocker_id — adding task_id -> blocker_id would close a loop."""
        seen, stack = set(), [blocker_id]
        while stack:
            cur = stack.pop()
            if cur == task_id:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self._blocked_by(cur))
        return False

    # ------------------------------------------------------------------
    # readiness / unblocking
    # ------------------------------------------------------------------

    def unblock_check(self, task_id):
        """True when every blocker of the task is ``done``. A ``failed``
        blocker never counts as satisfied (documented choice)."""
        t = self.get(task_id)
        if t is None:
            raise ValueError("unknown task %r" % (task_id,))
        blockers = t["blocked_by"]
        if not blockers:
            return True
        cur = self._conn.execute(
            "SELECT id, state FROM tasks WHERE id IN (%s)"
            % ",".join("?" * len(blockers)), blockers)
        states = {r["id"]: r["state"] for r in cur.fetchall()}
        return all(states.get(b) == "done" for b in blockers)

    def _unblock(self, task_id):
        """Move a blocked task back to work if all blockers are done."""
        t = self.get(task_id)
        if t is None or t["state"] != "blocked":
            return False
        if not self.unblock_check(task_id):
            return False
        target = t["resume_state"]
        if (not target or target in TERMINAL or target == "blocked"
                or target not in STATES):
            target = "assigned" if t["assignee"] else "open"
        self.set_state(task_id, target, force=True)
        return True

    def on_blocker_done(self, blocker_id):
        """Call after a blocker reaches ``done``. Unblocks every
        dependent whose blockers are now all done and returns the newly
        unblocked task dicts (the caller notifies their assignees)."""
        unblocked = []
        for dep_id in self._dependents_of(blocker_id):
            if self._unblock(dep_id):
                unblocked.append(self.get(dep_id))
        return unblocked

    def ready_tasks(self, assignee=None):
        """Tasks that can be worked now: not terminal, and every blocker
        is done. Tasks with no blockers are trivially ready. A dependent
        of a failed blocker is never ready (documented choice)."""
        ready = []
        for t in self.list(assignee=assignee):
            if t["state"] in TERMINAL:
                continue
            if not self.unblock_check(t["id"]):
                continue
            ready.append(t)
        return ready
