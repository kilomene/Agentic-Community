"""Cron-like scheduled tasks inside the connector (stdlib only).

A Scheduler lets an agent (or the local operator) arrange for
connector-level operations to run at a future time or on a recurrence:
``send_message``, ``send_file``, ``set_presence`` (built in), plus any
custom Python callbacks the embedding app registers via
``register_action``.

What actions CANNOT be: arbitrary shell commands. This is deliberate.
The connector is a network-reachable agent runtime whose scheduled
tasks persist in SQLite and re-arm across restarts; an action that
spawned subprocesses would turn the connector into a remote-execution
primitive — any party able to schedule a task (or any bug that let one
be created) would gain remote code execution. The closed action
allowlist keeps scheduling inside the messaging/presence domain. If an
app needs side effects beyond that, it registers a Python callback:
code the operator wrote and reviewed, never a string from the network.

Persistence: tasks live in the ``scheduled_tasks`` table (see
store.py). The scheduler loads and re-arms pending tasks on
Connector start, so tasks survive restarts. Custom actions are code,
not data: re-register them on every boot before their tasks are due.

Execution model: one background thread, tasks fire sequentially in
due order. Long-running actions delay later tasks — keep actions
quick. Every execution is written to the audit log
(``scheduler.task_fired``) and fanned out to result callbacks
(``on_result``).

Misfire policy (what happens when the connector was down or busy when
a task came due):
  * once: fires if it is at most MISFIRE_GRACE_S (300 s) late;
    otherwise it is marked ``misfire_skipped`` and disabled. A once
    task whose action raises is retried after RETRY_S (60 s), up to
    MAX_ATTEMPTS (5), then disabled as ``gave_up``.
  * every: never catches up — missed occurrences are skipped and the
    next run is scheduled ``interval`` seconds after the run that did
    happen (no catch-up storms after downtime).
  * daily: always the next future occurrence of hh:mm local time;
    missed days are skipped, never replayed.

Thread-safe: every public method serializes on one re-entrant lock;
schedule/cancel/list may be called from any thread.
"""
import json
import re
import threading
import time
import uuid

from acp_proto import AcpError

MISFIRE_GRACE_S = 300   # once tasks this late are skipped, not fired
RETRY_S = 60            # failed once tasks wait this long before retry
MAX_ATTEMPTS = 5        # failed once tasks give up after this many tries

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")

BUILTIN_ACTIONS = ("send_message", "send_file", "set_presence")


def _next_daily_occurrence(hh_mm, now=None):
    """Next future unix ts for a local-time "HH:MM"."""
    now = time.time() if now is None else now
    m = _HHMM_RE.match(hh_mm)
    hh, mm = int(m.group(1)), int(m.group(2))
    lt = time.localtime(now)
    cand = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                        hh, mm, 0, 0, 0, -1))
    if cand <= now:
        nxt = time.localtime(now + 86400)
        cand = time.mktime((nxt.tm_year, nxt.tm_mon, nxt.tm_mday,
                            hh, mm, 0, 0, 0, -1))
    return int(cand)


class Scheduler:
    def __init__(self, connector):
        self._c = connector
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._custom = {}       # name -> callable
        self._result_cbs = []   # fn(task_id, action, ok, detail)
        self._running = False
        self._thread = None

    # ------------------------------------------------------------ actions
    def register_action(self, name, fn):
        """Register a custom action callable. fn(*args) -> result.

        Names must match ^[a-z][a-z0-9_]{1,40}$ and may not shadow a
        builtin. Re-register on every boot: actions are code, and only
        persisted task rows survive restarts.
        """
        if not isinstance(name, str) or not _ACTION_RE.match(name):
            raise AcpError("INTERNAL", "bad action name: %r" % (name,))
        if name in BUILTIN_ACTIONS:
            raise AcpError("INTERNAL",
                           "cannot shadow builtin action %r" % name)
        if not callable(fn):
            raise AcpError("INTERNAL", "action must be callable")
        with self._lock:
            self._custom[name] = fn

    def on_result(self, cb):
        """cb(task_id, action, ok, detail) after every execution."""
        with self._lock:
            self._result_cbs.append(cb)

    def _resolve(self, action):
        if action == "send_message":
            return self._c.send_message
        if action == "send_file":
            return self._c.send_file
        if action == "set_presence":
            return self._c.set_presence
        with self._lock:
            return self._custom.get(action)

    # ---------------------------------------------------------- scheduling
    def _check_action(self, action):
        if action in BUILTIN_ACTIONS:
            return
        with self._lock:
            known = action in self._custom
        if not known:
            raise AcpError("INTERNAL", "unknown action: %r" % (action,))

    def _add(self, kind, action, args, sched, next_run):
        self._check_action(action)
        try:
            args_json = json.dumps(list(args), separators=(",", ":"))
        except (TypeError, ValueError):
            raise AcpError("INTERNAL", "args must be JSON-serializable")
        task_id = uuid.uuid4().hex
        now = int(time.time())
        self._c.store.sched_add(task_id, kind, action, args_json,
                                json.dumps(sched, separators=(",", ":")),
                                int(next_run), now)
        with self._cond:
            self._cond.notify()
        self._c.audit.log("scheduler.scheduled", target=task_id,
                          result="ok",
                          details={"kind": kind, "action": action,
                                   "next_run": int(next_run)})
        return task_id

    def schedule_once(self, at_ts, action, args):
        """Run once at unix ts ``at_ts``."""
        at_ts = float(at_ts)
        if at_ts <= 0:
            raise AcpError("INTERNAL", "at_ts must be positive")
        return self._add("once", action, args, {"at": at_ts}, at_ts)

    def schedule_every(self, interval_s, action, args):
        """Run every ``interval_s`` seconds, first run one interval out."""
        interval_s = float(interval_s)
        if interval_s <= 0:
            raise AcpError("INTERNAL", "interval_s must be positive")
        return self._add("every", action, args, {"interval": interval_s},
                         time.time() + interval_s)

    def schedule_daily(self, hh_mm, action, args):
        """Run daily at local time ``hh_mm`` ("HH:MM", 24 h)."""
        if not isinstance(hh_mm, str) or not _HHMM_RE.match(hh_mm):
            raise AcpError("INTERNAL",
                           'hh_mm must be "HH:MM" (24h), got %r'
                           % (hh_mm,))
        return self._add("daily", action, args, {"hh_mm": hh_mm},
                         _next_daily_occurrence(hh_mm))

    def cancel(self, task_id):
        """Cancel a task. Returns True if it existed."""
        with self._cond:
            gone = self._c.store.sched_delete(task_id)
            self._cond.notify()
        if gone:
            self._c.audit.log("scheduler.cancelled", target=task_id,
                              result="ok", details={})
        return gone

    def list_tasks(self):
        """Pending + finished tasks, newest-due first-ish (by next_run)."""
        out = []
        for t in self._c.store.sched_list():
            try:
                args = json.loads(t["args_json"])
            except (ValueError, TypeError):
                args = []
            out.append({
                "task_id": t["task_id"],
                "kind": t["kind"],
                "action": t["action"],
                "args": args,
                "next_run": t["next_run"],
                "enabled": bool(t["enabled"]),
                "created_at": t["created_at"],
                "last_run": t["last_run"],
                "last_result": t["last_result"],
                "run_count": t["run_count"],
            })
        return out

    # ------------------------------------------------------------ lifecycle
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="acp-scheduler")
            self._thread.start()

    def stop(self):
        with self._cond:
            self._running = False
            self._cond.notify()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -------------------------------------------------------------- worker
    def _run(self):
        while True:
            with self._cond:
                if not self._running:
                    break
                now = time.time()
                due = self._claim_due_locked(now)
                if not due:
                    nxt = self._next_wakeup_locked()
                    wait_s = 60.0 if nxt is None else max(
                        0.1, min(60.0, nxt - time.time()))
                    self._cond.wait(timeout=wait_s)
                    continue
            for task in due:
                if not self._running:
                    break
                self._fire(task)

    def _claim_due_locked(self, now):
        """Mark due tasks as claimed so they fire exactly once.

        once: disabled up front (re-armed on failure); every/daily:
        next_run advanced up front (no catch-up, no double fire).
        """
        due = []
        for t in self._c.store.sched_list():
            if not t["enabled"] or t["next_run"] > now:
                continue
            kind = t["kind"]
            if kind == "once":
                if now - t["next_run"] > MISFIRE_GRACE_S:
                    self._c.store.sched_update(
                        t["task_id"], enabled=0,
                        last_run=int(now), last_result="misfire_skipped")
                    self._c.audit.log(
                        "scheduler.misfire", target=t["task_id"],
                        result="ok",
                        details={"action": t["action"],
                                 "late_by": int(now - t["next_run"])})
                    continue
                self._c.store.sched_update(t["task_id"], enabled=0,
                                           last_run=int(now))
                due.append(t)
            elif kind == "every":
                sched = json.loads(t["sched_json"])
                self._c.store.sched_update(
                    t["task_id"], next_run=int(now + sched["interval"]),
                    last_run=int(now))
                due.append(t)
            elif kind == "daily":
                sched = json.loads(t["sched_json"])
                self._c.store.sched_update(
                    t["task_id"],
                    next_run=_next_daily_occurrence(sched["hh_mm"],
                                                   now + 1),
                    last_run=int(now))
                due.append(t)
        return due

    def _next_wakeup_locked(self):
        nxt = None
        for t in self._c.store.sched_list():
            if t["enabled"] and (nxt is None or t["next_run"] < nxt):
                nxt = t["next_run"]
        return nxt

    def _fire(self, task):
        task_id = task["task_id"]
        action = task["action"]
        fn = self._resolve(action)
        if fn is None:
            self._finish(task, False, "unknown_action: %r" % (action,))
            return
        try:
            args = json.loads(task["args_json"])
        except (ValueError, TypeError):
            self._finish(task, False, "unserializable args")
            return
        try:
            result = fn(*args)
        except Exception as e:
            self._finish(task, False, "%s: %s" % (type(e).__name__, e))
        else:
            self._finish(task, True, result)

    def _finish(self, task, ok, detail):
        task_id = task["task_id"]
        now = int(time.time())
        kind = task["kind"]
        if kind == "once":
            if ok:
                self._c.store.sched_update(
                    task_id, last_result="ok",
                    run_count=task["run_count"] + 1)
            else:
                attempts = task["run_count"] + 1
                if attempts >= MAX_ATTEMPTS:
                    self._c.store.sched_update(
                        task_id, last_result="gave_up: %s" % (detail,),
                        run_count=attempts)
                else:
                    # re-arm for a retry (claim disabled it already)
                    self._c.store.sched_update(
                        task_id, enabled=1,
                        next_run=now + RETRY_S,
                        last_result="failed(%d/%d): %s"
                                    % (attempts, MAX_ATTEMPTS, detail),
                        run_count=attempts)
        else:
            self._c.store.sched_update(
                task_id,
                last_result=("ok" if ok
                             else "failed: %s" % (detail,)),
                run_count=task["run_count"] + 1)
        self._c.audit.log("scheduler.task_fired", target=task_id,
                          result="ok" if ok else "failed",
                          details={"action": task["action"], "kind": kind,
                                   "detail": str(detail)[:200]})
        with self._lock:
            cbs = list(self._result_cbs)
        for cb in cbs:
            try:
                cb(task_id, task["action"], ok, detail)
            except Exception:
                pass
        with self._cond:
            self._cond.notify()
