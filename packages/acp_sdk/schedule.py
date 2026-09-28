"""Tiny scheduler for the SDK: every/at jobs on background threads.

Stdlib only (threading + time). Jobs are plain callables; exceptions
are swallowed and logged to stderr so one bad job can't kill the loop.
"""
import threading
import time
import traceback


class JobHandle:
    """Returned by :meth:`Scheduler.every` / :meth:`Scheduler.at`."""

    def __init__(self, scheduler, job_id):
        self._scheduler = scheduler
        self.job_id = job_id

    def cancel(self):
        """Stop the job (pending ``at`` jobs are dropped; ``every`` jobs
        stop after their current run)."""
        self._scheduler._cancel(self.job_id)

    def __repr__(self):
        return "JobHandle(%r)" % (self.job_id,)


class Scheduler:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}  # job_id -> dict
        self._seq = 0
        self._stopped = False

    def every(self, interval_seconds, fn, *args, **kwargs):
        """Run ``fn(*args, **kwargs)`` every ``interval_seconds`` seconds,
        first run after one interval. Returns a JobHandle."""
        interval = float(interval_seconds)
        if interval <= 0:
            raise ValueError("interval_seconds must be positive")
        return self._add({"kind": "every", "interval": interval,
                          "next": time.time() + interval,
                          "fn": fn, "args": args, "kwargs": kwargs})

    def at(self, when, fn, *args, **kwargs):
        """Run ``fn(*args, **kwargs)`` once at unix timestamp ``when``.
        If ``when`` is in the past, the job runs as soon as possible."""
        return self._add({"kind": "at", "next": float(when),
                          "fn": fn, "args": args, "kwargs": kwargs})

    def _add(self, job):
        with self._lock:
            if self._stopped:
                raise RuntimeError("scheduler is stopped")
            self._seq += 1
            job_id = "job-%d" % self._seq
            job["id"] = job_id
            self._jobs[job_id] = job
            if len(self._jobs) == 1:
                t = threading.Thread(target=self._loop, daemon=True,
                                     name="acp-sdk-scheduler")
                t.start()
        return JobHandle(self, job_id)

    def _cancel(self, job_id):
        with self._lock:
            self._jobs.pop(job_id, None)

    def stop(self):
        """Cancel all jobs and stop the loop thread. Idempotent."""
        with self._lock:
            self._stopped = True
            self._jobs.clear()

    def pending(self):
        """Number of scheduled jobs (for tests/diagnostics)."""
        with self._lock:
            return len(self._jobs)

    # ------------------------------------------------------------------ loop
    def _loop(self):
        while True:
            with self._lock:
                if self._stopped:
                    return
                now = time.time()
                due = [j for j in self._jobs.values() if j["next"] <= now]
                for j in due:
                    if j["kind"] == "at":
                        del self._jobs[j["id"]]
                    else:
                        # skip missed intervals instead of bursting
                        while j["next"] <= now:
                            j["next"] += j["interval"]
                sleep_for = min((j["next"] - now for j in self._jobs.values()),
                                default=None)
            for j in due:
                self._run(j)
            if sleep_for is None:
                return  # no jobs left; a new job restarts the loop
            time.sleep(max(0.05, min(sleep_for, 1.0)))

    def _run(self, job):
        try:
            job["fn"](*job["args"], **job["kwargs"])
        except Exception:
            traceback.print_exc()
