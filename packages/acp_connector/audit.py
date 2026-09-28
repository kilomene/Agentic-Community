"""Append-only audit log.

Two sinks, one call: JSONL lines in ``home_dir/audit.log`` (the durable,
human-greppable record) and rows in the ``audit_logs`` table (queryable
via Connector.audit_log).

Locking: uses the store's single lock for everything (file + DB) so
there is exactly one lock ordering in the process and no inversion is
possible. Callers must never log private content (message text, file
bytes, codes); keep details to metadata.
"""
import json
import os
import time


class Audit:
    def __init__(self, home_dir, store):
        self.path = os.path.join(home_dir, "audit.log")
        self._store = store

    def log(self, event, actor="local", target=None, result="ok",
            details=None):
        ts = int(time.time())
        if details is None:
            details = {}
        try:
            details_json = json.dumps(details, sort_keys=True,
                                     separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            details_json = json.dumps({"unserializable": True})
        record = {
            "ts": ts,
            "event": event,
            "actor": actor,
            "target": target,
            "result": result,
            "details": details,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          default=str)
        # Single lock for file + DB: the store's lock (re-entrant).
        with self._store._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._store.add_audit(ts, actor, event, target, result,
                                  details_json)

    def tail(self, limit=200):
        """Newest-first audit entries from the DB."""
        return self._store.list_audit(limit=limit)
