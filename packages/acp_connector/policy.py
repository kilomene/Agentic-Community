"""Policy engine: rate limits, file size caps, auto-accept policy.

Sensitive allow/deny decisions are audit-logged by the caller (or here
for rate limits). Config persists in the kv table so restarts keep it.
"""
import collections
import threading
import time

from acp_proto import AcpError

DEFAULT_RATE_PER_MIN = 60
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024
_WINDOW_S = 60.0


class PolicyEngine:
    def __init__(self, store, audit, rate_per_min=DEFAULT_RATE_PER_MIN,
                 max_file_bytes=DEFAULT_MAX_FILE_BYTES,
                 auto_accept_files=True):
        self._store = store
        self._audit = audit
        self._lock = threading.Lock()  # leaf lock: never held across calls
        self._hits = {}  # peer_id -> deque[timestamps]
        saved_rate = store.kv_get("policy.rate_per_min")
        saved_cap = store.kv_get("policy.max_file_bytes")
        saved_auto = store.kv_get("policy.auto_accept_files")
        self.rate_per_min = int(saved_rate) if saved_rate else rate_per_min
        self.max_file_bytes = int(saved_cap) if saved_cap else max_file_bytes
        # True/False, or {"peer_id": bool} for per-peer overrides.
        if saved_auto is not None:
            import json
            self.auto_accept_files = json.loads(saved_auto)
        else:
            self.auto_accept_files = auto_accept_files

    # ------------------------------------------------------------ configuration
    def set_rate_limit(self, per_min):
        with self._lock:
            self.rate_per_min = int(per_min)
        self._store.kv_set("policy.rate_per_min", str(per_min))

    def set_file_size_cap(self, max_bytes):
        with self._lock:
            self.max_file_bytes = int(max_bytes)
        self._store.kv_set("policy.max_file_bytes", str(max_bytes))

    def set_auto_accept_files(self, value):
        """bool, or dict {peer_id: bool} for per-peer overrides."""
        import json
        with self._lock:
            self.auto_accept_files = value
        self._store.kv_set("policy.auto_accept_files", json.dumps(value))

    # ---------------------------------------------------------------- checks
    def check_rate(self, peer_id):
        """Sliding-window rate limit. Raises AcpError(RATE_LIMITED)."""
        now = time.time()
        with self._lock:
            dq = self._hits.get(peer_id)
            if dq is None:
                dq = collections.deque()
                self._hits[peer_id] = dq
            while dq and dq[0] <= now - _WINDOW_S:
                dq.popleft()
            if len(dq) >= self.rate_per_min:
                raise AcpError("RATE_LIMITED",
                               f"{peer_id[:16]} exceeded"
                               f" {self.rate_per_min}/min")
            dq.append(now)

    def check_file_size(self, size):
        if size > self.max_file_bytes:
            raise AcpError("FILE_TOO_LARGE",
                           f"{size} bytes exceeds cap {self.max_file_bytes}")

    def auto_accept(self, peer_id):
        """Whether an inbound file offer from peer_id is auto-accepted."""
        with self._lock:
            v = self.auto_accept_files
        if isinstance(v, dict):
            return bool(v.get(peer_id, v.get("*", True)))
        return bool(v)
