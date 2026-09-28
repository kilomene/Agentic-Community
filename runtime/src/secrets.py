"""Phase 60: secret isolation.

A dedicated secret-management boundary:

  - secrets never appear in task state, event journal, logs, model context,
    error messages, browser screenshots, or debug output
  - secrets are exposed to tools only when required, at execution time
  - tool output is redacted before it reaches logs or the model
  - accidental credential exposure is detected and journaled (loudly)

Design: secrets live in an in-memory vault (never persisted to SQLite or
the journal). Task steps reference them via {"vault": "<name>"} refs,
which the agent resolves at execution time to raw values, hands to the
executor, and redacts (by value) from every journaled record.

Canonical store: the module-level `_VAULT` dict behind `vault_set` /
`vault_get` / `vault_drop` (scoped leases per task); `redact_text`
consults it so stored secrets never leak into redacted output.
"""
import os
import re

# Patterns that look like leaked credentials in free text.
EXPOSURE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),                       # openai-style
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),               # slack-style
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),                       # github pat
    re.compile(r"AKIA[0-9A-Z]{16}"),                           # aws key id
    re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*['\"]?([^\s'\"]{8,})"),
    re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{16,}={0,2}"),
]


def redact_values(text, values):
    """Redact a caller-supplied list of raw secret values from free text.

    Used when the runtime knows exactly which values were substituted for
    this step (e.g. resolved {"vault": ...} refs) — value-based redaction
    catches secrets regardless of the argument NAME they traveled under
    ("content", "command", ...), which name-based redaction misses.
    """
    if not text:
        return text
    out = str(text)
    for val in values or []:
        v = str(val) if val is not None else ""
        if v and len(v) >= 4:
            out = out.replace(v, "***REDACTED***")
    return out


def redact_text(text):
    """Redact known secret values and anything matching exposure patterns.

    The module-level vault (populated by vault_set, the canonical store
    the agent and CLI use) is always consulted: a secret stored via
    vault_set must be redacted even when the caller passes no explicit
    values. Values are snapshotted first — the vault can be mutated
    from another thread (vault_set / vault_drop) while redacting.
    """
    if not text:
        return text
    out = str(text)
    values = [rec.get("value") for rec in list(_VAULT.values())]
    for val in values:
        if val and len(val) >= 4:
            out = out.replace(val, "***REDACTED***")
    for pat in EXPOSURE_PATTERNS:
        out = pat.sub("***REDACTED***", out)
    return out


def scan_for_exposure(text, context=""):
    """Detect accidental credential exposure. Returns list of findings."""
    findings = []
    for pat in EXPOSURE_PATTERNS:
        for m in pat.finditer(str(text or "")):
            findings.append({"pattern": pat.pattern[:40],
                             "context": context,
                             "sample": m.group(0)[:24] + "..."})
    return findings


def scan_journal(journal_dir, days=1):
    """Phase 60: exposure detection — scan recent journal lines for
    secret-shaped values. Returns list of 'file:line: pattern' hits.
    Call this from diagnostics; investigate every hit."""
    import glob
    import time
    cutoff = time.time() - days * 86400
    hits = []
    for path in sorted(glob.glob(os.path.join(journal_dir, "*.jsonl"))):
        try:
            if os.path.getmtime(path) < cutoff - 86400:
                continue
        except OSError:
            continue
        try:
            with open(path) as f:
                for lineno, line in enumerate(f, 1):
                    if scan_for_exposure(line):
                        hits.append(f"{os.path.basename(path)}:{lineno}")
        except OSError:
            continue
    return hits


# ---- Phase 60: scoped, time-limited secret leases (process-local) ----
# Values live ONLY in this dict: never in SQLite, never in the journal,
# never in checkpoints. They die with the process. A task receives a
# secret only if it is the owner (or the secret is global "*"), and only
# while its lease has not expired.
import time as _time

_VAULT = {}  # name -> {"value", "owner", "expires"}


def vault_set(store, name, value, owner="*", ttl_s=None):
    """Store a secret with an owner scope and optional lease (seconds).
    Only the name is journaled — never the value."""
    expires = (_time.time() + ttl_s) if ttl_s is not None else None
    _VAULT[name] = {"value": value, "owner": owner, "expires": expires}
    try:
        store.journal("SECRET_STORED", name=name, owner=owner,
                      ttl_s=ttl_s)
    except Exception:  # noqa: BLE001 - journaling must not break vault use
        pass
    return True


def vault_get(store, task_id, name):
    """Retrieve a secret if the task is authorized and the lease is valid.
    Returns None otherwise (unknown, wrong owner, or expired)."""
    rec = _VAULT.get(name)
    if not rec:
        return None
    if rec["owner"] not in ("*", task_id):
        return None
    if rec["expires"] is not None and _time.time() >= rec["expires"]:
        _VAULT.pop(name, None)
        return None
    return rec["value"]


def vault_drop(store, name, task_id):
    """Revoke a secret (owner or global scope only)."""
    rec = _VAULT.get(name)
    if rec and rec["owner"] in ("*", task_id):
        _VAULT.pop(name, None)
        try:
            store.journal("SECRET_REVOKED", name=name)
        except Exception:  # noqa: BLE001
            pass
        return True
    return False
