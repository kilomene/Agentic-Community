"""Wake-on-task — wake webhooks for suspended fleet agents (workstream C).

When the head assigns a task to an agent whose presence is STALE
(``last_seen`` older than a threshold) AND that agent's roster entry
carries a ``wake`` config, the head fires the agent's wake webhook
before queueing the task. The wake webhook is a last-mile nudge — the
agent's platform (sandbox, host, CI runner...) decides what "wake" means
and resumes the agent; when the agent boots, the relay mailbox drains
the queued task to it automatically (see docs/WAKE_ON_TASK.md).

Secrets rule: the secret ITSELF is never in the roster file. The roster
holds only a ``secret_ref`` — a name the caller's ``secret_resolver``
maps to the real value (the Secure Vault in production, a stub in
tests). ``fire_wake`` never logs or returns the secret.

Wake channels. A roster ``wake`` block names a ``channel``:

- ``webhook`` (default) — POST the task payload to ``url``::

      {"wake": {"url": "https://sandbox.example/wake/<token-ish-path>",
                "method": "POST",
                "timeout_s": 5,
                "secret_ref": "INSTINCT_WAKE_TOKEN"}}

- ``email`` — send a wake email to ``to`` via the head host's
  connected Gmail (``hatch_gws_cli gmail +send``). No secret needed;
  Gmail auth is already connected on the head, and nothing credential-
  shaped is stored anywhere::

      {"wake": {"channel": "email",
                "to": "novaagent@mail.instinct.com"}}

Stdlib only.
"""

import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request

CHANNEL_WEBHOOK = "webhook"
CHANNEL_EMAIL = "email"
CHANNELS = (CHANNEL_WEBHOOK, CHANNEL_EMAIL)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DEFAULT_METHOD = "POST"
DEFAULT_TIMEOUT_S = 5
MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 30
DEFAULT_STALE_AFTER_S = 300  # presence older than this counts as STALE

_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


def _is_loopback_host(host):
    host = (host or "").lower().split("%")[0].strip("[]")
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


def parse_wake_config(cfg):
    """Validate the structural shape of a roster ``wake`` block.

    Returns the normalized dict. For channel ``webhook`` (the default):
    ``{"channel", "url", "method", "timeout_s", "secret_ref"}``. For
    channel ``email``: ``{"channel", "to"}``. Returns None when no wake
    block is configured (cfg is None). Raises ValueError on malformed
    config. URL scheme policy (https, or http loopback) is checked by
    ``validate_wake_url`` (webhook channel only).
    """
    if cfg is None:
        return None
    if not isinstance(cfg, dict):
        raise ValueError("wake config must be an object")
    channel = str(cfg.get("channel", CHANNEL_WEBHOOK)).strip().lower()
    if channel == CHANNEL_EMAIL:
        to = cfg.get("to")
        if not isinstance(to, str) or not _EMAIL_RE.match(to.strip()):
            raise ValueError("wake.to must be a valid email address "
                             "for channel 'email'")
        return {"channel": CHANNEL_EMAIL, "to": to.strip()}
    if channel != CHANNEL_WEBHOOK:
        raise ValueError("wake.channel must be one of %s, got %r"
                         % (list(CHANNELS), cfg.get("channel")))
    url = cfg.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("wake.url must be a non-empty string")
    method = cfg.get("method", DEFAULT_METHOD)
    if not isinstance(method, str) or not method.strip():
        raise ValueError("wake.method must be a non-empty string")
    secret_ref = cfg.get("secret_ref")
    if not isinstance(secret_ref, str) or not secret_ref.strip():
        raise ValueError("wake.secret_ref must be a non-empty string "
                         "(a reference NAME — never the secret itself)")
    try:
        timeout_s = float(cfg.get("timeout_s", DEFAULT_TIMEOUT_S))
    except (TypeError, ValueError):
        raise ValueError("wake.timeout_s must be a number")
    if not (MIN_TIMEOUT_S <= timeout_s <= MAX_TIMEOUT_S):
        raise ValueError("wake.timeout_s must be between %d and %d seconds"
                         % (MIN_TIMEOUT_S, MAX_TIMEOUT_S))
    return {"channel": CHANNEL_WEBHOOK,
            "url": url.strip(),
            "method": method.strip().upper(),
            "timeout_s": timeout_s,
            "secret_ref": secret_ref.strip()}


def validate_wake_url(cfg, allow_insecure=False):
    """Enforce the URL scheme policy on a parsed wake config.

    https always. http only when ``allow_insecure`` is set AND the host
    is loopback (tests). Raises ValueError otherwise.
    """
    parts = urllib.parse.urlparse(cfg["url"])
    scheme = parts.scheme.lower()
    if parts.username or parts.password:
        raise ValueError("wake.url must not embed credentials "
                         "(the secret travels in a header via secret_ref)")
    if scheme == "https" and parts.hostname:
        return
    if scheme == "http" and allow_insecure \
            and _is_loopback_host(parts.hostname):
        return
    raise ValueError("wake.url must be https (http only for loopback in "
                     "tests): %r" % (cfg["url"],))


def _redact_secret(result):
    """Strip anything secret-shaped from a result dict before logging."""
    result.pop("secret", None)
    return result


def fire_wake(cfg, payload, secret_resolver=None, timeout=None):
    """Fire the wake webhook. NEVER raises — wake is a nudge, and a wake
    failure must never block the task assignment.

    ``cfg`` is a parsed wake config (see ``parse_wake_config``).
    ``payload`` is the JSON body sent (task_id, agent handle, reason...).
    ``secret_resolver`` maps ``cfg["secret_ref"]`` -> the secret string;
    when it returns a value it is sent as a Bearer token header.

    Returns ``{"fired": bool, "status": int|None, "error": str|None}``.
    The secret never appears in the result.
    """
    result = {"fired": False, "status": None, "error": None}
    try:
        body = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(
            cfg["url"], data=body, method=cfg["method"],
            headers={"Content-Type": "application/json",
                     "User-Agent": "acp-fleet-wake/1"})
        if secret_resolver is not None:
            secret = secret_resolver(cfg["secret_ref"])
            if secret:
                req.add_header("Authorization", "Bearer " + str(secret))
        to = cfg["timeout_s"] if timeout is None else timeout
        with urllib.request.urlopen(req, timeout=to) as resp:
            result["status"] = resp.status
            result["fired"] = 200 <= resp.status < 300
            if not result["fired"]:
                result["error"] = "http %s" % resp.status
    except Exception as e:  # noqa: BLE001 - non-blocking by design
        result["error"] = "%s: %s" % (type(e).__name__, e)
    return _redact_secret(result)


# ------------------------------------------------------------ email wake

def build_wake_email(cfg, payload):
    """Render the wake email for an ``email``-channel wake config.

    Returns ``(subject, body)``. The subject is ``[fleet task] <title>``;
    the body carries the task summary and points the agent at the ACP
    relay mailbox, where the full task card is already queued.
    """
    payload = payload or {}
    title = payload.get("title") or "(untitled task)"
    task_id = payload.get("task_id") or "?"
    to_handle = payload.get("to") or "agent"
    instructions = (payload.get("instructions") or "").strip()
    subject = "[fleet task] %s" % title
    lines = [
        "Phoenix fleet wake-on-task.",
        "",
        "A task was assigned to @%s while its presence was stale, so "
        "this wake email was sent." % to_handle,
        "",
        "Task: %s" % title,
        "Task ID: %s" % task_id,
    ]
    if instructions:
        lines += ["", "Instructions:", instructions]
    lines += [
        "",
        "The full task card is queued as a direct message on the ACP "
        "relay mailbox — reconnect and drain your mailbox to pick it up, "
        "then ack with a task_ack fleet block.",
    ]
    return subject, "\n".join(lines)


def default_email_sender(to, subject, body, timeout_s=30):
    """Send via the head host's connected Gmail CLI. Never raises.

    Returns ``{"sent": bool, "error": str|None}``. No credentials are
    handled here — the CLI uses the host's connected Gmail account.
    """
    try:
        proc = subprocess.run(
            ["hatch_gws_cli", "gmail", "+send",
             "--to", to, "--subject", subject, "--body", body],
            capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:  # noqa: BLE001 - non-blocking by design
        return {"sent": False,
                "error": "%s: %s" % (type(e).__name__, e)}
    if proc.returncode != 0:
        err = ((proc.stderr or "") + (proc.stdout or "")).strip()
        return {"sent": False,
                "error": "gmail +send exited %d: %s"
                         % (proc.returncode, err[:200])}
    return {"sent": True, "error": None}


def fire_wake_email(cfg, payload, send_mail=None):
    """Send the wake email. NEVER raises — wake is a nudge, and a wake
    failure must never block the task assignment.

    ``cfg`` is a parsed email-channel wake config (see
    ``parse_wake_config``). ``payload`` carries to/task_id/title (and
    optionally instructions). ``send_mail`` is an injectable
    ``(to, subject, body) -> {"sent", "error"}`` callable; the default
    sends through the head host's connected Gmail CLI.

    Returns ``{"fired": bool, "status": None, "error": str|None}`` —
    the same shape as ``fire_wake`` so callers can treat channels
    uniformly.
    """
    result = {"fired": False, "status": None, "error": None}
    try:
        if cfg.get("channel") != CHANNEL_EMAIL:
            raise ValueError("not an email wake config")
        subject, body = build_wake_email(cfg, payload)
        sender = send_mail or default_email_sender
        outcome = sender(cfg["to"], subject, body) or {}
        result["fired"] = bool(outcome.get("sent"))
        if not result["fired"]:
            result["error"] = outcome.get("error") or "send failed"
    except Exception as e:  # noqa: BLE001 - non-blocking by design
        result["error"] = "%s: %s" % (type(e).__name__, e)
    return result


# ------------------------------------------------------------- presence

def read_presence(path):
    """Read the head-side presence store: ``{handle: last_seen_epoch}``.
    Missing file -> {}. Values that are not numbers are dropped."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(h): float(ts) for h, ts in data.items()
            if isinstance(ts, (int, float))}


def touch_presence(path, handle, now=None):
    """Record ``handle`` as seen right now. The head's watcher calls this
    whenever it observes agent activity (room ack, group message...)."""
    now = time.time() if now is None else float(now)
    presence = read_presence(path)
    presence[str(handle)] = now
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(presence, fh, ensure_ascii=False)
    os.replace(tmp, path)


def is_stale(handle, presence, now=None, stale_after_s=DEFAULT_STALE_AFTER_S):
    """True when the agent has never been seen, or its last_seen is older
    than ``stale_after_s``."""
    now = time.time() if now is None else float(now)
    last = presence.get(str(handle))
    if last is None:
        return True
    return (now - last) > stale_after_s


# ---------------------------------------------------------------- audit

def audit_log(path, event):
    """Append one JSON line to the audit trail. Never raises."""
    try:
        record = dict(event)
        record.setdefault("at", int(time.time()))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
