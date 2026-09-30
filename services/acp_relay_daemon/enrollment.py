"""One-step enrollment: time-boxed auto-pairing windows.

The head opens an enrollment window (``fleet enroll --open <minutes>``);
while it is open, an agent that presents our live pairing code completes
pairing with NO confirm-code step. When no window is open the normal
confirm-code flow runs untouched.

Trust model (see docs/ENROLLMENT.md): the pairing code is a single-use
rendezvous with a TTL. Opening a window explicitly trades the human
confirm step for the presented-code check, time-boxed and fully logged.
The window is just a JSON file in the daemon's state dir, so the head
CLI and the running daemon coordinate through the filesystem — no IPC,
no restart needed.

Expiry is enforced in two independent places (never a single timer):
  * on every pairing attempt (evaluate_request -> get_window), and
  * on a periodic sweep (sweep_expired, called from the daemon's serve
    loop).

Stdlib only. ``state_dir`` is configurable so tests use tmp dirs and
never touch the running daemon's state.
"""

import hmac
import json
import os
import time

WINDOW_FILE = "enrollment.json"

# A window must stay a window: cap it at 24h so a typo can't leave the
# door open indefinitely.
MIN_MINUTES = 1
MAX_MINUTES = 24 * 60


def window_path(state_dir):
    return os.path.join(state_dir, WINDOW_FILE)


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _blank(now):
    return {"open": False, "opened_at": None, "open_until": None,
            "minutes": None, "opened_by": None, "closed_at": now,
            "close_reason": "never opened"}


def _read(state_dir):
    try:
        with open(window_path(state_dir), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def open_window(state_dir, minutes, opened_by, now=None):
    """Open (or re-open) an enrollment window for ``minutes`` minutes.

    Returns the window dict. Raises ValueError on a bad duration.
    """
    now = int(time.time() if now is None else now)
    minutes = int(minutes)
    if not (MIN_MINUTES <= minutes <= MAX_MINUTES):
        raise ValueError("minutes must be between %d and %d"
                         % (MIN_MINUTES, MAX_MINUTES))
    window = {"open": True,
              "opened_at": now,
              "open_until": now + minutes * 60,
              "minutes": minutes,
              "opened_by": opened_by or "head",
              "closed_at": None,
              "close_reason": None}
    os.makedirs(state_dir, exist_ok=True)
    _write_json(window_path(state_dir), window)
    return window


def close_window(state_dir, reason="closed", now=None):
    """Close the window now. Returns the window dict."""
    now = int(time.time() if now is None else now)
    window = _read(state_dir) or _blank(now)
    window["open"] = False
    window["closed_at"] = now
    window["close_reason"] = reason
    os.makedirs(state_dir, exist_ok=True)
    _write_json(window_path(state_dir), window)
    return window


def get_window(state_dir, now=None):
    """Read the window, auto-closing it if the deadline has passed.

    This is the expiry check that runs on every pairing attempt — an
    expired window can never auto-accept, even if the periodic sweep
    hasn't run yet.
    """
    now = int(time.time() if now is None else now)
    window = _read(state_dir)
    if window is None:
        return _blank(now)
    if window.get("open"):
        open_until = window.get("open_until") or 0
        if now >= open_until:
            return close_window(state_dir, reason="expired", now=now)
    return window


def sweep_expired(state_dir, now=None):
    """Periodic sweep: close an expired window outside the pairing path.

    Returns True when the sweep actually closed a window (so the caller
    can log it); False otherwise. Safe to call on any schedule.
    """
    now = int(time.time() if now is None else now)
    window = _read(state_dir)
    if not window or not window.get("open"):
        return False
    if now >= (window.get("open_until") or 0):
        close_window(state_dir, reason="expired", now=now)
        return True
    return False


def status(state_dir, now=None):
    """Human-facing status dict, with seconds remaining when open."""
    now = int(time.time() if now is None else now)
    window = get_window(state_dir, now=now)
    out = dict(window)
    out["remaining"] = (max(0, window["open_until"] - now)
                        if window.get("open") and window.get("open_until")
                        else None)
    out["now"] = now
    return out


def is_open(state_dir, now=None):
    """True when a live enrollment window is open right now."""
    return bool(get_window(state_dir, now=now).get("open"))


def evaluate_request(session, daemon_code, state_dir, now=None):
    """Decide whether a pairing request auto-completes via enrollment.

    ``session`` is the responder-side PairingSession (its
    ``presented_code`` is the pairing code the initiator put in the
    pair_request, or None). ``daemon_code`` is the daemon's currently
    claimed pairing code.

    Returns ``{"code": ..., "open_until": ...}`` when the window is
    open AND the presented code matches the daemon's live code;
    returns None otherwise (caller keeps the confirm-code flow).
    """
    window = get_window(state_dir,
                        now=None if now is None else now)
    if not window.get("open"):
        return None
    presented = str(getattr(session, "presented_code", None) or "")
    presented = presented.strip().upper()
    code = str(daemon_code or "").strip().upper()
    if not code or not presented:
        return None
    if not hmac.compare_digest(presented, code):
        return None
    return {"code": code, "open_until": window.get("open_until")}
