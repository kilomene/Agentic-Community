#!/usr/bin/env python3
"""Workstream D: Autopilot — daemon-side autonomous agent-to-agent chat.

Default posture: AUTONOMOUS. Group channels are ON by default — no
``autopilot.json`` needed. The built-in default policy answers channel
messages in ``hook`` mode via the ``default`` hook
(``<home>/autopilot_hooks/default.py``); when that hook script is
absent nothing replies (audited as ``hook_missing``), so installing the
hook is the true opt-in and no stray process can ever speak for the
agent. Direct-message peers stay OFF by default (any relay peer can DM
you): opt a peer in explicitly, or set a ``"default"`` policy under
``"peers"``. Any explicit entry — including ``"mode": "off"`` — always
wins over the defaults, so the owner can always silence a peer/channel.

Two modes per peer/channel:

* ``"mode": "echo"`` — built-in test mode, replies ``"echo: <text>"``.
* ``"mode": "hook"`` — runs ``<home>/autopilot_hooks/<name>.py`` as a
  SUBPROCESS (isolation + killable): the event dict goes to the hook's
  stdin as JSON; the hook prints the reply on stdout, either
  ``{"reply": "<text>"}`` or a bare text line (empty stdout = no reply).
  Timeout (default 15 s) kills the hook — no reply is sent.

Hard rules, always enforced:

* A hook NEVER chooses recipients: the reply always goes to the event's
  source (the peer, or the channel). Any ``"to"``-style field in hook
  output is parsed and then ignored.
* Loop guard: if the inbound event is itself auto-generated (``auto``
  true) and the policy's ``reply_to_auto`` is false, no reply is sent.
  This stops two autopilots ping-ponging forever.
* Token bucket per peer/channel (default 6/min): excess events are
  dropped and audit-logged as ``autopilot.rate_limited``.
* Every decision is audited: ``autopilot.reply_sent``,
  ``autopilot.no_reply``, ``autopilot.skipped`` (reason: off/auto/rate),
  ``autopilot.hook_timeout``.
* The hook subprocess NEVER receives secrets: its environment holds only
  ``ACP_EVENT_KIND`` (CPython's subprocess may additionally inject the
  ``LC_CTYPE`` locale variable — not a secret); no passphrase, no tokens.

``poll_events(home, cursor_path)`` is the brain-side companion: it reads
``connector.db`` directly (sqlite3, read-only) and returns NEW inbound
direct messages plus group messages since a cursor stored in a JSON
file — no daemon needed. All column/table lookups are defensive so it
keeps working whether or not workstreams A (``reply_to``/``auto`` on
direct messages) and C (group ``reply_to``/``refs``) have landed.

Stdlib only. Protocol-first: the hook contract, config format and event
schema are specified in README.md ("Autopilot") and docs/PROTOCOL.md §12.
"""

import json
import logging
import inspect
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time

LOG = logging.getLogger("acp-relay-daemon.autopilot")

DEFAULT_MAX_PER_MIN = 6
DEFAULT_HOOK_TIMEOUT = 15.0
RATE_WINDOW = 60.0

_HOOK_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_HOOK_NAME = "default"
_MAX_REPLY_CHARS = 4000
_MAX_EVENT_TEXT_CHARS = 8000
_MAX_HOOK_STDOUT = 65536
_MAX_HOOK_STDERR_LOG = 4096
_POLL_BATCH = 500


def _accepts_kwarg(fn, name):
    """True if calling ``fn`` accepts keyword argument ``name``
    (explicit parameter or **kwargs). Never raises."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return (any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
            or name in (p.name for p in params))


# ---------------------------------------------------------------- config

def _policy_defaults():
    return {"mode": None, "hook": None, "max_per_min": DEFAULT_MAX_PER_MIN,
            "reply_to_auto": False}


def _builtin_default_policy():
    """Built-in default policy: group channels answer in hook mode via
    the ``default`` hook. A missing hook script means silence (audited
    as ``hook_missing``) — installing the hook is the true opt-in."""
    return {"mode": "hook", "hook": _DEFAULT_HOOK_NAME,
            "max_per_min": DEFAULT_MAX_PER_MIN, "reply_to_auto": False}


def _normalize_policy(raw):
    """Validate one peers/channels entry. Returns a policy dict, or None
    when the entry is unusable (treated as 'off')."""
    if not isinstance(raw, dict):
        return None
    p = _policy_defaults()
    mode = raw.get("mode")
    if mode not in ("hook", "echo"):
        return None
    p["mode"] = mode
    if mode == "hook":
        name = raw.get("hook")
        if not isinstance(name, str) or not _HOOK_NAME_RE.match(name):
            return None
        p["hook"] = name
    try:
        p["max_per_min"] = int(raw.get("max_per_min", DEFAULT_MAX_PER_MIN))
    except (TypeError, ValueError):
        p["max_per_min"] = DEFAULT_MAX_PER_MIN
    p["reply_to_auto"] = bool(raw.get("reply_to_auto", False))
    return p


class Autopilot:
    """Autonomous replies for the relay daemon — on by default.

    ``conn`` is any connector-like object exposing ``send_message`` /
    ``on_message`` and (optionally) ``messaging.send_reply``,
    ``audit.log`` and ``peer_id``. Pass ``groups`` with a
    ``send_group_message(group_id, text)`` method (e.g. a GroupChat) to
    enable channel replies; without it, group events are skipped.

    ``background=True`` (default) handles each event on its own daemon
    thread so the connector's reader thread is never blocked by a hook
    (15 s) or a blocking send (30 s ACK). Use ``background=False`` in
    tests for synchronous handling.
    """

    def __init__(self, home, conn, groups=None, hook_timeout=DEFAULT_HOOK_TIMEOUT,
                 background=True, config_path=None, hooks_dir=None):
        self.home = os.path.abspath(home)
        self._conn = conn
        self.groups = groups
        self.hook_timeout = hook_timeout
        self.background = background
        self.config_path = (config_path or
                            os.path.join(self.home, "autopilot.json"))
        self.hooks_dir = (hooks_dir or
                          os.path.join(self.home, "autopilot_hooks"))
        self._lock = threading.RLock()
        self._buckets = {}   # rate key -> [monotonic timestamps]
        self._threads = []

    # ------------------------------------------------------- event entry

    def handle_direct(self, sender, text, msg_id):
        """on_message callback: cb(sender_pid, text, msg_id)."""
        self._dispatch(self._direct_event(sender, text, msg_id))

    def handle_group(self, group_id, sender, text, seq):
        """on_group_message callback: cb(group_id, sender_pid, text, seq)."""
        self._dispatch(self._group_event(group_id, sender, text, seq))

    def join_pending(self, timeout=None):
        """Wait for background event threads (tests / clean shutdown)."""
        with self._lock:
            threads = [t for t in self._threads if t.is_alive()]
        for t in threads:
            t.join(timeout)

    # ------------------------------------------------------------- config

    def load_config(self):
        """Owner-edited config.

        Shape: ``{"peers": {peer_id: policy, ...}, "channels":
        {group_id: policy, ...}}`` where each section may also carry a
        ``"default"`` entry used as that section's fallback. A policy
        entry is ``{"mode": "hook"|"echo", ...}``; ``"mode": "off"``
        (or any invalid entry) explicitly disables that peer/channel.

        Precedence per peer/channel: explicit entry -> section
        ``"default"`` -> built-in default (channels: answer via the
        ``default`` hook; peers: off). An absent/unparseable file is
        the same as an empty config — the built-in defaults apply.
        Explicit-off entries are stored as ``False`` so they stay
        distinguishable from absent keys.
        """
        cfg = {"peers": {}, "channels": {},
               "defaults": {"peers": None, "channels": None}}
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as e:
            if isinstance(e, OSError) and not os.path.exists(self.config_path):
                LOG.debug("autopilot: no config at %s (built-in defaults)",
                          self.config_path)
            else:
                LOG.warning("autopilot: bad config %s: %s"
                            " (built-in defaults)", self.config_path, e)
            return cfg
        if not isinstance(raw, dict):
            return cfg
        for section in ("peers", "channels"):
            entries = raw.get(section)
            if not isinstance(entries, dict):
                continue
            for key, entry in entries.items():
                p = _normalize_policy(entry)
                stored = p if p is not None else False
                if key == "default":
                    cfg["defaults"][section] = stored
                else:
                    cfg[section][str(key)] = stored
        return cfg

    def _resolve_policy(self, cfg, section, key):
        """Effective policy for one peer/channel.

        Returns ``(policy_or_None, source)``; ``source`` is one of
        ``"explicit"``, ``"section_default"``, ``"builtin_default"``,
        ``"off"``. Precedence: explicit entry (an invalid/``"off"``
        entry means explicitly off) -> section ``"default"`` ->
        built-in default (channels answer via the ``default`` hook;
        peers stay off).
        """
        if key in cfg[section]:
            entry = cfg[section][key]
            if entry is False:
                return None, "off"
            return entry, "explicit"
        dflt = cfg["defaults"][section]
        if dflt is not None:
            if dflt is False:
                return None, "off"
            return dflt, "section_default"
        if section == "channels":
            return _builtin_default_policy(), "builtin_default"
        return None, "off"

    # -------------------------------------------------------------- audit

    def _audit(self, event, actor="local", target=None, result="ok",
               details=None):
        try:
            audit = getattr(self._conn, "audit", None)
            log = getattr(audit, "log", None) if audit is not None else None
            if callable(log):
                log(event, actor=actor, target=target, result=result,
                    details=details or {})
                return
        except Exception:  # noqa: BLE001 - audit must never break handling
            pass
        LOG.info("autopilot audit %s actor=%s target=%s result=%s details=%s",
                 event, actor, target, result, details or {})

    # --------------------------------------------------------- event dicts

    def _db_path(self):
        return os.path.join(self.home, "connector.db")

    def _direct_event(self, sender, text, msg_id):
        return {
            "kind": "message",
            "sender": sender,
            "text": text if isinstance(text, str) else "",
            "msg_id": msg_id,
            "reply_to": self._lookup_direct_field(msg_id, "reply_to"),
            "auto": self._lookup_direct_field(msg_id, "auto", False),
            "group_id": None,
            "channel": None,
        }

    def _lookup_direct_field(self, msg_id, column, default=None):
        """Defensive read of a messages-table column (workstream A may not
        have landed: missing table/column/row -> default)."""
        try:
            con = sqlite3.connect("file:%s?mode=ro" % self._db_path(),
                                  uri=True, timeout=5)
            try:
                cols = [r[1] for r in
                        con.execute("PRAGMA table_info(messages)").fetchall()]
                if column not in cols:
                    return default
                row = con.execute(
                    "SELECT %s FROM messages WHERE message_id=?" % column,
                    (msg_id,)).fetchone()
                if row is None or row[0] is None:
                    return default
                if column == "auto":
                    return bool(row[0])
                return row[0]
            finally:
                con.close()
        except Exception:  # noqa: BLE001 - DB absent/locked: not fatal
            return default

    def _group_event(self, group_id, sender, text, seq):
        msg_id = self._lookup_group_msg_id(group_id, sender, seq)
        return {
            "kind": "group_message",
            "sender": sender,
            "text": text if isinstance(text, str) else "",
            "msg_id": msg_id,
            "reply_to": self._lookup_group_field(group_id, msg_id, "reply_to"),
            "auto": bool(self._lookup_group_field(group_id, msg_id, "auto", 0)),
            "group_id": group_id,
            "channel": self._channel_info(group_id),
        }

    def _lookup_group_msg_id(self, group_id, sender, seq):
        try:
            con = sqlite3.connect("file:%s?mode=ro" % self._db_path(),
                                  uri=True, timeout=5)
            try:
                row = con.execute(
                    "SELECT message_id FROM group_history"
                    " WHERE group_id=? AND sender_id=? AND seq=?"
                    " ORDER BY created_at DESC LIMIT 1",
                    (group_id, sender, seq)).fetchone()
                return row[0] if row else None
            finally:
                con.close()
        except Exception:  # noqa: BLE001
            return None

    def _lookup_group_field(self, group_id, msg_id, column, default=None):
        if not msg_id:
            return default
        try:
            con = sqlite3.connect("file:%s?mode=ro" % self._db_path(),
                                  uri=True, timeout=5)
            try:
                cols = [r[1] for r in
                        con.execute("PRAGMA table_info(group_history)"
                                    ).fetchall()]
                if column not in cols:
                    return default
                row = con.execute(
                    "SELECT %s FROM group_history WHERE message_id=?" % column,
                    (msg_id,)).fetchone()
                if row is None or row[0] is None:
                    return default
                return row[0]
            finally:
                con.close()
        except Exception:  # noqa: BLE001
            return default

    def _channel_info(self, group_id):
        name = None
        try:
            con = sqlite3.connect("file:%s?mode=ro" % self._db_path(),
                                  uri=True, timeout=5)
            try:
                row = con.execute(
                    "SELECT name FROM group_chats WHERE group_id=?",
                    (group_id,)).fetchone()
                if row:
                    name = row[0]
            finally:
                con.close()
        except Exception:  # noqa: BLE001
            pass
        return {"name": name, "project_id": None}

    # ------------------------------------------------------------- handle

    def _dispatch(self, event):
        if self.background:
            t = threading.Thread(target=self._handle_event_safe,
                                 args=(event,), daemon=True,
                                 name="autopilot-event")
            with self._lock:
                self._threads.append(t)
            t.start()
            with self._lock:
                # Prune finished threads; the just-started one is alive
                # here, so it survives the filter.
                self._threads = [x for x in self._threads if x.is_alive()]
        else:
            self._handle_event(event)

    def _handle_event_safe(self, event):
        try:
            self._handle_event(event)
        except Exception as e:  # noqa: BLE001 - never kill the reader thread
            LOG.error("autopilot: event handler crashed: %s", e)

    def _own_pid(self):
        return getattr(self._conn, "peer_id", None)

    def _handle_event(self, event):
        kind = event["kind"]
        sender = event["sender"]
        cfg = self.load_config()
        section = "peers" if kind == "message" else "channels"
        key = sender if kind == "message" else event.get("group_id")
        policy, policy_source = self._resolve_policy(cfg, section, key)
        target = key  # audit target: peer pid or group id

        if policy is None:
            self._audit("autopilot.skipped", actor=sender, target=target,
                        details={"kind": kind, "reason": "off"})
            return

        # Never reply to our own messages.
        own = self._own_pid()
        if own and sender == own:
            self._audit("autopilot.skipped", actor=sender, target=target,
                        details={"kind": kind, "reason": "own_message"})
            return

        # Loop guard: don't answer another bot's auto-reply unless the
        # owner explicitly opted in — stops two autopilots ping-ponging.
        if event.get("auto") and not policy["reply_to_auto"]:
            self._audit("autopilot.skipped", actor=sender, target=target,
                        details={"kind": kind, "reason": "auto_guard"})
            return

        # Token bucket per peer/channel.
        if not self._check_rate(key, policy["max_per_min"]):
            self._audit("autopilot.rate_limited", actor=sender,
                        target=target, result="dropped",
                        details={"kind": kind,
                                 "max_per_min": policy["max_per_min"]})
            self._audit("autopilot.skipped", actor=sender, target=target,
                        details={"kind": kind, "reason": "rate_limit"})
            return

        # Produce the reply.
        hook_name = policy["hook"] if policy["mode"] == "hook" else None
        if policy["mode"] == "echo":
            reply = "echo: " + event["text"]
        else:
            reply = self._run_hook(hook_name, event, sender, target)

        if not reply:
            self._audit("autopilot.no_reply", actor=sender, target=target,
                        details={"kind": kind, "hook": hook_name})
            return

        try:
            if kind == "message":
                self._send_direct_reply(sender, reply, event.get("msg_id"))
            else:
                self._send_group_reply(event["group_id"], reply,
                                       event.get("msg_id"))
        except Exception as e:  # noqa: BLE001 - send failure is not fatal
            self._audit("autopilot.send_failed", actor=sender, target=target,
                        result="failed",
                        details={"kind": kind, "error": str(e)})
            return
        self._audit("autopilot.reply_sent", actor=sender, target=target,
                    details={"kind": kind, "msg_id": event.get("msg_id"),
                             "hook": hook_name,
                             "policy": policy_source,
                             "bytes": len(reply.encode("utf-8"))})

    # --------------------------------------------------------- rate limit

    def _check_rate(self, key, max_per_min):
        if max_per_min is None:
            max_per_min = DEFAULT_MAX_PER_MIN
        now = time.monotonic()
        with self._lock:
            stamps = [t for t in self._buckets.get(key, [])
                      if now - t < RATE_WINDOW]
            if max_per_min <= 0 or len(stamps) >= max_per_min:
                self._buckets[key] = stamps
                return False
            stamps.append(now)
            self._buckets[key] = stamps
            return True

    # --------------------------------------------------------------- hook

    def _run_hook(self, name, event, sender, target):
        """Run the hook subprocess; return the reply text or None."""
        script = os.path.join(self.hooks_dir, name + ".py")
        if not os.path.isfile(script):
            LOG.warning("autopilot: hook %r missing at %s", name, script)
            self._audit("autopilot.skipped", actor=sender, target=target,
                        details={"kind": event["kind"],
                                 "reason": "hook_missing", "hook": name})
            return None
        payload = {
            "kind": event["kind"],
            "sender": event["sender"],
            "text": event["text"][:_MAX_EVENT_TEXT_CHARS],
            "msg_id": event.get("msg_id"),
            "reply_to": event.get("reply_to"),
            "auto": bool(event.get("auto")),
            "group_id": event.get("group_id"),
            "channel": event.get("channel"),
        }
        stdin_data = (json.dumps(payload) + "\n").encode("utf-8")
        try:
            proc = subprocess.Popen(
                [sys.executable, script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.hooks_dir,
                # The hook gets ONLY the event kind in its environment.
                # Never the passphrase, never tokens, never secrets.
                env={"ACP_EVENT_KIND": event["kind"]},
            )
        except OSError as e:
            LOG.warning("autopilot: could not launch hook %r: %s", name, e)
            return None
        try:
            out, err = proc.communicate(stdin_data, timeout=self.hook_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            LOG.warning("autopilot: hook %r timed out after %.1fs (killed)",
                        name, self.hook_timeout)
            self._audit("autopilot.hook_timeout", actor=sender,
                        target=target, result="dropped",
                        details={"kind": event["kind"], "hook": name,
                                 "timeout_s": self.hook_timeout})
            return None
        if err:
            LOG.warning("autopilot: hook %r stderr: %.4096s",
                        name, err.decode("utf-8", "replace"))
        return self._parse_hook_output(out, name)

    @staticmethod
    def _parse_hook_output(out, name):
        """Hook contract: stdout is {"reply": "<text>"} or a bare text
        line; empty stdout = no reply. A hook can never name another
        recipient — any "to"-style field is parsed and ignored."""
        text = out[:_MAX_HOOK_STDOUT].decode("utf-8", "replace").strip()
        if not text:
            return None
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                reply = obj.get("reply")
                if reply is None:
                    return None
                reply = str(reply).strip()
                return reply[:_MAX_REPLY_CHARS] or None
        return text[:_MAX_REPLY_CHARS] or None

    # ---------------------------------------------------------------- send

    def _send_direct_reply(self, peer_pid, text, msg_id):
        """Threaded reply when the API supports it, plain send otherwise.

        Preference order (all feature-detected, never assumed):
          1. ``send_message(..., reply_to=..., auto=...)`` (workstream A
             as landed) — threads the reply AND marks it ``auto=True``,
             which is what the other side's loop guard reads;
          2. ``send_reply`` — the brief's hypothetical
             ``send_reply(peer, text, reply_to=...)`` shape, else the
             landed ``send_reply(peer, reply_to_id, text)`` shape
             (threaded, but cannot carry the auto flag);
          3. plain ``send_message(peer, text)``.

        Autopilot replies are always marked ``auto=True`` when the API
        accepts it — that is the loop-prevention flag the other side's
        autopilot reads.
        """
        c = self._conn
        send_message = getattr(c, "send_message", None)
        if (callable(send_message)
                and _accepts_kwarg(send_message, "reply_to")
                and _accepts_kwarg(send_message, "auto")):
            kwargs = {"auto": True}
            if msg_id:
                kwargs["reply_to"] = msg_id
            try:
                return send_message(peer_pid, text, **kwargs)
            except Exception as e:  # noqa: BLE001
                # The reply target may be unknown locally (e.g. store
                # write raced the callback): retry as a plain send rather
                # than dropping the reply. Anything else re-raises.
                if getattr(e, "code", "") != "NOT_FOUND":
                    raise
                LOG.warning("autopilot: threaded send failed (%s); "
                            "retrying plain", e)
        messaging = getattr(c, "messaging", None)
        send_reply = getattr(messaging, "send_reply", None)
        if send_reply is None:
            send_reply = getattr(c, "send_reply", None)
        if callable(send_reply):
            if _accepts_kwarg(send_reply, "reply_to"):
                # Brief's hypothetical shape.
                return send_reply(peer_pid, text, reply_to=msg_id)
            # Landed shape: send_reply(peer, reply_to_id, text).
            return send_reply(peer_pid, msg_id, text)
        if callable(send_message):
            return send_message(peer_pid, text)
        raise RuntimeError("autopilot: connector has no send_message")

    def _send_group_reply(self, group_id, text, msg_id):
        """Threaded group reply when supported, plain group send
        otherwise. Preference: ``send_group_reply`` (hypothetical) ->
        ``send_channel_message(..., reply_to=...)`` (workstream C as
        landed) -> ``send_group_message``."""
        if self.groups is None:
            raise RuntimeError("group replies unavailable (no GroupChat)")
        send_group_reply = getattr(self.groups, "send_group_reply", None)
        if callable(send_group_reply):
            return send_group_reply(group_id, text, reply_to=msg_id)
        send_channel = getattr(self.groups, "send_channel_message", None)
        if (callable(send_channel) and msg_id
                and _accepts_kwarg(send_channel, "reply_to")):
            return send_channel(group_id, text, reply_to=msg_id)
        return self.groups.send_group_message(group_id, text)


# ------------------------------------------------------------------ poll

def _read_cursor(cursor_path):
    try:
        with open(cursor_path, "r", encoding="utf-8") as fh:
            cur = json.load(fh)
        if isinstance(cur, dict):
            return cur
    except (OSError, ValueError):
        pass
    return {"messages": None, "groups": None}


def _write_cursor(cursor_path, cursor):
    tmp = cursor_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cursor, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, cursor_path)


def _table_columns(con, table):
    try:
        return [r[1] for r in
                con.execute("PRAGMA table_info(%s)" % table).fetchall()]
    except Exception:  # noqa: BLE001 - table may not exist
        return []


def _derive_own_pid(con):
    """Own pid from sent rows (status != delivered) — avoids loading the
    encrypted identity just to poll."""
    try:
        row = con.execute(
            "SELECT DISTINCT sender_id FROM messages"
            " WHERE status IN ('sent','queued','acked') LIMIT 1").fetchone()
        return row[0] if row else None
    except Exception:  # noqa: BLE001
        return None


def poll_events(home, cursor_path, own_pid=None):
    """Brain-side poll: NEW inbound direct + group messages since the
    cursor, read straight from ``<home>/connector.db`` (read-only).

    Returns ``(events, new_cursor)``; the cursor is persisted to
    ``cursor_path`` as JSON ``{"messages": ..., "groups": ...}`` keyed on
    ``(created_at, message_id)`` per table. Missing tables/columns are
    tolerated (workstreams A/C may not have landed).

    ``own_pid`` filters own group sends; when omitted it is derived from
    the DB's sent rows, and when that fails group messages from every
    sender are returned (documented fallback — the caller can filter).
    """
    home = os.path.abspath(home)
    db_path = os.path.join(home, "connector.db")
    cursor = _read_cursor(cursor_path)
    events = []
    if not os.path.exists(db_path):
        return events, cursor
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True,
                          check_same_thread=False, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        # ------------------------------------------------- direct messages
        msg_cols = _table_columns(con, "messages")
        if msg_cols:
            select = ["message_id", "sender_id", "text", "created_at"]
            if "reply_to" in msg_cols:
                select.append("reply_to")
            if "auto" in msg_cols:
                select.append("auto")
            if "scope" in msg_cols:
                where = "scope='direct'"
            else:
                where = "1=1"
            where += " AND status='delivered'"  # inbound only
            params = []
            cur = cursor.get("messages")
            if cur:
                where += (" AND (created_at > ? OR (created_at = ?"
                          " AND message_id > ?))")
                params += [cur[0], cur[0], cur[1]]
            rows = con.execute(
                "SELECT %s FROM messages WHERE %s"
                " ORDER BY created_at, message_id LIMIT %d"
                % (", ".join(select), where, _POLL_BATCH),
                params).fetchall()
            for r in rows:
                d = dict(r)
                events.append({
                    "kind": "message",
                    "sender": d["sender_id"],
                    "text": d["text"],
                    "msg_id": d["message_id"],
                    "reply_to": d.get("reply_to"),
                    "auto": bool(d.get("auto", 0)),
                    "group_id": None,
                    "channel": None,
                })
            if rows:
                last = dict(rows[-1])
                cursor["messages"] = [last["created_at"], last["message_id"]]

        # -------------------------------------------------- group messages
        grp_cols = _table_columns(con, "group_history")
        if grp_cols:
            if own_pid is None:
                own_pid = _derive_own_pid(con)
            select = ["message_id", "group_id", "sender_id", "text",
                      "created_at"]
            for col in ("reply_to", "auto", "refs"):
                if col in grp_cols:
                    select.append(col)
            where = "1=1"
            params = []
            if own_pid:
                where += " AND sender_id != ?"
                params.append(own_pid)
            cur = cursor.get("groups")
            if cur:
                where += (" AND (created_at > ? OR (created_at = ?"
                          " AND message_id > ?))")
                params += [cur[0], cur[0], cur[1]]
            rows = con.execute(
                "SELECT %s FROM group_history WHERE %s"
                " ORDER BY created_at, message_id LIMIT %d"
                % (", ".join(select), where, _POLL_BATCH),
                params).fetchall()
            for r in rows:
                d = dict(r)
                events.append({
                    "kind": "group_message",
                    "sender": d["sender_id"],
                    "text": d["text"],
                    "msg_id": d["message_id"],
                    "reply_to": d.get("reply_to"),
                    "auto": bool(d.get("auto", 0)),
                    "group_id": d["group_id"],
                    "channel": {"name": _group_name(con, d["group_id"]),
                                "project_id": None},
                })
            if rows:
                last = dict(rows[-1])
                cursor["groups"] = [last["created_at"], last["message_id"]]
    finally:
        con.close()
    _write_cursor(cursor_path, cursor)
    return events, cursor


def _group_name(con, group_id):
    try:
        row = con.execute("SELECT name FROM group_chats WHERE group_id=?",
                          (group_id,)).fetchone()
        return row[0] if row else None
    except Exception:  # noqa: BLE001
        return None
