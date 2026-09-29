"""RelayLink: the Connector-side client for a WebSocket ACP relay.

One persistent outbound wss:// connection (e.g. to a Cloudflare Worker
relay); the relay routes envelopes by their ``to`` pid. Wire convention:
each WebSocket binary message is exactly one length-prefixed frame
(4-byte big-endian length + JSON), the same framing the TCP relay uses.

Handshake: the first frame sent is the signed hello
``{"hello": {"pid", "ts", "sig"}}`` (sig = Ed25519 over
canonical({"pid", "ts"})), exactly as services/acp_relay/relay.py
expects.

Control frames coming back (length-prefixed JSON, not envelopes):
  {"relayed": false, "to", "error": "offline"[, "queued": true, ...]}
      -> audit event (the peer is offline; optionally queued server-side)
  {"pong": ts}            -> ignored
  {"mailbox_delivery": {"ids": [...]}} -> arm: the relay drains queued
      mailbox frames BEFORE any live traffic, so the next len(ids)
      envelopes delivered are exactly those; after the last one an
      {"mailbox_ack": {"ids": [...]}} control frame is sent back.
  {"mailbox_ack": {...}}  -> reply to our own ack; ignored

Interface mirrors transport.Conn so Connector can treat the link as a
connection: send_env, send_raw, read_loop (never raises), close,
.closed, .peer_addr.
"""
import os
import re
import struct
import threading
import time

from acp_crypto import ed25519_sign
from acp_proto import AcpError, b62encode, canonical

from .ws_transport import wss_connect

# 6-char pairing codes (same alphabet as pairing.new_code: no 0/O, 1/I/L).
PAIR_CODE_RE = re.compile(r"^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$")
PAIR_CODE_TTL_DEFAULT = 600
PAIR_CODE_TTL_MIN = 60
PAIR_CODE_TTL_MAX = 3600
_PAIR_CODE_RETRIES = 5  # new random code on "taken"


def _looks_like_envelope(obj):
    """Structural check: is this plausibly an ACP envelope frame (as
    opposed to a control frame)? Never raises. Identical to
    services/acp_relay/relay._looks_like_envelope."""
    return (isinstance(obj, dict)
            and isinstance(obj.get("kind"), str)
            and isinstance(obj.get("from"), str)
            and isinstance(obj.get("to"), str)
            and isinstance(obj.get("ts"), int)
            and not isinstance(obj.get("ts"), bool)
            and isinstance(obj.get("nonce"), str)
            and isinstance(obj.get("sig"), str)
            and ("payload" in obj) != ("box" in obj))


class RelayLink:
    """One wss:// link to a relay. Shared by all pids routed through it."""

    def __init__(self, connector):
        self._c = connector
        self._ws = None
        self._closed = False
        self.peer_addr = None
        self._ack_lock = threading.Lock()
        self._ack_ids = None       # armed mailbox ids awaiting envelopes
        self._ack_remaining = 0
        self._pending_lock = threading.Lock()
        self._pending = {}         # req nonce -> [threading.Event, result box]

    @property
    def closed(self):
        if self._closed:
            return True
        ws = self._ws
        return ws is None or ws.closed

    # -------------------------------------------------------------- connect
    def connect(self, url):
        """Open the wss:// connection and send the signed hello.

        Raises AcpError on failure. Starts no reader thread — the
        Connector spawns one via relay_connect().
        """
        if self._ws is not None:
            raise AcpError("INTERNAL", "relay link already connected")
        ws = wss_connect(url)
        try:
            pid = self._c.peer_id
            ts = int(time.time())
            sig = b62encode(ed25519_sign(
                self._c.identity.ed_priv,
                canonical({"pid": pid, "ts": ts})))
            hello = canonical({"hello": {"pid": pid, "ts": ts,
                                          "sig": sig}})
            ws.send_raw(struct.pack(">I", len(hello)) + hello)
        except Exception:
            try:
                ws.close()
            except Exception:
                pass
            raise
        self._ws = ws

    # ----------------------------------------------------------------- send
    def send_env(self, env):
        """Send one envelope through the relay. Raises AcpError."""
        ws = self._ws
        if ws is None or ws.closed:
            self._closed = True
            raise AcpError("INTERNAL", "relay link is closed")
        ws.send_env(env)

    def send_raw(self, frame_bytes):
        """Send one already-framed control frame. Raises AcpError."""
        ws = self._ws
        if ws is None or ws.closed:
            self._closed = True
            raise AcpError("INTERNAL", "relay link is closed")
        ws.send_raw(frame_bytes)

    def _send_control(self, obj):
        """Best-effort control frame send; never raises (the relay
        retries unacked mailbox frames on reconnect)."""
        try:
            raw = canonical(obj)
            self.send_raw(struct.pack(">I", len(raw)) + raw)
        except AcpError:
            pass

    # ----------------------------------------------------------------- read
    def read_loop(self, on_envelope, on_error=None):
        """Pump frames until the link drops. Never raises."""
        ws = self._ws
        if ws is None:
            return
        try:
            ws.read_loop(lambda obj: self._handle_frame(obj, on_envelope),
                         on_error)
        finally:
            self._closed = True

    def _handle_frame(self, obj, on_envelope):
        """Route one parsed JSON frame. Never raises."""
        try:
            if _looks_like_envelope(obj):
                self._handle_envelope(obj, on_envelope)
                return
            if not isinstance(obj, dict):
                return
            if obj.get("relayed") is False:
                self._c.audit.log(
                    "relay.offline", actor="relay", target=obj.get("to"),
                    result="relayed_offline",
                    details={"error": obj.get("error"),
                             "queued": bool(obj.get("queued"))})
                if obj.get("queued"):
                    # The relay stored our envelope in the recipient's
                    # mailbox; surface it so senders get "queued" instead
                    # of an ack timeout.
                    self._c._on_relay_queued(obj.get("to"),
                                             obj.get("mailbox_id"))
                return
            if "pong" in obj:
                return
            if "mailbox_ack" in obj:
                return  # reply to our own ack
            if "mailbox_delivery" in obj:
                self._arm_mailbox_ack(obj.get("mailbox_delivery"))
                return
            # Pair-code directory replies: correlate to the waiting request.
            for key in ("pair_code_claimed", "pair_code_error",
                        "pair_code_released", "pair_code_result"):
                if key in obj:
                    body = obj.get(key) or {}
                    req = body.get("req") if isinstance(body, dict) else None
                    if req:
                        self._resolve_pending(req, {key: body})
                    return
            # Unknown control frame: ignore (forward-compatible).
        except Exception as e:  # never let a control frame kill the reader
            try:
                self._c.audit.log("relay.frame_error", actor="relay",
                                  result="failed",
                                  details={"error": str(e)})
            except Exception:
                pass

    def _handle_envelope(self, env, on_envelope):
        # The relay drains mailbox frames before live traffic, so the
        # next N envelopes after a mailbox_delivery notice are exactly
        # the queued ones. Count them down, deliver, then ack.
        with self._ack_lock:
            ids = self._ack_ids
            if ids is not None:
                self._ack_remaining -= 1
                if self._ack_remaining <= 0:
                    self._ack_ids = None
                    self._ack_remaining = 0
                else:
                    ids = None
        on_envelope(env)
        if ids is not None:
            self._send_control({"mailbox_ack": {"ids": list(ids)}})

    def _arm_mailbox_ack(self, notice):
        ids = notice.get("ids") if isinstance(notice, dict) else None
        if not isinstance(ids, list):
            return
        with self._ack_lock:
            if not ids:
                self._ack_ids = None
                self._ack_remaining = 0
            else:
                self._ack_ids = list(ids)
                self._ack_remaining = len(ids)
        if not ids:
            # Nothing queued; acknowledge the (empty) drain immediately.
            self._send_control({"mailbox_ack": {"ids": []}})

    # ------------------------------------------------------- pair-code directory
    @staticmethod
    def _normalize_code(code):
        c = (code or "").strip().upper()
        if not PAIR_CODE_RE.match(c):
            raise AcpError("INTERNAL",
                           "pairing code must be 6 chars "
                           "[ABCDEFGHJKMNPQRSTUVWXYZ23456789]")
        return c

    def _send_request(self, obj, timeout):
        """Send a control frame, wait for the correlated reply.

        The relay answers with one of the pair_code_* frames carrying
        the same ``req`` nonce. Returns the reply body dict.
        """
        req = os.urandom(8).hex()
        for key in obj:
            obj[key]["req"] = req
        ev = threading.Event()
        box = {}
        with self._pending_lock:
            self._pending[req] = (ev, box)
        try:
            self._send_control(obj)
            if not ev.wait(timeout):
                raise AcpError("INTERNAL",
                               "relay did not answer pair-code request")
            return box["reply"]
        finally:
            with self._pending_lock:
                self._pending.pop(req, None)

    def _resolve_pending(self, req, reply):
        with self._pending_lock:
            pending = self._pending.get(req)
        if pending is not None:
            ev, box = pending
            box["reply"] = reply
            ev.set()

    def claim_pair_code(self, code=None, ttl=PAIR_CODE_TTL_DEFAULT,
                        timeout=20):
        """Claim a 6-char pairing code on the relay for this agent's pid.

        Generates a random code when ``code`` is None (retries on
        collision). The code expires after ``ttl`` seconds (60-3600).
        Returns the claimed code (uppercase).
        """
        from .pairing import new_code  # lazy: pairing must not import us
        if self.closed:
            raise AcpError("INTERNAL", "relay link is closed")
        ttl = max(PAIR_CODE_TTL_MIN, min(PAIR_CODE_TTL_MAX, int(ttl or 0)
                                         or PAIR_CODE_TTL_DEFAULT))
        attempts = _PAIR_CODE_RETRIES if code is None else 1
        last_error = None
        for _ in range(attempts):
            c = self._normalize_code(code) if code else new_code()
            try:
                reply = self._send_request(
                    {"pair_code_claim": {"code": c, "ttl": ttl}}, timeout)
            except AcpError as e:
                last_error = e
                continue
            if "pair_code_claimed" in reply:
                claimed = reply["pair_code_claimed"].get("code")
                if claimed:
                    return claimed
                raise AcpError("INTERNAL", "relay claim reply malformed")
            err = (reply.get("pair_code_error") or {}).get("error")
            if err == "taken" and code is None:
                last_error = AcpError("INTERNAL", "code taken, retrying")
                continue
            raise AcpError("INTERNAL",
                           "relay refused pair-code claim: %s" % (err or "?"))
        raise last_error or AcpError("INTERNAL", "pair-code claim failed")

    def release_pair_code(self, code, timeout=20):
        """Release a code claimed by this connection (best effort)."""
        c = self._normalize_code(code)
        if self.closed:
            return False
        try:
            self._send_request({"pair_code_release": {"code": c}}, timeout)
            return True
        except AcpError:
            return False

    def lookup_pair_code(self, code, timeout=20):
        """Resolve a 6-char pairing code to the owner's peer id.

        Raises NOT_FOUND (unknown/expired), RATE_LIMITED, or INTERNAL.
        """
        c = self._normalize_code(code)
        if self.closed:
            raise AcpError("INTERNAL", "relay link is closed")
        reply = self._send_request({"pair_code_lookup": {"code": c}},
                                   timeout)
        body = reply.get("pair_code_result") or {}
        pid = body.get("pid")
        if pid:
            return pid
        err = body.get("error") or "not_found"
        if err == "rate_limited":
            raise AcpError("RATE_LIMITED", "pair-code lookup rate limited")
        raise AcpError("NOT_FOUND",
                       "pairing code unknown or expired: %s" % c)

    # ---------------------------------------------------------------- close
    def close(self):
        self._closed = True
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def send_ping(self, payload=b""):
        """Send a WebSocket ping frame (keepalive) on the underlying
        socket. Raises AcpError when there is no live connection."""
        ws = self._ws
        if ws is None or self._closed:
            raise AcpError("INTERNAL", "relay link not connected")
        ws.send_ping(payload)
