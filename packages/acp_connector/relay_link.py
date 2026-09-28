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
import json
import struct
import threading
import time

from acp_crypto import ed25519_sign
from acp_proto import AcpError, b62encode, canonical

from .ws_transport import wss_connect


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

    # ---------------------------------------------------------------- close
    def close(self):
        self._closed = True
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
