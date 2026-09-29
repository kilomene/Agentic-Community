"""Direct E2E messaging with delivery acknowledgements.

send_message blocks until the peer's MSG_ACK arrives (30 s timeout).
Inbound MSG is stored, acked, and fanned out to on_message callbacks.
Receiving needs no permission (per spec); sending to an unknown or
revoked peer raises.
"""
import os
import threading
import time

from acp_proto import AcpError, MSG, MSG_ACK

ACK_TIMEOUT = 30


class Messaging:
    def __init__(self, connector):
        self._c = connector
        self._lock = threading.Lock()
        self._waiters = {}  # msg_id -> threading.Event
        self._cbs = []

    def on_message(self, cb):
        """cb(sender_pid, text, msg_id)."""
        self._cbs.append(cb)

    def send_message(self, peer_pid, text, *, reply_to=None, auto=False):
        """Send a direct message; blocks until the peer's MSG_ACK arrives.

        reply_to: message_id this message answers. Must be a non-empty
        string that exists in the local messages table (either
        direction); otherwise AcpError(NOT_FOUND). It is a plain
        reference string — it may point at another peer's message.
        auto: marks autopilot-generated messages (loop-prevention for
        autonomous agents). Included on the wire only when True.
        """
        c = self._c
        c._require_peer(peer_pid)
        if not isinstance(text, str) or not text:
            raise AcpError("INTERNAL", "text must be a non-empty string")
        if reply_to is not None:
            if not isinstance(reply_to, str) or not reply_to:
                raise AcpError("NOT_FOUND",
                               "reply_to must be a non-empty message id")
            if c.store.get_message(reply_to) is None:
                raise AcpError("NOT_FOUND",
                               f"reply target {reply_to} not found")
        msg_id = os.urandom(16).hex()
        payload = {"text": text, "msg_id": msg_id}
        if reply_to is not None:
            payload["reply_to"] = reply_to
        if auto:
            payload["auto"] = True
        ev = threading.Event()
        with self._lock:
            self._waiters[msg_id] = ev
        try:
            c._send_e2e(MSG, peer_pid, payload)
        except AcpError:
            with self._lock:
                self._waiters.pop(msg_id, None)
            raise
        now = int(time.time())
        c.store.add_message(msg_id, c.peer_id, "direct", None, text, now,
                            "sent", now, reply_to=reply_to,
                            auto=1 if auto else 0, read_at=now)
        # Wait for the peer's MSG_ACK — but if the relay reports the
        # envelope was queued in the recipient's mailbox (peer offline),
        # return early with a "queued" status instead of blocking the
        # full timeout. The message is safe; delivery happens on
        # reconnect and the late ACK (if any) is just logged as stray.
        deadline = time.time() + ACK_TIMEOUT
        mailbox_id = None
        acked = False
        while not acked and time.time() < deadline:
            q = c._pop_relay_queued(peer_pid)
            if q is not None:
                mailbox_id = q
                break
            acked = ev.wait(0.5)
        if mailbox_id is not None:
            with self._lock:
                self._waiters.pop(msg_id, None)
            c.store.update_message(msg_id, status="queued")
            c.audit.log("message.queued", actor=peer_pid, target=msg_id,
                        result="ok", details={"mailbox_id": mailbox_id})
            return msg_id
        if not acked:
            with self._lock:
                self._waiters.pop(msg_id, None)
            c.audit.log("message.ack_timeout", actor=peer_pid,
                        target=msg_id, result="failed", details={})
            raise AcpError("INTERNAL",
                           f"no MSG_ACK for {msg_id} within {ACK_TIMEOUT}s")
        with self._lock:
            self._waiters.pop(msg_id, None)
        c.store.update_message(msg_id, status="acked")
        details = {"bytes": len(text.encode())}
        if reply_to is not None:
            details["reply_to"] = reply_to
        if auto:
            details["auto"] = True
        c.audit.log("message.sent", actor=peer_pid, target=msg_id,
                    result="ok", details=details)
        c._metric("message_sent", nbytes=len(text.encode()))
        return msg_id

    def send_reply(self, peer_pid, reply_to_msg_id, text):
        """Thin wrapper: send_message with reply_to set."""
        return self.send_message(peer_pid, text, reply_to=reply_to_msg_id)

    # ------------------------------------------------------- inbound events
    def handle_msg(self, env, payload):
        c = self._c
        sender = env["from"]
        msg_id = payload["msg_id"]
        text = payload["text"]
        # Idempotent: a redelivered msg_id (new nonce) is re-acked, not
        # re-stored or re-announced.
        if c.store.get_message(msg_id) is None:
            now = int(time.time())
            # reply_to is informational: a non-string value is dropped
            # (audit-logged) but never kills the message. auto is stored
            # as-received; only a literal True sets the flag.
            reply_to = payload.get("reply_to")
            if reply_to is not None and not isinstance(reply_to, str):
                c.audit.log("message.bad_reply_to", actor=sender,
                            target=msg_id, result="dropped_field",
                            details={"got_type": type(reply_to).__name__})
                reply_to = None
            auto = 1 if payload.get("auto") is True else 0
            c.store.add_message(msg_id, sender, "direct", None, text,
                                int(env["ts"]), "delivered", now,
                                reply_to=reply_to, auto=auto)
            c.audit.log("message.received", actor=sender, target=msg_id,
                        result="ok",
                        details={"bytes": len(text.encode("utf-8")),
                                 "auto": bool(auto)})
            c._metric("message_received",
                      nbytes=len(text.encode("utf-8")))
            for cb in list(self._cbs):
                try:
                    cb(sender, text, msg_id)
                except Exception as e:
                    c.audit.log("message.callback_error", actor=sender,
                                target=msg_id, result="failed",
                                details={"error": str(e)})
        try:
            c._send_e2e(MSG_ACK, sender, {"msg_id": msg_id})
        except AcpError as e:
            c.audit.log("message.ack_failed", actor=sender, target=msg_id,
                        result="failed", details={"error": e.code})

    def handle_ack(self, env, payload):
        msg_id = payload["msg_id"]
        with self._lock:
            ev = self._waiters.get(msg_id)
        if ev is not None:
            ev.set()
        else:
            self._c.audit.log("message.stray_ack", actor=env["from"],
                              target=msg_id, result="ok", details={})
