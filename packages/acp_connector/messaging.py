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

    def send_message(self, peer_pid, text):
        c = self._c
        c._require_peer(peer_pid)
        if not isinstance(text, str) or not text:
            raise AcpError("INTERNAL", "text must be a non-empty string")
        msg_id = os.urandom(16).hex()
        ev = threading.Event()
        with self._lock:
            self._waiters[msg_id] = ev
        try:
            c._send_e2e(MSG, peer_pid, {"text": text, "msg_id": msg_id})
        except AcpError:
            with self._lock:
                self._waiters.pop(msg_id, None)
            raise
        now = int(time.time())
        c.store.add_message(msg_id, c.peer_id, "direct", None, text, now,
                            "sent", now)
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
        c.audit.log("message.sent", actor=peer_pid, target=msg_id,
                    result="ok", details={"bytes": len(text.encode())})
        c._metric("message_sent", nbytes=len(text.encode()))
        return msg_id

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
            c.store.add_message(msg_id, sender, "direct", None, text,
                                int(env["ts"]), "delivered", now)
            c.audit.log("message.received", actor=sender, target=msg_id,
                        result="ok",
                        details={"bytes": len(text.encode("utf-8"))})
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
