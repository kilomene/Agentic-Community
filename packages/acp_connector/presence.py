"""Presence broadcast/tracking, typing indicators, and KEY_ROTATE handling.

set_presence(state) stores the local state and sends a signed PRESENCE
envelope to every trusted peer (best effort; presence is plaintext per
PROTOCOL.md section 7). Inbound PRESENCE updates the presence table
with a timestamp.

Typing indicators (TYPING kind, signed plaintext, same posture as
PRESENCE): senders emit typing_start/typing_stop frames while the user
types; receivers keep ephemeral in-memory state that expires 8s after
the last refresh. Heartbeat contract: a sender re-sends typing_start
every <=5s while typing continues; the UI/brain owns that loop, this
module only provides the wire primitives.

KEY_ROTATE: the envelope signature is verified with the OLD stored
identity key by the dispatch layer; here we replace the stored
ipub/x_pub and audit the rotation.
"""
import threading
import time

from acp_proto import AcpError, PRESENCE, KEY_ROTATE, register_kind

# Signed-plaintext wire kind for typing indicators (PROTOCOL.md section
# 7 posture, same as PRESENCE). Schema requires "typing"; "context" and
# "context_id" are optional.
TYPING = register_kind("typing", e2e=False, schema=("typing",))

# Typing-state TTL (seconds). Receivers expire state 8s after the last
# refresh; senders re-send typing_start every <=5s while typing.
TYPING_TTL = 8
TYPING_HEARTBEAT = 5

VALID_STATES = ("online", "offline", "busy", "paused", "unknown")
TYPING_CONTEXTS = ("direct", "group")


class Presence:
    def __init__(self, connector):
        self._c = connector
        # Ephemeral typing state: (sender_pid, context, context_id) ->
        # unix expiry. Never persisted; guarded by an RLock.
        self._typing_lock = threading.RLock()
        self._typing = {}
        # The bound TYPING handler, registered via _ensure_typing_handler.
        # Registration timing: Connector.__init__ builds Presence very
        # early, and on the older init order _ext_handlers is created
        # (and rebound to {}) only afterwards -- so a plain registration
        # here would be wiped, and acp_connector/__init__.py is owned by
        # the coordinator, not this workstream. Two-part answer:
        #  1. try immediate registration (works on the newer init order
        #     where _ext_handlers exists before components);
        #  2. a short daemon timer backstops the older order, firing
        #     after construction -- long before any peer can connect and
        #     send a TYPING frame.
        # Every public entry point also calls _ensure_typing_handler(),
        # making the wiring self-healing and idempotent.
        self._typing_cb = self._on_typing
        try:
            connector.register_kind_handler(TYPING, self._typing_cb)
        except AttributeError:
            pass
        _t = threading.Timer(1.0, self._ensure_typing_handler)
        _t.daemon = True
        _t.name = "acp-typing-register"
        _t.start()

    def _ensure_typing_handler(self):
        """(Re)register the TYPING handler on the connector's V2+
        extension table.

        Connector._dispatch_plain routes every signed-plaintext kind
        that is not PRESENCE/KEY_ROTATE/REVOKE_NOTICE through
        _ext_handlers (after signature verification and
        validate_payload() against the registered schema) -- the same
        pattern groups.GroupChat uses. This needs no change to
        acp_connector/__init__.py.
        """
        c = self._c
        handlers = getattr(c, "_ext_handlers", None)
        if handlers is None:
            handlers = c._ext_handlers = {}
        if handlers.get(TYPING) is not self._typing_cb:
            handlers[TYPING] = self._typing_cb

    def set_presence(self, state):
        self._ensure_typing_handler()
        if state not in VALID_STATES:
            raise AcpError("INTERNAL",
                           f"bad presence state: {state!r}"
                           f" (want one of {VALID_STATES})")
        c = self._c
        now = int(time.time())
        c.store.set_presence(c.peer_id, state, now)
        c.audit.log("presence.set", target=state, result="ok", details={})
        for peer in c.store.list_peers():
            try:
                c._send_plain(PRESENCE, peer["agent_id"], {"state": state})
            except AcpError as e:
                c.audit.log("presence.broadcast_failed",
                            actor=peer["agent_id"], result="failed",
                            details={"error": e.code})

    def get(self, peer_pid):
        self._ensure_typing_handler()
        row = self._c.store.get_presence(peer_pid)
        if row is None:
            return {"agent_id": peer_pid, "status": "unknown",
                    "updated_at": 0}
        return dict(row)

    def list(self):
        self._ensure_typing_handler()
        return [dict(r) for r in self._c.store.list_presence()]

    # ------------------------------------------- typing: sender primitives
    def typing_start(self, peer_pid):
        """Send a direct-chat typing-started frame to a trusted peer.

        The UI/brain owns the heartbeat: re-call every <=5s while the
        user keeps typing (see TYPING_HEARTBEAT).
        """
        self._ensure_typing_handler()
        c = self._c
        c._require_peer(peer_pid)  # unknown/revoked -> raise
        c._send_plain(TYPING, peer_pid,
                      {"typing": True, "context": "direct"})

    def typing_stop(self, peer_pid):
        """Send a direct-chat typing-stopped frame to a trusted peer."""
        self._ensure_typing_handler()
        c = self._c
        c._require_peer(peer_pid)  # unknown/revoked -> raise
        c._send_plain(TYPING, peer_pid,
                      {"typing": False, "context": "direct"})

    def typing_start_group(self, group_id):
        """Fan out a typing-started frame to every current group member."""
        self._ensure_typing_handler()
        self._typing_group(group_id, True)

    def typing_stop_group(self, group_id):
        """Fan out a typing-stopped frame to every current group member."""
        self._ensure_typing_handler()
        self._typing_group(group_id, False)

    def _typing_group(self, group_id, is_typing):
        # GroupChat is imported lazily: presence.py is imported by
        # acp_connector/__init__ at package init time, so a top-level
        # import would risk a cycle.
        from acp_connector.groups import GroupChat
        c = self._c
        gc = GroupChat(c)
        group = gc.get_group(group_id)
        if group is None or c.peer_id not in (group.get("members") or []):
            raise AcpError("POLICY_DENIED",
                           "not a member of group "
                           f"{str(group_id)[:16]}")
        for pid in group["members"]:
            if pid == c.peer_id:
                continue
            try:
                c._send_plain(TYPING, pid,
                              {"typing": is_typing, "context": "group",
                               "context_id": group_id})
            except AcpError as e:
                c.audit.log("typing.send_failed", actor=pid,
                            target=group_id, result="failed",
                            details={"error": e.code})

    # -------------------------------------------- typing: query primitives
    def is_typing(self, peer_pid):
        self._ensure_typing_handler()
        """True if peer_pid has a live direct-chat typing indicator."""
        return self._typing_live(peer_pid, "direct", self._c.peer_id)

    def typing_in_group(self, group_id):
        self._ensure_typing_handler()
        """Peer pids with a live typing indicator in group_id (sorted)."""
        now = time.time()
        with self._typing_lock:
            self._prune_typing_locked(now)
            return sorted(pid for (pid, ctx, cid) in self._typing
                          if ctx == "group" and cid == group_id)

    def typing_peers(self):
        self._ensure_typing_handler()
        """All live (peer_pid, context, context_id) typing triples."""
        now = time.time()
        with self._typing_lock:
            self._prune_typing_locked(now)
            return [(pid, ctx, cid)
                    for (pid, ctx, cid) in self._typing]

    def _typing_live(self, sender_pid, context, context_id):
        now = time.time()
        key = (sender_pid, context, context_id)
        with self._typing_lock:
            exp = self._typing.get(key)
            if exp is None:
                return False
            if exp <= now:
                del self._typing[key]
                return False
            return True

    def _prune_typing_locked(self, now):
        for key, exp in list(self._typing.items()):
            if exp <= now:
                del self._typing[key]

    # ------------------------------------------------------- inbound events
    def handle_presence(self, env, payload):
        self._ensure_typing_handler()
        c = self._c
        state = payload["state"]
        if state not in VALID_STATES:
            raise AcpError("BAD_ENVELOPE",
                           f"bad presence state: {state!r}")
        c.store.set_presence(env["from"], state, int(time.time()))
        c.audit.log("presence.received", actor=env["from"], result="ok",
                    details={"state": state})

    # ------------------------------------------ typing: inbound receiver
    def _on_typing(self, conn, env, payload):
        """V2+ extension handler for the TYPING kind.

        Wired by _ensure_typing_handler onto the connector's V2+
        extension table; _dispatch_plain calls this with
        (conn, env, payload) after signature verification and schema
        validation.
        """
        self.handle_typing(env, payload)

    def handle_typing(self, env, payload):
        self._ensure_typing_handler()
        c = self._c
        sender = env.get("from")
        peer = c.store.get_peer(sender)
        if peer is None or peer["revoked"]:
            # Unknown/untrusted sender: drop silently (no error reply to
            # an unverified sender), audit the attempt.
            c.audit.log("typing.unknown_sender",
                        actor=sender or "unknown", result="denied",
                        details={})
            return
        if not isinstance(payload.get("typing"), bool):
            raise AcpError("BAD_ENVELOPE", "typing must be a bool")
        context = payload.get("context", "direct")
        if context not in TYPING_CONTEXTS:
            raise AcpError("BAD_ENVELOPE",
                           f"bad typing context: {context!r}")
        context_id = payload.get("context_id")
        if context == "group":
            # Group typing must name the group, and the sender must be a
            # current member of it -- this stops typing-spoof frames
            # injected into groups the sender is not in.
            if not isinstance(context_id, str) or not context_id:
                raise AcpError("BAD_ENVELOPE",
                               "group typing requires a group_id")
            if not self._is_group_member(context_id, sender):
                c.audit.log("typing.group_spoof", actor=sender,
                            target=context_id, result="denied",
                            details={})
                return
        else:
            if context_id is not None and \
                    not isinstance(context_id, str):
                raise AcpError("BAD_ENVELOPE",
                               "context_id must be a string")
            if context_id is None:
                # For direct chat the envelope recipient IS the peer
                # being typed to, so context_id may be omitted.
                context_id = env.get("to")
        key = (sender, context, context_id)
        now = time.time()
        with self._typing_lock:
            if payload["typing"]:
                # Log start events only: a heartbeat refresh of a live
                # key (or of a not-yet-pruned expired key treated as a
                # fresh start) is deduped here, never re-logged.
                is_new = (key not in self._typing or
                          self._typing[key] <= now)
                self._typing[key] = now + TYPING_TTL
                if is_new:
                    c.audit.log("typing.received", actor=sender,
                                result="ok",
                                details={"context": context,
                                         "context_id": context_id})
            else:
                self._typing.pop(key, None)

    def _is_group_member(self, group_id, pid):
        from acp_connector.groups import GroupChat  # lazy: see above
        group = GroupChat(self._c).get_group(group_id)
        return bool(group) and pid in (group.get("members") or [])

    def handle_key_rotate(self, env, payload):
        self._ensure_typing_handler()
        c = self._c
        peer_pid = env["from"]
        peer = c.store.get_peer(peer_pid)
        if peer is None or peer["revoked"]:
            raise AcpError("UNKNOWN_SENDER", peer_pid)
        try:
            new_ipub = bytes.fromhex(payload["ipub"])
            new_x_pub = bytes.fromhex(payload["x_pub"])
        except (ValueError, TypeError):
            raise AcpError("BAD_ENVELOPE", "key_rotate keys not hex")
        if len(new_ipub) != 32 or len(new_x_pub) != 32:
            raise AcpError("BAD_ENVELOPE", "key_rotate key wrong length")
        # Signature was verified with the OLD ipub by the dispatch layer.
        c.store.update_peer_keys(peer_pid, new_ipub.hex(), new_x_pub.hex())
        c.audit.log("key.rotated", actor=peer_pid, result="ok",
                    details={"identity_changed":
                             new_ipub.hex() != (peer["ed_pub"] or "")})
