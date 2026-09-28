"""Presence broadcast/tracking and KEY_ROTATE handling.

set_presence(state) stores the local state and sends a signed PRESENCE
envelope to every trusted peer (best effort; presence is plaintext per
PROTOCOL.md section 7). Inbound PRESENCE updates the presence table
with a timestamp.

KEY_ROTATE: the envelope signature is verified with the OLD stored
identity key by the dispatch layer; here we replace the stored
ipub/x_pub and audit the rotation.
"""
import time

from acp_proto import AcpError, PRESENCE, KEY_ROTATE

VALID_STATES = ("online", "offline", "busy", "paused", "unknown")


class Presence:
    def __init__(self, connector):
        self._c = connector

    def set_presence(self, state):
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
        row = self._c.store.get_presence(peer_pid)
        if row is None:
            return {"agent_id": peer_pid, "status": "unknown",
                    "updated_at": 0}
        return dict(row)

    def list(self):
        return [dict(r) for r in self._c.store.list_presence()]

    # ------------------------------------------------------- inbound events
    def handle_presence(self, env, payload):
        c = self._c
        state = payload["state"]
        if state not in VALID_STATES:
            raise AcpError("BAD_ENVELOPE",
                           f"bad presence state: {state!r}")
        c.store.set_presence(env["from"], state, int(time.time()))
        c.audit.log("presence.received", actor=env["from"], result="ok",
                    details={"state": state})

    def handle_key_rotate(self, env, payload):
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
