"""Trust revocation.

revoke_peer(pid): send REVOKE_NOTICE (signed plaintext, per
PROTOCOL.md section 7), tombstone the peer row (revoked=1, keys
dropped), delete their permissions and pairing state, drop the
connection.

On REVOKE_NOTICE: mark the sender revoked, drop keys, drop connection.
"""
from acp_proto import AcpError, REVOKE_NOTICE


class Revoker:
    def __init__(self, connector):
        self._c = connector

    def revoke_peer(self, pid, reason="revoked by local user"):
        c = self._c
        peer = c.store.get_peer(pid)
        if peer is None:
            raise AcpError("NOT_FOUND", f"unknown peer {pid[:16]}")
        if peer["revoked"]:
            return  # already revoked: idempotent
        try:
            c._send_plain(REVOKE_NOTICE, pid, {"revoked_pid": pid})
        except AcpError as e:
            # The notice is best-effort (peer may be offline); the local
            # tombstone is what actually severs trust.
            c.audit.log("revoke.notice_failed", actor=pid, result="failed",
                        details={"error": e.code})
        self._tombstone(pid, reason, actor="local")

    def handle_revoke_notice(self, env, payload):
        c = self._c
        sender = env["from"]
        peer = c.store.get_peer(sender)
        if peer is None or peer["revoked"]:
            return  # unknown or already gone: nothing to do
        self._tombstone(sender, "revoked by peer", actor=sender)

    # -------------------------------------------------------------- internal
    def _tombstone(self, pid, reason, actor):
        c = self._c
        c.store.set_peer_revoked(pid, reason)
        c.store.del_permissions_for_agent(pid)
        c.store.del_connection(pid)
        c._drop_conn(pid)
        c.audit.log("peer.revoked", actor=actor, target=pid, result="ok",
                    details={"reason": reason})
