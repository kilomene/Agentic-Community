"""Capability permissions: explicit grants, default deny.

Pairing grants a default set (send_message, send_file, read_profile).
Everything else must be granted explicitly. Denials raise
AcpError(POLICY_DENIED) and are audit-logged.
"""
import time

from acp_proto import AcpError

PERMS = (
    "read_profile",
    "send_message",
    "send_file",
    "family_read",
    "family_write",
    "project_read",
    "project_write",
    "task_assign",
)

# Granted automatically when a pairing completes.
DEFAULT_PAIRING_GRANTS = ("send_message", "send_file", "read_profile")


class Permissions:
    def __init__(self, store, audit):
        self._store = store
        self._audit = audit

    def grant(self, agent_id, scope, granted_by="local", context=None,
              expires_at=None):
        if scope not in PERMS:
            raise AcpError("INTERNAL", f"unknown permission scope: {scope}")
        self._store.set_permission(agent_id, scope, True, context,
                                   granted_by, expires_at)
        self._audit.log("permission.granted", actor=granted_by,
                        target=f"{agent_id}:{scope}", result="ok",
                        details={"scope": scope})

    def revoke(self, agent_id, scope):
        self._store.del_permission(agent_id, scope)
        self._audit.log("permission.revoked", actor="local",
                        target=f"{agent_id}:{scope}", result="ok",
                        details={"scope": scope})

    def revoke_all(self, agent_id):
        self._store.del_permissions_for_agent(agent_id)
        self._audit.log("permission.revoked_all", actor="local",
                        target=agent_id, result="ok")

    def has(self, agent_id, scope):
        """Boolean check, no audit, no raise. Expired grants count as denied."""
        row = self._store.get_permission(agent_id, scope)
        if not row or not row["granted"]:
            return False
        if row["expires_at"] and int(time.time()) > int(row["expires_at"]):
            self._store.del_permission(agent_id, scope)
            return False
        return True

    def check(self, agent_id, scope):
        """Raise AcpError(POLICY_DENIED) (+ audit) unless granted."""
        if scope not in PERMS:
            raise AcpError("INTERNAL", f"unknown permission scope: {scope}")
        if self.has(agent_id, scope):
            return True
        self._audit.log("permission.denied", actor=agent_id,
                        target=scope, result="denied",
                        details={"scope": scope})
        raise AcpError("POLICY_DENIED",
                       f"{agent_id[:16]} lacks '{scope}'")

    def default_pairing_grants(self, agent_id):
        for scope in DEFAULT_PAIRING_GRANTS:
            self._store.set_permission(agent_id, scope, True, None,
                                       "pairing", None)
        self._audit.log("permission.pairing_defaults", actor="local",
                        target=agent_id, result="ok",
                        details={"granted": list(DEFAULT_PAIRING_GRANTS)})

    def list(self, agent_id):
        return self._store.list_permissions(agent_id)
