"""Phase 59: capability-based permissions.

No task gets unrestricted access. Capabilities are granted per task by the
scheduler (or a policy-authorized granter) and stored in the DB. The tool
executor consults this module before running anything.

Capabilities:
  FILES_READ, FILES_WRITE, SHELL_EXECUTE, PROCESS_CONTROL,
  NETWORK_ACCESS, BROWSER_CONTROL, DATABASE_READ, DATABASE_WRITE,
  DEPLOY, SYSTEM_SERVICE_CONTROL, ACP_NETWORK

ACP_NETWORK gates the `acp` tool (pairing, messaging, file transfer over
the ACP network). It is deliberately separate from NETWORK_ACCESS
(generic HTTP): talking to other agents is its own trust decision.

The LLM/model can never grant itself capabilities. Escalation requires
explicit policy authorization (out-of-band token, same boundary as
protected config writes).
"""
import time

CAPABILITIES = {
    "FILES_READ",
    "FILES_WRITE",
    "SHELL_EXECUTE",
    "PROCESS_CONTROL",
    "NETWORK_ACCESS",
    "BROWSER_CONTROL",
    "DATABASE_READ",
    "DATABASE_WRITE",
    "DEPLOY",
    "SYSTEM_SERVICE_CONTROL",
    "ACP_NETWORK",
}

# tool -> capability required to run it
TOOL_CAPABILITY = {
    "shell": "SHELL_EXECUTE",
    "write_file": "FILES_WRITE",
    "read_file": "FILES_READ",
    "mkdir": "FILES_WRITE",
    "http_get": "NETWORK_ACCESS",
    "browser": "BROWSER_CONTROL",
    "acp": "ACP_NETWORK",
}


def check(store, task_id, capability):
    """Returns (allowed, reason)."""
    if capability not in CAPABILITIES:
        return False, f"unknown capability: {capability}"
    if store.capability_has(task_id, capability):
        return True, "granted"
    return False, f"capability denied: {capability}"


def check_tool(store, task_id, tool):
    need = TOOL_CAPABILITY.get(tool)
    if need is None:
        return False, f"unknown tool: {tool}"
    return check(store, task_id, need)


def grant(store, task_id, tool, ttl_s=None, granted_by="scheduler"):
    """Grant the capability a tool needs, with an optional TTL (seconds).
    ttl_s=0 means already expired."""
    need = TOOL_CAPABILITY.get(tool)
    if need is None:
        return False, f"unknown tool: {tool}"
    store.capability_grant(task_id, need, granted_by=granted_by,
                           ttl_s=ttl_s)
    return True, f"granted {need} for {tool}"


def grant_all_basic(store, task_id, tools, ttl_s=None, journal=None):
    """Grant exactly the tools in `tools` — the task's spec-declared set.
    Anything not in this set is denied at execution time."""
    granted = []
    for tool in sorted(tools):
        ok, _ = grant(store, task_id, tool, ttl_s=ttl_s)
        if ok:
            granted.append(tool)
    if journal:
        journal("CAPS_GRANTED", task_id=task_id, tools=granted)
    return granted


def revoke(store, task_id, tool, journal=None):
    """Revoke the capability a tool needs."""
    need = TOOL_CAPABILITY.get(tool)
    if need is None:
        return False, f"unknown tool: {tool}"
    store.capability_revoke(task_id, need)
    if journal:
        journal("CAP_REVOKED", task_id=task_id, tool=tool)
    return True, f"revoked {need} for {tool}"


def request_escalation(store, task_id, tool, auth_token=None, journal=None):
    """Escalate to a tool whose capability is escalation-gated.
    Requires an out-of-band auth token; the model can never self-escalate."""
    need = TOOL_CAPABILITY.get(tool)
    if need is None:
        return False, f"unknown tool: {tool}"
    return escalate(store, task_id, need, auth_token=auth_token,
                    journal=journal)


def escalate(store, task_id, capability, auth_token=None, journal=None):
    """Capability escalation: requires explicit policy authorization.
    The model can never do this on its own."""
    if capability not in CAPABILITIES:
        return False, f"unknown capability: {capability}"
    if auth_token is None:
        if journal:
            journal("CAP_ESCALATION_REFUSED", task_id=task_id,
                    capability=capability, reason="no auth token")
        return False, (f"capability escalation refused (no auth token): "
                       f"{capability}")
    store.capability_grant(task_id, capability, granted_by="policy:human")
    if journal:
        journal("CAP_ESCALATED", task_id=task_id, capability=capability,
                by="policy:human")
    return True, "escalated with policy authorization"
