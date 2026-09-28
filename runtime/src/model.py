"""Phase 37/38: model output validation + failure classification.

The model proposes; the runtime disposes. This module:
  - validates every model-generated action against a strict schema (38)
  - classifies model failures (timeout, rate_limit, auth_failure…) (37)
"""

# ---- Phase 38: strict action schema ----
ACTION_SCHEMA = {
    "type": "object",
    "required": ["tool", "args"],
    "properties": {
        "tool": {"type": "string",
                 "enum": ["shell", "write_file", "read_file", "mkdir",
                          "http_get", "browser", "acp"]},
        "args": {"type": "object"},
        "op_id": {"type": "string"},
        "verify": {"type": "array"},
    },
}

REQUIRED_ARG_FIELDS = {
    "shell": ["command"],
    "write_file": ["path", "content"],
    "read_file": ["path"],
    "mkdir": ["path"],
    "http_get": ["url"],
    "browser": [],
    "acp": ["op"],
}


def validate_action(action):
    """Returns (ok, errors). Never executes; only validates shape."""
    errors = []
    if not isinstance(action, dict):
        return False, ["action must be an object"]
    for field in ACTION_SCHEMA["required"]:
        if field not in action:
            errors.append(f"missing required field: {field}")
    tool = action.get("tool")
    if tool not in ACTION_SCHEMA["properties"]["tool"]["enum"]:
        errors.append(f"unknown tool: {tool}")
    else:
        args = action.get("args") or {}
        if not isinstance(args, dict):
            errors.append("args must be an object")
        else:
            for req in REQUIRED_ARG_FIELDS.get(tool, []):
                if req not in args:
                    errors.append(f"tool {tool}: missing arg '{req}'")
    if "verify" in action and not isinstance(action["verify"], list):
        errors.append("verify must be a list")
    return (len(errors) == 0), errors


# ---- Phase 37: model failure classification ----
def classify_model_failure(error_text):
    t = str(error_text or "").lower()
    if "timeout" in t or "timed out" in t:
        return "timeout"
    if "rate" in t and "limit" in t or "429" in t:
        return "rate_limit"
    if "auth" in t or "401" in t or "403" in t or "api key" in t:
        return "auth_failure"
    if "json" in t or "malformed" in t or "parse" in t:
        return "malformed_response"
    if "unavailable" in t or "overloaded" in t or "503" in t:
        return "model_unavailable"
    if "context" in t and ("limit" in t or "length" in t or "token" in t):
        return "context_limit"
    return "inference_failure"
