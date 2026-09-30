"""Fleet message blocks — the shared wire format for fleet operations.

Every fleet agent (and the head) speaks the same tiny protocol inside
ordinary chat text, so tasking works over any transport that carries
text — group rooms, DMs, anything.

A *fleet block* is a fenced code block whose info string is ``fleet``
containing a single JSON object::

    ```fleet
    {"kind": "task_assign", "task_id": "a3f9c2", "to": "tobi",
     "title": "Probe relay latency",
     "instructions": "Measure round-trip ..."}
    ```

Block kinds:

- ``task_assign`` — head -> agent. Fields: ``task_id`` (str),
  ``to`` (handle), ``title`` (str), ``instructions`` (str),
  ``due`` (optional ISO-8601 str).
- ``task_ack`` — agent -> head. Fields: ``task_id``, ``by`` (handle),
  ``status`` (``"accepted"`` | ``"declined"``), ``note`` (optional).
- ``task_done`` / ``task_failed`` — agent -> head. Fields: ``task_id``,
  ``by``, ``note`` (optional).
- ``role_assign`` — head -> agent. Fields: ``to`` (handle),
  ``position`` (str), ``responsibilities`` (list of str),
  ``instructions`` (optional str).

Mentions: ``@handle`` tokens in the surrounding text. Matching is
case-insensitive against the agent's handle and display name.

Stdlib only. Safe to vendor into a hook directory.
"""

import json
import re

BLOCK_LANG = "fleet"

# ```fleet ... ``` — info string may carry trailing whitespace; the JSON
# body must be a single object. Non-greedy so several blocks per message
# each parse independently.
_BLOCK_RE = re.compile(
    r"```fleet[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE
)

# @handle — letters, digits, underscore, hyphen; must not be part of an
# email address (no match when preceded by a word char or '.'), and must
# not be followed by a word char (so "@tobi!" and "@tobi," match, but
# "@tobix" does not match handle "tobi").
_MENTION_RE = re.compile(r"(?<![\w.])@([\w-]{1,64})(?![\w-])")

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_VALID_KINDS = {
    "task_assign",
    "task_ack",
    "task_done",
    "task_failed",
    "role_assign",
}

# Required fields per block kind (beyond "kind" itself).
_REQUIRED = {
    "task_assign": ("task_id", "to", "title", "instructions"),
    "task_ack": ("task_id", "by", "status"),
    "task_done": ("task_id", "by"),
    "task_failed": ("task_id", "by"),
    "role_assign": ("to", "position", "responsibilities"),
}


def make_block(payload):
    """Render a fleet block (dict) as message text. Raises ValueError on
    a payload that fails validation."""
    validate_block(payload)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return "```fleet\n%s\n```" % body


def extract_blocks(text):
    """Return a list of validated block dicts found in *text*.

    Malformed blocks (bad JSON, unknown kind, missing fields) are
    skipped silently — a chat room is adversarial input.
    """
    blocks = []
    for m in _BLOCK_RE.finditer(text or ""):
        try:
            payload = json.loads(m.group(1))
        except (ValueError, TypeError):
            continue
        if validate_block(payload, _raise=False):
            blocks.append(payload)
    return blocks


def validate_block(payload, _raise=True):
    """True when *payload* is a well-formed fleet block. With
    ``_raise=False`` returns False instead of raising."""
    def fail(reason):
        if _raise:
            raise ValueError("invalid fleet block: %s" % reason)
        return False

    if not isinstance(payload, dict):
        return fail("not an object")
    kind = payload.get("kind")
    if kind not in _VALID_KINDS:
        return fail("unknown kind %r" % (kind,))
    for field in _REQUIRED[kind]:
        if field not in payload or payload[field] is None:
            return fail("missing field %r for kind %r" % (field, kind))
    if "task_id" in payload and not _TASK_ID_RE.match(
            str(payload["task_id"])):
        return fail("bad task_id %r" % (payload["task_id"],))
    if kind == "task_ack" and payload["status"] not in (
            "accepted", "declined"):
        return fail("bad ack status %r" % (payload["status"],))
    if kind == "role_assign" and not isinstance(
            payload["responsibilities"], list):
        return fail("responsibilities must be a list")
    for f in ("to", "by", "title", "position"):
        if f in payload and not isinstance(payload[f], str):
            return fail("field %r must be a string" % f)
    return True


def find_mentions(text):
    """Return the de-duplicated @handles mentioned in *text*, lower-cased,
    in order of first appearance."""
    seen = []
    for m in _MENTION_RE.finditer(text or ""):
        handle = m.group(1).lower()
        if handle not in seen:
            seen.append(handle)
    return seen


def is_mentioned(text, names):
    """True when *text* @-mentions any of *names* (handle or display
    name, case-insensitive)."""
    wanted = {str(n).lower() for n in names if n}
    return any(h in wanted for h in find_mentions(text))


def blocks_for(text, handle):
    """Blocks in *text* addressed to *handle* (task_assign / role_assign
    whose ``to`` matches, case-insensitive)."""
    want = str(handle).lower()
    return [b for b in extract_blocks(text)
            if b["kind"] in ("task_assign", "role_assign")
            and str(b.get("to", "")).lower() == want]


def latest_status(blocks):
    """Reduce a sequence of task blocks to ``{task_id: (kind, block)}``
    keeping the newest occurrence of each task id. Order of *blocks*
    is oldest-first."""
    state = {}
    for b in blocks:
        if b["kind"] in ("task_assign", "task_ack",
                         "task_done", "task_failed"):
            state[str(b["task_id"])] = (b["kind"], b)
    return state
