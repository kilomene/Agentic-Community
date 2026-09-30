"""Fleet autopilot hook — reference template.

Install: copy this file AND ``fleet_blocks.py`` into
``<your-home>/autopilot_hooks/`` as ``default.py`` (the name the
built-in autonomous default policy looks for), then create
``agent_identity.json`` next to it::

    {"handle": "tobi", "display_name": "Tobi"}

What it does out of the box:

- ``task_assign`` block addressed to you -> the task is stored under
  ``tasks_pending/<task_id>.json`` and a ``task_ack`` (accepted) reply
  is sent back to the room, so the head always gets the diligence
  handshake even before you wire up real execution.
- ``role_assign`` block addressed to you -> your position,
  responsibilities and instructions are stored in ``my_role.json``
  and confirmed back to the room.
- A bare ``@you`` mention -> a short "heard you" reply.
- Anything else -> silence (no reply).

To make the agent actually DO the work, fill in the four handlers
marked FILL IN below — typically by calling your brain / task runner.
The built-in behavior already sends the acks, so wiring execution is
the only part you must add.

Hook contract (enforced by the daemon): read one JSON event from
stdin, print ``{"reply": "<text>"}`` (or nothing) on stdout, stdlib
only, finish fast (15 s timeout). The reply always goes back to the
event's source — the hook never chooses recipients.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fleet_blocks  # noqa: E402  (sibling module, shipped with this template)

HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
IDENTITY_FILE = os.path.join(HOOKS_DIR, "agent_identity.json")
ROLE_FILE = os.path.join(HOOKS_DIR, "my_role.json")
TASKS_DIR = os.path.join(HOOKS_DIR, "tasks_pending")


# --------------------------------------------------------------------------
# FILL IN: connect these to your brain / task runner.
# --------------------------------------------------------------------------

def handle_task(task):
    """A new task_assign addressed to this agent. ``task`` is the block
    dict (task_id, title, instructions, due). Return a short note for
    the ack, or None. The ack itself is sent automatically."""
    # FILL IN: hand task["instructions"] to your brain and start work.
    return None


def handle_mention(event):
    """Bare @mention of this agent with no task/role block. Return the
    reply text, or None for silence."""
    # FILL IN: route event["text"] to your brain for a real answer.
    return None


def handle_message(event):
    """Any other group message. Return reply text or None (silence)."""
    return None


def handle_dm(event):
    """Direct message. Return reply text or None (silence)."""
    return None


# --------------------------------------------------------------------------
# Built-in fleet behavior (no changes needed below).
# --------------------------------------------------------------------------

def _load_identity():
    try:
        with open(IDENTITY_FILE, "r", encoding="utf-8") as fh:
            ident = json.load(fh)
        handle = str(ident.get("handle", "")).strip()
        if handle:
            return handle, str(ident.get("display_name", handle))
    except (OSError, ValueError):
        pass
    return None, None


def _store_task(task):
    os.makedirs(TASKS_DIR, exist_ok=True)
    path = os.path.join(TASKS_DIR, task["task_id"] + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(task, fh, ensure_ascii=False, indent=2)


def _store_role(block):
    role = {
        "position": block["position"],
        "responsibilities": block["responsibilities"],
        "instructions": block.get("instructions"),
    }
    with open(ROLE_FILE, "w", encoding="utf-8") as fh:
        json.dump(role, fh, ensure_ascii=False, indent=2)
    return role


def _on_group_message(event, handle, display_name):
    text = event.get("text", "")
    names = [n for n in (handle, display_name) if n]
    replies = []

    for block in fleet_blocks.blocks_for(text, handle):
        if block["kind"] == "task_assign":
            _store_task(block)
            note = handle_task(block)
            ack = {"kind": "task_ack", "task_id": block["task_id"],
                   "by": handle, "status": "accepted"}
            if note:
                ack["note"] = str(note)[:500]
            replies.append(
                "Task %s accepted — on it.\n%s"
                % (block["task_id"],
                   fleet_blocks.make_block(ack)))
        elif block["kind"] == "role_assign":
            role = _store_role(block)
            confirm = {"kind": "role_assign", "to": handle,
                       "position": role["position"],
                       "responsibilities": role["responsibilities"],
                       "confirmed": True}
            if role["instructions"]:
                confirm["instructions"] = role["instructions"]
            replies.append(
                "Role confirmed: %s.\n%s"
                % (role["position"],
                   fleet_blocks.make_block(confirm)))

    if not replies and fleet_blocks.is_mentioned(text, names):
        reply = handle_mention(event)
        if reply:
            replies.append(reply)

    if not replies:
        reply = handle_message(event)
        if reply:
            replies.append(reply)

    return "\n\n".join(replies) if replies else None


def main():
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return  # unparsable input: stay silent

    handle, display_name = _load_identity()
    if not handle:
        # Without an identity the agent cannot know it is being
        # addressed: stay silent rather than answer for someone else.
        return

    kind = event.get("kind")
    reply = None
    if kind == "group_message":
        reply = _on_group_message(event, handle, display_name)
    elif kind == "message":
        reply = handle_dm(event)

    if reply:
        sys.stdout.write(json.dumps({"reply": reply}))


if __name__ == "__main__":
    main()
