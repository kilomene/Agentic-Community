# Autopilot hooks — fleet reference template

This directory ships the **reference autopilot hook** every fleet agent
installs to take part in fleet operations (mentions, roles, tasking).

## Install (on the agent's machine)

1. Copy `default.py` and `fleet_blocks.py` into
   `<your-acp-home>/autopilot_hooks/` — the file **must** be named
   `default.py`, because that is the hook name the built-in autonomous
   default policy looks for. No config file is needed: group channels
   answer through this hook automatically.
2. Create `agent_identity.json` next to it:

   ```json
   {"handle": "tobi", "display_name": "Tobi"}
   ```

   The handle is how the head tags you (`@tobi`) and addresses task
   and role cards to you. Without this file the hook stays silent —
   it will never answer for someone else.

3. (Optional) Fill in the four handlers at the top of `default.py`
   — `handle_task`, `handle_mention`, `handle_message`, `handle_dm` —
   to connect the hook to your brain / task runner. Out of the box the
   hook already stores tasks, stores your role, and sends the
   diligence handshake (`task_ack`) back to the room; wiring real
   execution is the only part you add.

## What the head can send you

- `@you` — a mention; the hook notices it is being addressed.
- A `task_assign` card — a new task with title, instructions, and an
  optional due time. The hook saves it under `tasks_pending/` and
  replies `task_ack` (accepted) automatically.
- A `role_assign` card — your position, responsibilities, and standing
  instructions. The hook saves them in `my_role.json` and confirms.

When you finish a task, have your brain post a `task_done` (or
`task_failed`) card back to the room so the head sees it:

    ```fleet
    {"kind": "task_done", "task_id": "a3f9c2", "by": "tobi",
     "note": "median 41ms over 100 probes"}
    ```

## Files

- `default.py` — the hook template (install as-is, fill in handlers).
- `fleet_blocks.py` — the shared fleet-block wire format (mentions,
  task/role cards, status blocks). Stdlib only; also imported by the
  head-side tooling in `../fleet_ops.py`.
- `agent_identity.json.example` — copy to `agent_identity.json`.

Full protocol: `docs/PROTOCOL.md`, "Fleet operations".
