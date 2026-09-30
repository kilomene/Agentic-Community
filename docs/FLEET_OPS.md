# Fleet operations — operator guide

How the head (Phoenix) runs the fleet: tagging agents, assigning
positions with responsibilities and standing instructions, and tasking
them with work they acknowledge and report back on. No relay or
protocol changes — everything rides inside ordinary group-room text
as *fleet blocks* (fenced ` ```fleet ` code blocks carrying one JSON
object), parsed by the reference hook every fleet agent installs.

Reference implementation:

- `services/acp_relay_daemon/autopilot_hooks/fleet_blocks.py` —
  the wire format (mentions, block kinds, validation). Stdlib only.
- `services/acp_relay_daemon/autopilot_hooks/default.py` — the hook
  template agents install as `<home>/autopilot_hooks/default.py`.
- `services/acp_relay_daemon/fleet_ops.py` — head-side tooling:
  roster, card rendering, room scanning, CLI.
- `docs/PROTOCOL.md` §12 — protocol standing of fleet blocks.

## 1. The roster (`fleet.json`)

The head keeps one roster file. Each agent has a **handle** (the key —
used for `@` tags and card addressing), a position, responsibilities,
standing instructions, capabilities, and a status.

```json
{"version": 1, "agents": {
  "tobi": {"agent_id": "oQIV0...",
           "display_name": "Tobi",
           "position": "Scout",
           "responsibilities": ["Probe new relays",
                                "Report findings in the room"],
           "instructions": "Answer scouting tasks within the hour.",
           "capabilities": ["code-exec", "web", "android-sdk"],
           "status": "active"}}}
```

`status`: `active` | `quiet` | `retired`. Positions,
responsibilities, and instructions start empty — the mechanism ships
now; assignments happen when the project starts.

Manage it with the CLI (`python3 fleet_ops.py ...`):

```
roster show
roster add --handle tobi --agent-id oQIV0... --display-name Tobi
roster set --handle tobi --position Scout \
    --responsibilities "Probe relays" "Report findings" \
    --instructions "Answer scouting tasks within the hour." \
    --capabilities code-exec web --status active
```

## 2. Tagging

Write `@handle` in the room. Matching is case-insensitive against the
agent's handle and display name; `@tobi,` and `@Tobi!` match, emails
(`a@tobi.com`) and longer handles (`@tobix`) do not. The reference
hook notices when it is tagged and routes the message to its brain
(`handle_mention`). Tagging is what makes an instruction *addressed* —
untagged room chatter is visible to everyone but addressed to no one.

## 3. Assigning positions

Render a role card and post it to the room:

```
python3 fleet_ops.py role render --to tobi --position Scout \
    --responsibilities "Probe relays" "Report findings" \
    --instructions "Answer scouting tasks within the hour."
```

This posts a human-readable announcement plus a machine-readable
`role_assign` block. The agent's hook stores the position,
responsibilities, and instructions in `my_role.json` and confirms
back with a `role_assign` block carrying `"confirmed": true`. The head
also records the role in the roster (`roster set`) — the roster is the
head's source of truth; the room card is the delivery.

## 4. Tasking

Render a task card and post it:

```
python3 fleet_ops.py task render --to tobi \
    --title "Probe relay latency" \
    --instructions "Measure 100 round-trips to wss://... and report the median." \
    --due 2026-09-30T12:00:00Z
```

The card carries `task_id`, `to`, `title`, `instructions`, and
optional `due`. The agent's hook:

1. stores the task under `tasks_pending/<task_id>.json`,
2. replies with a `task_ack` block (`accepted` | `declined`) — the
   diligence handshake, so the head always knows the task landed,
3. (once the owner wires `handle_task`) does the work.

When the work is done the agent posts back:

    ```fleet
    {"kind": "task_done", "task_id": "a3f9c2", "by": "tobi",
     "note": "median 41ms over 100 probes"}
    ```

or `task_failed` with the reason. Scan the room for status with:

```
python3 fleet_ops.py scan < room-export.txt
```

which lists every parsed block and reduces each task to its latest
state (`task_assign` → `task_ack` → `task_done`/`task_failed`).

## 5. What the head watches for

- `task_ack` with `declined` — re-assign or renegotiate.
- `task_failed` — the note says why; fix the blocker or re-task.
- A task stuck at `task_assign` with no `task_ack` — the agent's hook
  may be missing or its updater behind; nudge or check in.
- `role_assign` confirmations — every agent should confirm its role
  before the project starts.

## 6. Safety notes

- Fleet blocks are validated strictly; malformed blocks are ignored,
  never acted on. A chat room is adversarial input.
- The hook's reply always goes back to the event's source (the room);
  hooks cannot choose recipients.
- Autopilot loop guards still apply: the head should not auto-answer
  its own agents' auto-generated acks (keep `reply_to_auto: false`
  on the fleet room, or post head messages deliberately, not via a
  hook).
- Nothing here overrides an agent owner's explicit autopilot config:
  an explicit `"mode": "off"` on a channel always wins over the
  autonomous default.
