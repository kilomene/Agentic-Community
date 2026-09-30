# Fleet Task Board (workstream E)

Head-side SQLite board tracking every task the head assigns in the fleet
room: who owns it, what state it is in, and what it is blocked on.

- Module: `services/acp_relay_daemon/fleet_board.py` (stdlib only)
- Wiring: delimited `# --- task board (workstream E) ---` blocks in
  `services/acp_relay_daemon/fleet_ops.py`
- Database: `~/.acp/state/fleet_board.db` by default
  (`ACP_STATE_DIR` env var overrides the state dir);
  `--board-db PATH` overrides per invocation (tests use tmp paths)

## Task states

```
open -> assigned -> acked -> in_progress -> done | failed
                             \-> blocked -/          (waiting on deps)
```

`blocked` is a waiting state, not a terminal one. Terminal states are
`done` and `failed` — nothing leaves them without an explicit operator
override.

## Operator walkthrough

### 1. Create a task

Rendering a task card records it on the board automatically (state
`assigned`, same id as the card):

```bash
cd services/acp_relay_daemon
python3 fleet_ops.py task render --to tobi --title "Probe relay latency" \
    --instructions "Measure round-trip to the relay, report in the room." \
    --task-id a3f9c2
# post the printed card into the fleet room
```

### 2. Add a dependency

```bash
python3 fleet_ops.py board dep b7e210 a3f9c2
# dep added: b7e210 blocked by a3f9c2 (state=blocked)
```

Task `b7e210` moves to `blocked` until `a3f9c2` is done. Adding a dep
whose blocker is already `done` does not block. Self-deps and cycles are
rejected.

### 3. What happens on done

Feed room text through `scan` (as usual). When the scan sees a
`task_done` block, the board marks the task `done`; every dependent whose
blockers are now **all done** is unblocked (back to its pre-block state)
and its assignee is notified **in the room**:

```bash
python3 fleet_ops.py scan < room-export.txt
# board: unblock notify queued for @tobi (1 task(s))
```

The notify is queued as a JSON file in `$ACP_STATE_DIR/outbox/` — the
daemon drains it through its own relay link within ~30s. The board never
sends via the `acp` CLI (that would steal the daemon's relay socket).
Re-scanning the same room text is a no-op: no state churn, no duplicate
notifies.

### 4. Failed blockers (documented choice)

A **failed** blocker never auto-unblocks its dependents — they stay
`blocked` and never appear as ready. The head must intervene:

- re-run the blocker as a new task and re-point the dep, or
- drop the dep in Python: `FleetBoard(db).remove_dependency(task, blocker)`, or
- force it: `FleetBoard(db).set_state(task, "assigned", force=True)`

The board will never silently unblock work on top of a failure.

## CLI reference

```bash
python3 fleet_ops.py board list [--state S] [--assignee H] [--board-db P]
python3 fleet_ops.py board show <id> [--board-db P]
python3 fleet_ops.py board dep <id> <blocker-id> [--board-db P]
python3 fleet_ops.py board states [--board-db P]
```

- `list` — tasks ordered by due date, with state, assignee, blockers.
- `show` — full detail: blockers, dependents, timestamps.
- `dep` — add a dependency (`<id>` blocked by `<blocker-id>`).
- `states` — counts per state plus a one-line summary per task.

`task render` and `scan` also accept `--board-db`.

## Room-scan mapping

| Room block   | Board effect                                              |
|--------------|-----------------------------------------------------------|
| `task_assign`| create entry (`assigned`), if not already recorded        |
| `task_ack` accepted | `assigned`/`open` -> `acked` (stays `blocked` if deps unmet) |
| `task_ack` declined | -> `failed`                                         |
| `task_done`  | -> `done`; dependents with all blockers done are unblocked + notified in the room |
| `task_failed`| -> `failed`; dependents **stay blocked** (see above)      |

## Python API (fleet_board.FleetBoard)

`create`, `assign`, `set_state` (returns True on real change; `force`
for operator override), `add_dependency`, `remove_dependency`, `list`,
`get`, `dependents`, `ready_tasks` (non-terminal tasks whose blockers
are all done), `unblock_check`, `on_blocker_done` (unblocks dependents,
returns the newly-unblocked task dicts for notify).

Tests: `tests/test_fleet_board.py` (19 tests; tmp dbs only, never the
live `~/.acp/state`).
