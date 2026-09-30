# Work Ledger — fleet task diligence record

The work ledger is the head-side append-only record of every task
lifecycle event per fleet agent. It answers "what happened to task
X?" and "how diligent is @handle?" — the raw diligence feed for the
office dashboard.

Reference implementation: `services/acp_relay_daemon/work_ledger.py`
(stdlib only). The head wires it in through
`services/acp_relay_daemon/fleet_ops.py` (head-side tooling), and
the CLI lives there too.

## Event types

| event        | meaning                                        |
|--------------|------------------------------------------------|
| `assigned`   | head assigned a task to the agent              |
| `acked`      | agent acknowledged (accepted/declined in note) |
| `in_progress`| agent started work                             |
| `done`       | agent reported completion                      |
| `failed`     | agent reported failure (reason in note)        |
| `blocked`    | task is stuck waiting on something             |

Wire mapping from fleet blocks (see `docs/FLEET_OPS.md`): `task_assign`
→ `assigned`, `task_ack` → `acked`, `task_done` → `done`,
`task_failed` → `failed`. There are no fleet blocks for
`in_progress` / `blocked` today, so those are recorded
programmatically through `WorkLedger.record_event(...)`.

## Schema

SQLite database, default `~/.acp/state/work_ledger.db` (configurable;
tests use temp files and never touch live state).

```sql
CREATE TABLE work_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id    TEXT NOT NULL,
    agent      TEXT NOT NULL,      -- handle, lowercased, no '@'
    event      TEXT NOT NULL,      -- one of the six event types
    ts         REAL NOT NULL,      -- epoch seconds
    detail     TEXT,               -- title / note / failure reason
    dedupe_key TEXT                -- UNIQUE; prevents double-counting
);
CREATE INDEX idx_work_events_task   ON work_events (task_id, id);
CREATE INDEX idx_work_events_agent  ON work_events (agent, id);
CREATE UNIQUE INDEX idx_work_events_dedupe ON work_events (dedupe_key);
```

## Append-only guarantee

The public API is insert + query only:

- `record_event(task_id, agent, event, detail=None, ts=None,
  dedupe_key=None)` — appends one row. Unknown event types raise
  `ValueError`.
- `events_for_task(task_id)` / `events_for_agent(handle)` — history,
  oldest first.
- `summary_for_agent(handle)` — per-agent diligence summary.

There is no update/delete API. The explicit `update()` / `delete()`
stubs exist only to raise `TypeError` ("work ledger is append-only"),
so misuse fails loudly instead of silently.

**Dedupe:** `record_event` accepts an optional `dedupe_key`; a repeat
insert with the same key is skipped (`INSERT OR IGNORE`). The room-scan
hook passes `"assigned:<task_id>"` / `"acked:<task_id>"` /
`"done:<task_id>"` / `"failed:<task_id>"`, so re-scanning overlapping
room exports never double-counts.

## Lifecycle hook points (`fleet_ops.py`)

All workstream H edits in `fleet_ops.py` are delimited by
`# --- work ledger (workstream H) ---` markers.

- **`record_block_events(blocks, ledger)`** — the single transition
  function: takes the oldest-first block list from `scan_text` and
  appends one ledger event per lifecycle block. This is the preferred
  hook point over scattering per-kind edits.
- **`cmd_task_render`** — when the head renders a `task_assign` card,
  an `assigned` event (with the task title) is recorded.
- **`cmd_scan`** — when the head scans room text, every `task_ack` /
  `task_done` / `task_failed` block becomes a ledger event via
  `record_block_events`.
- **Programmatic**: `in_progress` and `blocked` have no block kind;
  record them via `ledger.record_event(...)` whenever the head learns
  of the transition (e.g. from a status message in the room).

## Summary math

`summary_for_agent(handle)` returns counts per event type, `tasks_completed`,
`tasks_failed`, and two latencies:

- `avg_ack_latency_s` — mean over tasks of
  (first `acked` − first `assigned`), tasks with both only.
- `avg_completion_time_s` — mean over completed tasks of
  (first `done` − first `acked`; falls back to first `assigned` when
  the task was never acked).

Single-event tasks contribute no latency. Missing data reports `None`
(rendered as `-` in the CLI).

## CLI reference

```
python3 fleet_ops.py task render --to tobi --title "..." --instructions "..."
    [--db PATH]                      # records an `assigned` event
python3 fleet_ops.py scan [--db PATH] < room-export.txt
                                     # records acked/done/failed events
python3 fleet_ops.py ledger --agent tobi [--db PATH]
    @tobi — work ledger summary
      assigned: 3 / acked: 3 / in_progress: 1 / done: 2 / failed: 1 / blocked: 0
      tasks completed: 2
      tasks failed: 1
      avg ack latency: 42.5s
      avg completion time: 318.0s
python3 fleet_ops.py ledger --task a3f9c2 [--db PATH]
    2026-09-29 23:58:00  @tobi  assigned — Probe relay
    2026-09-29 23:58:41  @tobi  acked — accepted
    2026-09-30 00:04:12  @tobi  done — rtt 40ms
```

`--db` overrides the default `~/.acp/state/work_ledger.db`.
Handles accept an optional leading `@` and are case-insensitive.

## Feeding the office site

The office dashboard consumes the ledger through two stable seams:

1. **Direct SQL read** — `work_events` is plain SQLite at
   `~/.acp/state/work_ledger.db`. Indexes on `(task_id, id)` and
   `(agent, id)` make per-task and per-agent timelines cheap; the
   dashboard can poll `SELECT ... WHERE id > <last_seen>` for a live
   event stream. The DB is never written by anything except
   `record_event`, so reads need no locking beyond SQLite's own.
2. **Python API** — `summary_for_agent` gives the dashboard its
   per-agent cards (counts, completed/failed, ack latency, completion
   time) without the dashboard re-deriving the math.

Because the ledger is append-only, the dashboard can cache rows by
`id` forever — history never changes underneath it.
