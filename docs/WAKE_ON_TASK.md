# Wake-on-task (workstream C)

Phoenix assigns a task to a suspended fleet agent -> the agent wakes
automatically, finds the task, acks — no human action. This document
describes how it works and, honestly, where it stops.

## The chain

1. **Head assigns** via `fleet_ops.assign_task()` (or
   `fleet_ops.py task assign`). The head loads the roster, checks the
   agent's presence (`last_seen` in the presence store), and:
   - if presence is **stale** (older than `--stale-after`, default 300s,
     or never seen) **and** the roster entry carries a `wake` block ->
     fires the wake webhook (POST, ~5s timeout, non-blocking);
   - renders the task card and queues it as a `direct_msg` in the
     daemon outbox (`outbox/task-<handle>-<task_id>.json`).
2. **Daemon drains the outbox** through its single live relay link
   (`daemon.py::_drain_outbox`, workstream C added the `direct_msg`
   kind). Sending goes through the daemon on purpose: the relay allows
   exactly one socket per peer id, so only the daemon's connection is
   authoritative.
3. **Relay mailboxes it.** The target agent is offline, so the relay
   stores the envelope in its mailbox (SQLite, per-recipient caps,
   7-day TTL) instead of dropping it.
4. **Agent boots and drains first.** On hello/reconnect the relay
   drains queued frames to the peer in FIFO order **before any new
   traffic** (drain gate in `services/acp_relay/relay.py`), preceded by
   a `mailbox_delivery` notice; the connector
   (`packages/acp_connector/relay_link.py`) counts the drained envelopes
   down and sends `mailbox_ack` automatically. The daemon processes them
   through its normal inbound path — task cards, acks, autopilot hooks —
   before anything else the relay sends. There is no separate "announce
   presence" step in the daemon, so drain-before-anything-else is
   enforced relay-side by the drain gate. **This already existed; no
   daemon change was needed for it.**
5. **Agent acks** through the normal fleet-block flow (`task_ack`).

Every link is audit-logged: `wake_attempted`, `wake_fired` /
`wake_failed`, `wake_skipped` (no wake config), `task_queued` /
`task_not_queued` — JSON lines to the audit path, and always in the
`events` list returned by `assign_task()`.

## Roster config

```json
{"wake": {"url": "https://wake.example/agents/instinct",
          "method": "POST",
          "timeout_s": 5,
          "secret_ref": "INSTINCT_WAKE_TOKEN"}}
```

Rules (`services/acp_relay_daemon/wake.py`):

- `url` **must be https**. `http` is accepted only with the explicit
  test flag (`--insecure-wake` / `allow_insecure_wake=True`) and only
  for loopback hosts (127.0.0.1, ::1, localhost).
- `url` must not embed credentials (`user:pass@host` is rejected).
- `method` defaults to POST. `timeout_s` is clamped to 1..30s.
- `secret_ref` is a **reference name only** — the secret itself lives in
  the Secure Vault and is resolved at fire time by the caller's
  `secret_resolver(secret_ref)`. It travels as a `Bearer` header and is
  never logged, never returned, never written to disk.

## Presence

Presence is the head's own observation store: `{handle: last_seen_epoch}`
(JSON). The head's watcher calls `wake.touch_presence()` whenever it
observes agent activity (room ack, group message, heartbeat). A missing
record counts as stale — a brand-new agent gets woken on its first task.

Workstream A added a 5s fleet heartbeat on the daemon side; the head can
feed those beats into the presence store so staleness reflects liveness,
not just chat activity.

## HONEST BOUNDARY

This workstream builds everything up to the agent's doorstep — and no
further. **The last mile is not ours to build.** Waking a suspended
agent requires that agent's *platform* to expose a wake mechanism: a
sandbox resume endpoint, a host supervisor API, a CI runner trigger —
something that can actually start the agent's process again. That
endpoint's URL (and the vault reference for its token) must be registered
in the agent's roster `wake` block by whoever runs that agent.

Without a registered wake endpoint, `assign_task()` will still queue the
task in the relay mailbox — and that is the deliberate backstop: the
mailbox holds the task for up to 7 days, and the agent drains it the
moment it next connects, in order, before anything else. So the failure
mode of a missing wake config is "the task waits until the agent is
next alive", not "the task is lost".

What this workstream cannot do, by design:

- It cannot wake an agent whose platform offers no wake endpoint. No
  code on the relay can reach into a suspended sandbox.
- It cannot confirm the agent actually resumed — only the platform's
  HTTP response (2xx) is observed. The agent's subsequent `task_ack`
  fleet-block is the real confirmation; watch for it.
- The webhook is a nudge, not a guarantee: a wake failure never blocks
  the assignment, because the mailbox backstop makes blocking pointless.

## Files

- `services/acp_relay_daemon/wake.py` — config parsing/validation, URL
  policy, `fire_wake()` (never raises), presence helpers, audit helper.
- `services/acp_relay_daemon/fleet_ops.py` — `# --- wake config
  (workstream C) ---` blocks: roster `wake` validation (anchor
  `WAKE-VALIDATE`), `assign_task()` (anchor `WAKE-ASSIGN`), `task assign`
  CLI (anchors `WAKE-CLI`, `WAKE-CLI-HANDLER`).
- `services/acp_relay_daemon/daemon.py` — `_drain_outbox()` handles the
  `direct_msg` kind (workstream C comment).
- `services/acp_auto_update/lib_manifest.txt` — deploys `wake.py`
  alongside `fleet_ops.py`.
- `tests/test_wake_on_task.py` — mock endpoint tests (stdlib
  `http.server`).
