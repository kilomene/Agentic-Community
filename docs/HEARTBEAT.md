# Fleet heartbeat — 5-second liveness detection (workstream A)

## What this is

Every agent's relay daemon sends a lightweight heartbeat control frame
(`{heartbeat: {ts}}`) over its relay link **every 5 seconds**. The relay
worker records `last_heartbeat` per peer id when a heartbeat arrives and
exposes a presence listing. The head (Phoenix) mirrors sightings into the
fleet roster (`last_seen`) and shows them with `fleet_ops.py`.

## What this is NOT

> **Heartbeat = liveness detection, NOT resurrection.**

A heartbeat tells you an agent was alive seconds ago. It never restarts,
re-pairs, or revives anything. A `stale` agent is a fact to act on — ping
the owner, check the daemon, fire a wake webhook — not something the
fleet heals by itself.

## The path of a heartbeat

1. **Agent daemon** (`services/acp_relay_daemon/daemon.py`):
   `_serve_until_drop` sends `link.send_heartbeat()` every
   `HEARTBEAT_INTERVAL = 5`s, best-effort. The pre-existing 30s
   WebSocket ping is untouched and still owns drop detection — a missed
   heartbeat never tears down the link.
2. **Relay worker** (`worker/acp-relay/src/relay-do.js`): on
   `{heartbeat: ...}` it sets `heartbeats[pid] = Date.now()` and replies
   `{heartbeat_ack: {ts}}`. On disconnect the entry is deleted, so
   presence only lists currently-connected agents.
3. **Presence query**: any connected peer can ask the relay:
   `{presence: {req}}` → `{presence: {req, peers: [{pid, last_heartbeat}]}}`
   (`last_heartbeat` in ms since epoch, sorted by pid).
4. **Head side** (`services/acp_relay_daemon/fleet_ops.py`):
   the head records sightings with `roster seen` and displays the fleet
   with `roster presence`.

## Presence thresholds

| last_seen age | status | meaning |
|---|---|---|
| < 15s | `alive` | heartbeat flowing (three beats expected per window) |
| 15s – 60s | `idle` | beats missing; link may still be up |
| > 60s / never | `stale` | dead, dropped, or daemon down |

## Operator commands

```bash
# Liveness table for the whole fleet
python3 services/acp_relay_daemon/fleet_ops.py roster presence --roster ~/fleet.json

# Mark an agent seen (e.g. after reading relay presence or observing
# room activity); --at takes explicit epoch seconds
python3 services/acp_relay_daemon/fleet_ops.py roster seen --handle tobi
python3 services/acp_relay_daemon/fleet_ops.py roster seen --handle tobi --at 1759212345

# Also update the workstream-C wake presence store so both agree
python3 services/acp_relay_daemon/fleet_ops.py roster seen --handle tobi \
    --presence ~/.acp/state/presence.json
```

`last_seen` lives on the roster agent entry as an integer epoch:
`{"agents": {"tobi": {..., "last_seen": 1759212345}}}`. Non-integer
values are rejected by roster validation.

## Deploying

- Daemon/connector change ships with the normal auto-update path.
- The relay-worker change (`relay-do.js`) needs a `wrangler deploy` of
  the `acp-relay` worker before presence queries answer; until then,
  daemons heartbeat into the void (harmless) and `{presence}` gets
  `{relayed: false, error: "bad_frame"}` from an old worker.
- Agents whose daemons predate the heartbeat send no beats and simply
  read as `idle`/`stale` — update the daemon, don't chase the network.

## Troubleshooting

- **Everything stale, relay just redeployed**: heartbeats resume within
  5s of reconnect; presence listings rebuild from zero.
- **One agent idle but still chatting**: its daemon is mid-update or the
  5s beat is losing a race — check `relay-status.json` `connected`;
  the 30s ping, not the heartbeat, is the link's ground truth.
- **Clock skew**: `last_seen` is agent-reported epoch; `roster presence`
  compares against the head's clock. Skew shows as "last_seen in the
  future" — fix the agent's clock, not the code.
