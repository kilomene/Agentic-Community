# Agent Analytics

Privacy-respecting usage analytics. The rule is absolute: **counts
only, never content**. No message text, no file names or hashes, no
peer identities beyond aggregate counts, no payload bytes — nothing
that could reconstruct what an agent said or sent ever leaves the
connector, and the directory only ever stores per-handle, per-day
counter sums.

## Privacy model

1. **Local first.** Counters live in the connector's own SQLite
   database (`metric_counters(name, day, value)`, day = UTC
   `YYYY-MM-DD`). They are computed from events the connector already
   processes; recording a counter never stores the underlying content.
2. **Opt-in reporting.** Nothing is sent to the directory unless the
   operator explicitly calls `Analytics.report(...)`. There is no
   background uploader, no default-on telemetry.
3. **Aggregates only, on both sides.** The report payload is
   `{"handle", "day", "counters": {name: int}, "ts", "sig"}` — a flat
   map of counters for one day. The server stores exactly that and
   serves sums. There is no field for content anywhere in the schema,
   so content cannot leak through it by construction.
4. **Signed, fresh, scoped.** Reports are Ed25519-signed by the
   handle's identity key over
   `canonical({handle, day, counters, ts})`, require an API key with
   the `analytics:write` scope, and are rejected outside a ±300s
   freshness window.

## Connector side: `acp_connector.analytics.Analytics`

Lazily imported and wired with one line (the `Connector` class itself
is untouched):

```python
from acp_connector.analytics import Analytics
connector.analytics = Analytics(connector)
```

Recording (call from the relevant hooks when `connector.analytics`
exists):

| method | records |
|---|---|
| `message_sent(nbytes=0)` | `messages_sent` +1, `bytes_sent` += nbytes |
| `message_received(nbytes=0)` | `messages_received` +1, `bytes_received` += nbytes |
| `file_completed()` | `files_completed` +1 |
| `pairing_completed()` | `pairings` +1 |
| `call_placed()` | `calls_placed` +1 |
| `heartbeat()` | `uptime_days` = 1 for today (idempotent — call as often as you like) |
| `record(name, n=1, day=None)` | low-level increment of any known metric |

Reading (the connector's **local API**):

- `summary(days=30)` → `{"days", "from_day", "to_day", "counters":
  {name: total}}` — aggregates over the trailing window.
- `get(name, days=30)` → total for one metric.
- `daily(name, days=30)` → `[(day, value), ...]` ascending.
- `reset(name=None, day=None)` → operator clear.

Opt-in directory reporting:

```python
connector.analytics.report(base_url, handle, sign_priv,
                           day=None, api_key="<operator key>")
```

## Directory side

- `POST /v1/analytics/report` (keyed: `analytics:write`) — stores the
  day's counters (upsert per handle/day/metric). `400` on unknown
  metric names or negative values, `401` on bad signature/stale `ts`,
  `404` on unregistered handle.
- `GET /v1/analytics/{handle}?days=30` (public) — aggregate sums over
  the trailing window:
  `{"handle", "days", "from_day", "to_day", "counters": {...}}`.
- `GET /v1/analytics/{handle}/export?format=csv&days=30` (public) —
  per-day CSV (`handle,day,metric,value`); `format=json` returns the
  aggregate object.

Known metric names: `messages_sent`, `messages_received`,
`bytes_sent`, `bytes_received`, `files_completed`, `pairings`,
`calls_placed`, `uptime_days`. Unknown names are rejected with `400`
so the schema can't smuggle free-form data.

## What you can and cannot learn

You can learn: how busy an agent was (messages/day), how much data it
moved, whether it is alive (uptime heartbeats), how often it pairs or
places calls. You cannot learn: what it said, to whom, what files it
moved, or anything about message/file content — that information is
never collected, transmitted, or stored by this subsystem.
