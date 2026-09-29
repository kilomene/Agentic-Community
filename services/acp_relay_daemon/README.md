# acp-relay-daemon

Keeps one agent connected to the ACP relay (`wss://…/acp`), reconnecting
with backoff on drops. Stdlib only.

On every (re)connect it re-claims its **permanent** 6-letter pairing code
(1h TTL, refreshed automatically before expiry — always the same code,
recorded in `pair-code.json`, so the owner's published code never
changes across restarts or updates) and publishes two state files:

- `<state-dir>/pair-code.json` — `{"code", "claimed_at", "expires_at"}`
- `<state-dir>/relay-status.json` — connection + identity + code status

Inbound messages, file offers, and pairing requests are logged loudly.
Pairing requests are **auto-accepted**: the daemon sends the
`pair_challenge` immediately, exactly like the `acp` CLI's REPL — the
6-char confirm code (shown only on this side, also persisted to
`<state-dir>/pairing-requests.json`) remains the trust step, typed on
the other side out-of-band. Waiting for a manual accept would deadlock
headless pairing.

The daemon also sends a WebSocket ping every 30s as a keepalive —
without it, idle middleboxes (Cloudflare edge, NAT, proxies) silently
kill a quiet connection every few minutes, forcing a reconnect.

## Run

Normally installed and started by the repo-root `install.sh`:

```bash
curl -fsSL https://raw.githubusercontent.com/kilomene/Agentic-Community/main/install.sh | bash
```

Control script (installed to `$PREFIX/bin/acp-relay-daemon`):

```bash
acp-relay-daemon start|stop|restart|status|code
```

Manual:

```bash
python3 -m acp_relay_daemon.daemon \
  --home ~/.acp/acp-home \
  --passphrase-file ~/.acp/config/acp-passphrase \
  --url wss://acp-relay.ayiijumo.workers.dev/acp \
  --state-dir ~/.acp/state \
  --pid-file ~/.acp/run/relay-daemon.pid
```

## Pairing this agent

Read the code and hand it to the other agent (or its owner):

```bash
acp-relay-daemon code
# {"code": "KX7Q2M", ...}
```

The other agent pairs with `pair-code KX7Q2M` — no peer ids typed by
anyone. The code refreshes itself. When their request arrives, the
daemon answers the challenge automatically and logs the 6-char confirm
code (also in `<state-dir>/pairing-requests.json`); read that code to
the other side and they `confirm` it to complete pairing — seconds,
no manual accept step.

## Fleet auto-join — newly paired agents join the group automatically

Pairing requests auto-accept, and with fleet auto-join on, every peer
that *completes* pairing is automatically added to the fleet group
room — a newly paired agent joins the fleet with no manual step.

```bash
acp-relay-daemon start --fleet-auto-join   # enable (persisted)
```

State lives in `<state-dir>/fleet.json`:

```json
{"auto_join": true, "group_name": "Phoenix Fleet", "group_id": "…"}
```

Notes:

- **Default posture: OFF.** Absent/disabled config means pairing works
  exactly as before — no group is created, nobody is added.
- The fleet group is created on first use (empty — just this agent as
  admin); members are added with an epoch-key rotation, so a new
  member never sees group history from before it joined.
- Peers paired *before* auto-join was enabled are NOT grandfathered
  in; only future pairing completions trigger the add (both
  initiator and responder roles).
- A raising/failing add never breaks the handshake — the error is
  logged and pairing still completes.
- `acp-relay-daemon status` reports the fleet block (`auto_join`,
  `group_id`, member count).

## Autopilot — opt-in autonomous replies

The daemon can answer direct messages and channel posts on its own,
per-peer / per-channel, using the `autopilot.py` module in this
directory. **Default posture: everything OFF.** No config file (or an
unparsable one) means no replies, ever. The owner explicitly opts each
peer or channel in.

### Config — `<home>/autopilot.json` (owner-edited)

```json
{
  "peers": {
    "<peer_pid>": {"mode": "hook", "hook": "status_hook",
                   "max_per_min": 6, "reply_to_auto": false}
  },
  "channels": {
    "<group_id>": {"mode": "echo",
                   "max_per_min": 6, "reply_to_auto": false}
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `mode` | yes | `"hook"` — run a hook script; `"echo"` — built-in test mode, replies `"echo: <text>"`. Anything else = entry ignored (treated as off). |
| `hook` | for `hook` mode | Script name, must match `^[A-Za-z0-9_-]+$` (path traversal rejected, entry treated as off). |
| `max_per_min` | no (default 6) | Token-bucket rate limit per peer/channel. `<= 0` = never reply. |
| `reply_to_auto` | no (default false) | Whether to answer messages that are themselves auto-generated (loop guard). |

Peers/channels not listed are ignored (audit `autopilot.skipped`,
`reason: "off"`).

### Hook contract — `<home>/autopilot_hooks/<name>.py`

Stdlib only. The hook runs as a **subprocess** (isolation + killable):

- **stdin:** the event dict as a single JSON document:
  `{"kind": "message"|"group_message", "sender", "text" (≤ 8000 chars),
  "msg_id", "reply_to", "auto", "group_id", "channel": {"name",
  "project_id"}}`.
- **stdout:** either `{"reply": "<text>"}` (JSON object with a `reply`
  key) or a bare text line (whole stdout, stripped). Empty stdout = no
  reply (audit `autopilot.no_reply`).
- **Timeout:** 15 s — the process is killed, no reply is sent
  (audit `autopilot.hook_timeout`).
- **stderr:** captured and forwarded to the daemon log, never to the peer.
- **Environment:** only `ACP_EVENT_KIND` (`"message"` or
  `"group_message"`). Never the passphrase, never tokens, never any
  other secret.

**The hook MUST NOT choose recipients.** The reply always goes to the
event's source — the peer for `message` events, the channel for
`group_message` events — via the threaded-send path. If hook stdout
names another peer/channel (e.g. a `"to"` field), it is parsed and then
**ignored**.

### Safety defaults

- **Loop guard:** an event whose `auto` flag is true is skipped unless
  the policy sets `reply_to_auto: true` (audit `reason: "auto_guard"`).
  Autopilot's own replies are sent with `auto=True` whenever the send
  API accepts the flag, so two autopilots with default policy can never
  ping-pong.
- **Rate guard:** token bucket per peer/channel (`max_per_min`,
  default 6); excess events are dropped
  (audits `autopilot.rate_limited` + `autopilot.skipped`).
- **Hard skips:** unknown peer/channel (`"off"`), own messages
  (`"own_message"`), missing/invalid hook (`"hook_missing"`), hook
  timeout.
- Every decision is audited via `Connector.audit.log` (metadata only,
  never message text): `autopilot.reply_sent`, `autopilot.no_reply`,
  `autopilot.skipped`, `autopilot.rate_limited`,
  `autopilot.hook_timeout`, `autopilot.send_failed`.
- The whole autopilot block in the daemon is wrapped in try/except: a
  broken autopilot module can never break the daemon's core loop, and
  each event is handled on a worker thread so the connector's reader
  thread is never blocked by a hook or a blocking send.

### `poll_events` — brain-side polling, no daemon needed

```python
from autopilot import poll_events
events, new_cursor = poll_events(home, cursor_path, own_pid=None)
```

Reads `<home>/connector.db` directly (sqlite3, read-only) and returns
new inbound direct messages plus group messages since the cursor (which
persists to `cursor_path` as JSON). Events use the same schema as the
hook stdin above, so the owner's own agent brain can feed them to hooks
with the same contract. Missing tables/columns are tolerated
(`reply_to`/`auto` default to `null`/`false` when the columns don't
exist yet).

## Tests

```bash
python3 -m pytest tests/test_relay_daemon.py -q
```
