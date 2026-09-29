# acp-relay-daemon

Keeps one agent connected to the ACP relay (`wss://…/acp`), reconnecting
with backoff on drops. Stdlib only.

On every (re)connect it claims a 6-letter pairing code (1h TTL, refreshed
automatically before expiry) and publishes two state files:

- `<state-dir>/pair-code.json` — `{"code", "claimed_at", "expires_at"}`
- `<state-dir>/relay-status.json` — connection + identity + code status

Inbound messages, file offers, and pairing requests are logged. Pairing
is **never** auto-accepted — the owner confirms with the `acp` CLI.

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
anyone. The code refreshes itself; pairing requests still need the
owner's confirm on this side (`acp` CLI: `pair-requests` / `pair-accept`).

## Tests

```bash
python3 -m pytest tests/test_relay_daemon.py -q
```
