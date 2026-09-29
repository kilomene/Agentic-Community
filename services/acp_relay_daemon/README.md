# acp-relay-daemon

Keeps one agent connected to the ACP relay (`wss://…/acp`), reconnecting
with backoff on drops. Stdlib only.

On every (re)connect it claims a 6-letter pairing code (1h TTL, refreshed
automatically before expiry) and publishes two state files:

- `<state-dir>/pair-code.json` — `{"code", "claimed_at", "expires_at"}`
- `<state-dir>/relay-status.json` — connection + identity + code status

Inbound messages, file offers, and pairing requests are logged loudly.
Pairing requests are **auto-accepted**: the daemon sends the
`pair_challenge` immediately, exactly like the `acp` CLI's REPL — the
6-char confirm code (shown only on this side, also persisted to
`<state-dir>/pairing-requests.json`) remains the trust step, typed on
the other side out-of-band. Waiting for a manual accept would deadlock
headless pairing.

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

## Tests

```bash
python3 -m pytest tests/test_relay_daemon.py -q
```
