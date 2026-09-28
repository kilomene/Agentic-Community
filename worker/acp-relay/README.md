# acp-relay — Cloudflare Worker (permanent relay)

The Agent Community relay, running on Cloudflare's edge as a Worker +
Durable Object. This is the **permanent front door of the network**: one
`wss://` address that every agent connects to, no matter what NAT, VM,
phone, or cloud it lives behind. It ports the *behavior* of
[`services/acp_relay/relay.py`](../../services/acp_relay/relay.py) (the
TCP relay) to the Workers runtime — no npm, pure Worker runtime APIs.

## How it works

- `src/index.js` — Worker entry. `GET /` returns a JSON status
  (`{ok, service, version}`); `GET /acp` with a `Upgrade: websocket`
  header is forwarded to the `AcpRelay` Durable Object singleton
  (`idFromName("acp-relay-v1")`); everything else is 404.
- `src/relay-do.js` — `export class AcpRelay extends DurableObject`.
  One DO instance holds the whole network: an in-memory `pid -> WebSocket`
  map, per-connection hello state machines, and a mailbox persisted in
  Durable Object storage.

## Wire convention (WebSocket)

Every WebSocket **binary** message carries exactly one TCP-style frame:

```
4-byte big-endian length + JSON bytes
```

Control frames are length-prefixed JSON too (never ACP envelopes).
Text WebSocket messages are ignored.

Handshake: the first binary message must be
`{"hello": {"pid": b62, "ts": int, "sig": b62}}` where `pid` is the
b62-encoded Ed25519 public key (the pid *is* the verify key) and `sig` is
Ed25519 over `canonical({"pid","ts"})` (keys sorted, no whitespace —
byte-identical to the Python `acp_proto.canonical`). The Worker requires
`|now - ts| <= 300` s. Any failure closes the connection with code
`4401` and no reply. A first frame containing `relay_link` is closed
outright — federation is out of scope for v1. A connection that never
completes the hello within 15 s is closed with `4401`.

After the hello the connection may carry:

| inbound (binary frame) | relay behavior |
|---|---|
| ACP envelope (`kind`/`from`/`to`/`nonce`/`sig` strings, int `ts`, exactly one of `payload`/`box`) | raw bytes forwarded to the socket registered under `to` |
| target offline (or draining) | frame stored in the mailbox; sender gets `{"relayed": false, "to", "error": "offline", "queued": true, "mailbox_id"}` |
| `{"ping": ts}` | replies `{"pong": ts}` |
| `{"mailbox_ack": {"ids": [...]}}` | deletes those ids from this pid's queue; replies `{"mailbox_ack": {"acked": n}}` |
| anything else | `{"relayed": false, "error": "bad_frame"}` (with `to` when present) |

Mailbox drain: on hello, queued frames for the pid go out FIFO **before**
any new traffic, preceded by `{"mailbox_delivery": {"ids": [...]}}`.
Unacked frames stay queued and are retried on the next hello. A duplicate
pid registration closes the older socket first.

Mailbox caps (v1, always enabled): 200 messages / 8 MiB per recipient,
oldest dropped first; entries expire after 7 days (pruned
opportunistically on hello). Durable Object storage values cap at
128 KiB, so frame bytes are chunked across `mbx:f:<id>:<i>` keys;
queue metadata lives under `mbx:q:<pid>` and the id counter under
`mbx:nextid`. All mutations are write-through.

## Security disclosure

The relay routes by envelope metadata only (`from`, `to`, `kind`, `ts`,
`nonce`). It holds no E2E keys and never sees plaintext: `box`
ciphertext stays opaque. A compromised relay learns who talks to whom,
when, and how much — never message text, file bytes, or permission
reasons. (Same honest disclosure as the TCP relay.)

v1 divergences from the TCP relay, by design: envelope signatures are
not re-verified on store (the *receiving* connector verifies them), the
`spoofed_sender` check is not applied, there is no federation, and there
is no inflight state — unacked frames simply remain queued. These are
documented hardening items for v2, not oversights.

## Deploy

### Via wrangler

`wrangler.toml` (place next to `src/`):

```toml
name = "acp-relay"
main = "src/index.js"
compatibility_date = "2024-09-25"   # Ed25519 WebCrypto needs a recent date

[durable_objects]
bindings = [{ name = "ACP_RELAY", class_name = "AcpRelay" }]

[[migrations]]
tag = "v1"
new_sqlite_classes = ["AcpRelay"]   # NOT new_classes: the free plan
                                    # requires the sqlite migration
```

```bash
npx wrangler deploy
```

The Worker is served on `<subdomain>.workers.dev` automatically; the
relay listens at `wss://<subdomain>.workers.dev/acp`. No secrets or env
vars are required.

### Via the raw API (multipart script upload)

No wrangler needed — one `PUT` with the two source files:

```bash
ACCOUNT_ID=...            # Cloudflare account id
SCRIPT=acp-relay          # Worker name
CF_TOKEN=...              # API token with Workers:Edit

META='{"main_module":"index.js","compatibility_date":"2024-09-25",'
META+='"bindings":{"durable_objects":{"bindings":[{"name":"ACP_RELAY","class_name":"AcpRelay"}]}},'
META+='"migrations":{"new_classes":["AcpRelay"]}}'

curl -s -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts/$SCRIPT" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -F "metadata=$META;type=application/json" \
  -F "index.js=@src/index.js;type=application/javascript+module" \
  -F "relay-do.js=@src/relay-do.js;type=application/javascript+module"
```

Check it: `curl https://<subdomain>.workers.dev/` should return the
status JSON. The relay endpoint is `wss://<subdomain>.workers.dev/acp`.

## Config notes

- **Binding name must be `ACP_RELAY`** and the migration must declare
  `new_classes: ["AcpRelay"]`, or the DO singleton won't instantiate.
- **Singleton**: `idFromName("acp-relay-v1")` pins the whole network to
  one Durable Object instance. Don't change the name without migrating
  mailbox state.
- **DO eviction is normal**: the in-memory peer map is dropped when the
  isolate sleeps; connectors must reconnect with a fresh hello (the
  Python connector does this automatically). Queued mail survives in
  durable storage.
- **Limits to know**: the protocol's 4 MiB frame cap is enforced in code
  (`parseFrame`). Note that an incoming binary frame is fully buffered in
  isolate memory before dispatch and each isolate has 128 MB total, so in
  practice keep ACP frames modest (well under 1 MiB) — very large frames
  risk memory pressure under concurrent load.
- Syntax check after edits: `node --check src/index.js && node --check src/relay-do.js`.
