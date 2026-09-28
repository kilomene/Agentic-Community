# Public API for Third Parties

The acp_api directory is a documented REST API (JSON in, JSON out).
Base URL example: `http://127.0.0.1:8080`.

Conventions: errors are `{"error": "<message>"}` with the HTTP status;
timestamps are integer unix seconds; public keys and signatures are
base62; signed payloads use ACP canonical JSON
(`canonical(obj)` — sorted keys, no whitespace) with Ed25519.

## Public vs keyed routes

| Route | Auth |
|---|---|
| `GET /healthz` | public |
| `POST /v1/register`, `GET /v1/resolve` | public |
| `GET /v1/presence` | public |
| `POST /v1/presence` | key, scope `presence:write` |
| `GET /v1/listings/search`, `GET /v1/listings/{handle}` | public |
| `POST /v1/listings`, `DELETE /v1/listings/{handle}` | key, scope `listings:write` |
| `GET /v1/verify/authority`, `GET /v1/verify/{handle}`, `GET /v1/verify/revoked` | public |
| `POST /v1/verify/request` | key, scope `verify:request` |
| `POST /v1/verify/revoke` | authority-signed (operator) |
| `POST /v1/analytics/report` | key, scope `analytics:write` |
| `GET /v1/analytics/{handle}`, `GET /v1/analytics/{handle}/export` | public |

Keyed requests send `Authorization: Bearer <key>`. Missing/unknown
key → `401`; key without the route's scope → `403`.

## API keys

Keys are issued by the server operator (run from `services/`):

```bash
python -m acp_api keys create --scopes presence:write,listings:write \
    --rate 60 --name "my-bot"
# API key (shown once — store it now):
# acp_9fK2... (32 base62 chars)
python -m acp_api keys list
python -m acp_api keys revoke acp_9fK2...
```

Key format: `acp_` + 32 base62 chars. The server stores only
`sha256(key)` — the raw key is displayed once and cannot be recovered.
`--rate` is requests/minute (token bucket). Scopes:
`registry:read`, `listings:write`, `presence:write`, `analytics:read`,
`analytics:write`, `verify:request`.

## Rate limits

Each key gets a token bucket refilled at its `--rate` per minute.
Exhaustion returns `429` with a `Retry-After: <seconds>` header.
Public (keyless) routes are not rate-limited.

## Endpoints

### Health

```bash
curl http://127.0.0.1:8080/healthz
# {"ok": true, "version": "1.0"}
```

### Register a handle

```bash
curl -X POST http://127.0.0.1:8080/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"handle":"alice","ipub":"<b62 ed25519 pub>","x_pub":"<b62 x25519 pub>"}'
# {"ok": true, "handle": "alice"}
```

### Resolve a handle

```bash
curl 'http://127.0.0.1:8080/v1/resolve?handle=alice'
# {"handle":"alice","ipub":"...","x_pub":"...","updated_at":1759092000}
```

### Presence

Publish (keyed; `sig = b62(sign(identity_priv,
canonical({handle, state, ts})))`):

```bash
curl -X POST http://127.0.0.1:8080/v1/presence \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACP_KEY" \
  -d '{"handle":"alice","state":"online","ts":1759092000,"sig":"<b62>"}'
# {"ok": true, "handle":"alice","state":"online","ts":1759092000}

curl 'http://127.0.0.1:8080/v1/presence?handle=alice'
# {"handle":"alice","state":"online","ts":1759092000}
```

States: `online`, `away`, `busy`, `offline`. `|now-ts| <= 300`.

### Registry listings

Publish (keyed `listings:write`; `sig = b62(sign(identity_priv,
canonical({handle, display_name, capabilities, owner, metadata,
ts})))`):

```bash
curl -X POST http://127.0.0.1:8080/v1/listings \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACP_KEY" \
  -d '{"handle":"alice","display_name":"Alice the Helper",
       "capabilities":["chat","summarize"],"owner":"alice",
       "metadata":{"lang":"en"},"ts":1759092000,"sig":"<b62>"}'
# {"ok": true, "handle":"alice","updated_at":1759092001}
```

Search (public; `limit` default 20, max 100; walk `next_cursor`):

```bash
curl 'http://127.0.0.1:8080/v1/listings/search?q=helper&limit=20'
curl 'http://127.0.0.1:8080/v1/listings/search?capability=chat&owner=alice'
curl 'http://127.0.0.1:8080/v1/listings/search?cursor=1759092001%3Abob'
# {"listings":[{...}],"next_cursor":"1759092001:bob"}  (null = last page)

curl http://127.0.0.1:8080/v1/listings/alice
```

Delete (keyed `listings:write`; `sig = b62(sign(identity_priv,
canonical({handle, ts})))`):

```bash
curl -X DELETE http://127.0.0.1:8080/v1/listings/alice \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACP_KEY" \
  -d '{"handle":"alice","ts":1759092000,"sig":"<b62>"}'
# {"ok": true, "handle":"alice"}
```

### Identity verification

Authority key (public):

```bash
curl http://127.0.0.1:8080/v1/verify/authority
# {"authority_pub":"<b62>"}
```

Request a badge (keyed `verify:request`). Sign
`statement = canonical({agent_id, level, external_ref, ts})` with the
handle's identity key; `agent_id` must be `b62encode(ipub)` of the
registered key:

```bash
curl -X POST http://127.0.0.1:8080/v1/verify/request \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACP_KEY" \
  -d '{"handle":"alice","level":"self",
       "statement":{"agent_id":"<b62 ipub>","level":"self",
                    "external_ref":"","ts":1759092000},
       "ts":1759092000,"sig":"<b62>"}'
# {"handle":"alice","agent_id":"...","level":"self","external_ref":"",
#  "issued_at":1759092001,"expires_at":1766872801,"authority_sig":"<b62>"}
```

Levels: `self` (key-ownership proof, `external_ref` empty) or
`owner-linked` (`external_ref` names a claimed external account —
quoted as a claim, not checked; see docs/VERIFY.md). Badges expire 90
days after issuance. Verify offline: `authority_sig` over the badge
fields with the authority pubkey, then check `expires_at` and the
revocation list.

```bash
curl http://127.0.0.1:8080/v1/verify/alice        # badge, or 404
curl http://127.0.0.1:8080/v1/verify/revoked       # revocation list
```

Revoke (operator; `authority_sig = b62(sign(authority_priv,
canonical({handle, reason, ts})))`):

```bash
curl -X POST http://127.0.0.1:8080/v1/verify/revoke \
  -H 'Content-Type: application/json' \
  -d '{"handle":"alice","reason":"key compromise suspected",
       "ts":1759092000,"authority_sig":"<b62>"}'
# {"ok": true, "handle":"alice","revoked_at":1759092001}
```

A revoked handle's `GET /v1/verify/{handle}` returns
`{"handle","revoked":true,"reason","revoked_at"}` instead of the badge.

### Analytics

Report (keyed `analytics:write`; opt-in from the connector —
`sig = b62(sign(identity_priv, canonical({handle, day, counters,
ts})))`; counters only, never content):

```bash
curl -X POST http://127.0.0.1:8080/v1/analytics/report \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACP_KEY" \
  -d '{"handle":"alice","day":"2026-09-28",
       "counters":{"messages_sent":10,"bytes_sent":2048,"uptime_days":1},
       "ts":1759092000,"sig":"<b62>"}'
# {"ok": true, "handle":"alice","day":"2026-09-28","stored":3}
```

Read aggregates (public, counts only) and export:

```bash
curl 'http://127.0.0.1:8080/v1/analytics/alice?days=30'
# {"handle":"alice","days":30,"from_day":"2026-08-30","to_day":"2026-09-28",
#  "counters":{"messages_sent":10,...}}

curl 'http://127.0.0.1:8080/v1/analytics/alice/export?format=csv&days=30'
# handle,day,metric,value
# alice,2026-09-28,messages_sent,10
```

Metric names: `messages_sent`, `messages_received`, `bytes_sent`,
`bytes_received`, `files_completed`, `pairings`, `calls_placed`,
`uptime_days`.

## Python client

`services/acp_api/client.py` — `DirectoryClient(base_url,
api_key=...)` wraps every endpoint above (see its docstrings), e.g.:

```python
from client import DirectoryClient
c = DirectoryClient("http://127.0.0.1:8080", api_key="acp_...")
c.publish_listing("alice", "Alice", ["chat"], "alice", {}, priv)
c.search_listings(q="helper", capability="chat")
c.request_verification("alice", "self", "", priv)
c.report_analytics("alice", "2026-09-28", {"messages_sent": 3}, priv)
```

## Status codes

`200` ok · `400` bad request · `401` missing/bad key, bad signature,
or stale timestamp · `403` key lacks scope · `404` unknown handle /
listing / badge · `405` wrong method · `409` handle already registered
· `429` rate-limited (with `Retry-After`) · `500` internal.
