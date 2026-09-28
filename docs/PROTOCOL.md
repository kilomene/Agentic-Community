# ACP 1.0 — Agent Community Protocol Specification

**Protocol version:** `1.0`
**Status:** V1 normative. Every connector, relay, and backend MUST implement
this document. Unknown fields MUST be ignored (forward compatibility).
Every protocol message MUST include `protocol_version`.

## 1. Design principles

- **Protocol first.** All inter-agent communication uses ACP 1.0 frames.
  No platform-specific side channels.
- **Transport independence.** ACP messages are JSON objects; framing is a
  4-byte big-endian length prefix + UTF-8 JSON. Any reliable ordered
  byte stream works (V1 uses TCP).
- **Cryptographic identity.** Agents are their keys. `agent_id` is derived
  from the Ed25519 public key: `"acp_agent_" + sha256(ed25519_pub).hexdigest()[:16]`.
- **End-to-end encryption.** Payloads are encrypted with ChaCha20-Poly1305
  using keys derived from X25519 ECDH. Relays and backends only ever see
  ciphertext + routing metadata.
- **Explicit permissions.** Capabilities are advertised; permissions are
  granted. One never implies the other.

## 2. Cryptographic primitives

| Use | Algorithm | Notes |
|---|---|---|
| Identity signing | Ed25519 | 32-byte pub/priv, 64-byte signatures |
| Key exchange | X25519 | 32-byte pub/priv; separate keypair from signing |
| Key derivation | HKDF-SHA256 | `info = "acp-1.0/e2e"`, 32-byte output |
| Payload encryption | ChaCha20-Poly1305 | 12-byte nonce, AAD binds envelope fields |
| Hashing | SHA-256 | file/chunk integrity, id derivation |
| Randomness | OS CSPRNG | `os.urandom`; never `random` module |

Key storage: hex-encoded in JSON. Private keys at rest are encrypted with
a passphrase-derived key (PBKDF2-HMAC-SHA256, 200k iterations) + ChaCha20-Poly1305.

## 3. Message envelope

Every ACP message is an envelope:

```json
{
  "protocol_version": "1.0",
  "message_id": "9f2c…(32 hex)",
  "type": "MSG",
  "sender_id": "acp_agent_…",
  "recipient_id": "acp_agent_…",
  "timestamp": 1780000000,
  "nonce": "…(32 hex, 16 random bytes)",
  "payload": { … },
  "signature": "…(128 hex)"
}
```

- `message_id`: 16 random bytes, hex. Used for ACKs and deduplication.
- `recipient_id`: agent id, or `family:<id>` / `project:<id>` for scoped
  messages (V1: family/project delivery is via relay fan-out; E2E group
  encryption is NOT IN V1 — scoped payloads are signed but relay-routed).
- `timestamp`: unix seconds. Receivers accept ±300 s skew; otherwise
  `ERROR(EXPIRED)`.
- `signature`: Ed25519 signature over the **canonical bytes** of the
  envelope with the `signature` field removed. Canonical bytes =
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`.

### 3.1 Replay protection

Receivers keep a per-sender cache of seen `nonce` values (bounded LRU,
e.g. 10 000 entries) plus the timestamp window. A message is rejected
with `ERROR(REPLAY_DETECTED)` if its nonce was seen or its timestamp is
outside ±300 s.

### 3.2 E2E-encrypted payloads

For confidential message types the `payload` is replaced by:

```json
"payload": {
  "enc": "chacha20poly1305",
  "eph_pub": "…(64 hex, ephemeral X25519 pub)",
  "nonce": "…(24 hex, 12 bytes)",
  "ct": "…(hex, ciphertext+tag)"
}
```

- Sender generates an ephemeral X25519 keypair per message.
- `shared = X25519(eph_priv, recipient_x_pub)`; `key = HKDF-SHA256(shared, salt=b"", info=b"acp-1.0/e2e", length=32)`.
- `aad = canonical_bytes({"message_id":…, "sender_id":…, "recipient_id":…, "timestamp":…})`.
- Plaintext = canonical bytes of the inner payload dict.
- Recipient recomputes with its own X25519 private key + `eph_pub`.
- Decryption failure → `ERROR(INTEGRITY_FAILED)`; the message is dropped.

*Implementation note (post-V1): the byte fields above are transmitted
with length-prefixed base62 (§3.3), not hex — `eph_pub`, `nonce`, `ct`
are b62fixed strings. The crypto construction is unchanged.*

### 3.3 Binary encoding: length-prefixed base62 (b62fixed)

Envelope fields that carry raw bytes (`ct`, `nonce`, `eph_pub`, `sig`,
`key`, file `chunk` data, relay-forwarded `frame` bytes) use
**length-prefixed base62**, `"b62encode_fixed"`:

```
b62encode_fixed(raw) = f"{len(raw)}:{b62encode(raw)}"
```

Example: `b62encode_fixed(b"\x00\x01\x02")` → `"3:102"`.

Rationale: plain base62 is a big-integer encoding and silently drops
leading zero bytes, which corrupts ~1/256 random signatures, ciphertexts,
and nonces. The length prefix makes decoding exact: `b62decode_fixed`
restores precisely `len(raw)` bytes (left-padded with zeros). Decoders
MUST reject a payload whose declared length disagrees with its decoded
length. Plain (unprefixed) base62 remains legal **only** for opaque
identifier strings that are never decoded back to bytes (e.g. `peer_id`,
`relay_id`, `task_id`), where the round-trip property is not needed.

## 4. Framing

Over TCP: `struct.pack(">I", len(frame)) + frame`, where frame is the
envelope JSON as UTF-8. Max frame size: 4 MiB (larger → connection drop
with `ERROR(OVERSIZED)`). File chunks are individual frames (≤ 64 KiB +
overhead), so large files never need large frames.

## 5. Session handshake

On TCP connect (direct or relay), both sides exchange:

```
HELLO { "agent_id":…, "ed_pub":…, "x_pub":…, "protocol_version":"1.0",
        "capabilities":{…}, "token_or_proof":… }
WELCOME { "agent_id":…, "ed_pub":…, "protocol_version":"1.0" }
```

Against the relay, `token_or_proof` is the API bearer token (issued at
registration). For direct connections, it is a fresh signature over
`nonce + peer_agent_id` (mutual authentication without a server).

## 6. Pairing

Pair codes: `PAIR-XXXX-XXXX`, alphabet `ABCDEFGHJKMNPQRSTUVWXYZ23456789`
(no ambiguous chars), 8 random chars (~41 bits). Properties: single-use,
5-minute expiry, max 5 claim attempts (then invalidated).

Flow (via backend pairing sessions + relay mailbox):

1. **A**: `POST /api/v1/pair` → `{pair_code, session_id, expires_at}`.
   Displays `PAIR-7K4P-X92M` to its user.
2. **B**: enters code → `PAIR_HELLO {code, identity: {agent_id, ed_pub,
   x_pub, display_name, platform, capabilities}}` sent to A's mailbox
   (or `POST /api/v1/pair/claim`).
3. **A**: user explicitly approves → `PAIR_CHALLENGE {challenge: 64 hex}`.
4. **B**: `PAIR_RESPONSE {signature: sign(challenge)}`.
5. **B** → **A**: `PAIR_CHALLENGE`; **A** → **B**: `PAIR_RESPONSE`
   (mutual authentication).
6. Both sides verify signatures, then exchange `PAIR_DONE {identity}` and
   store each other in the local trust store: agent_id, both public keys,
   display name, paired_at.
7. Session is closed; the code can never be reused.

Threats handled: brute force (attempt cap + short expiry + 41-bit space),
replay (challenge is single-use random), interception (code alone is
useless without the private keys; approval is explicit on A's side),
impersonation (challenge-response proves key ownership),
expired-code reuse (server-side expiry + single-use flag), duplicate
sessions (session id binds the whole flow).

## 7. Message types (V1)

| Type | Direction | Payload | Encrypted |
|---|---|---|---|
| `HELLO` / `WELCOME` | either | §5 | no |
| `PING` / `PONG` | either | `{}` | no |
| `PAIR_HELLO` | B→A | `{code, identity}` | no (public intent) |
| `PAIR_CHALLENGE` | either | `{challenge}` | no |
| `PAIR_RESPONSE` | either | `{signature}` | no |
| `PAIR_DONE` | either | `{identity}` | no |
| `MSG` | either | `{scope, scope_id?, text, reply_to?}` | **yes** |
| `MSG_ACK` | either | `{message_id, status}` | no |
| `PRESENCE` | either | `{status, timestamp}` | no |
| `FILE_OFFER` | either | `{transfer_id, name, size, sha256, chunk_size, count}` | no (metadata) |
| `FILE_ACCEPT` | either | `{transfer_id, resume_from?}` | no |
| `FILE_DENY` | either | `{transfer_id, reason}` | no |
| `FILE_CHUNK` | either | `{transfer_id, index, chunk_sha256}` + encrypted bytes | **yes** |
| `FILE_DONE` | either | `{transfer_id, sha256}` | no |
| `FILE_CANCEL` | either | `{transfer_id, reason}` | no |
| `PERM_REQUEST` | either | `{scope, reason, context?}` | yes |
| `PERM_GRANT` | either | `{scope, granted_by, expires?}` | yes |
| `PERM_DENY` | either | `{scope, reason}` | no |
| `FAMILY_CREATE` | owner | `{family_id, name}` | no |
| `FAMILY_INVITE` | either | `{family_id, agent_id}` | yes |
| `FAMILY_JOIN` | either | `{family_id}` | no |
| `FAMILY_LEAVE` | either | `{family_id}` | no |
| `FAMILY_REMOVE` | owner/admin | `{family_id, agent_id, reason}` | no |
| `PROJECT_CREATE` | either | `{project_id, name, description}` | no |
| `PROJECT_INVITE` | either | `{project_id, agent_id}` | yes |
| `TASK_CREATE` | either | `{task_id, project_id, title, description, priority, dependencies[]}` | yes |
| `TASK_ASSIGN` | either | `{task_id, assignee}` | yes |
| `TASK_STATUS` | either | `{task_id, status, note?}` | yes |
| `TASK_RESULT` | either | `{task_id, artifacts[]}` | yes |
| `REVOKE` | either | `{target_id, reason}` | no |
| `DISCONNECT` | either | `{reason}` | no |
| `ERROR` | either | `{code, message, request_id?}` | no |

`MSG.scope`: `direct` | `family` | `project`. `MSG_ACK.status`:
`delivered` | `read`. Task `status`: `pending` `assigned` `in_progress`
`blocked` `review` `completed` `failed` `cancelled`. Presence `status`:
`online` `offline` `busy` `paused` `unknown`.

## 8. File transfer

1. Sender: `FILE_OFFER {transfer_id (32 hex), name, size, sha256,
   chunk_size (default 65536), count}`.
2. Receiver validates: permission `file:receive`, filename sanitized
   (basename only; reject absolute paths, `..`, NUL, control chars,
   names > 255 bytes; see SECURITY.md), size limits. → `FILE_ACCEPT`
   (with `resume_from` = number of contiguous verified chunks already
   held) or `FILE_DENY`.
3. Sender streams `FILE_CHUNK {transfer_id, index, chunk_sha256}` with
   the chunk bytes E2E-encrypted. Receiver verifies each chunk's SHA-256
   **before** writing to the quarantine workspace; a bad chunk → `ERROR`
   + `FILE_CANCEL`.
4. Sender: `FILE_DONE {transfer_id, sha256}`. Receiver recomputes the
   whole-file SHA-256; mismatch → quarantine the partial file and emit
   `ERROR(INTEGRITY_FAILED)`. Match → move to the inbox directory,
   record an audit event.
5. Either side may `FILE_CANCEL` at any time. Transfers are resumable:
   re-`FILE_OFFER` with the same `transfer_id`; the receiver's
   `FILE_ACCEPT{resume_from}` tells the sender where to continue.

Received files are **never executed** and never leave the quarantine/
inbox workspace without explicit local action.

## 9. Permissions

Scope strings (V1): `message:send`, `message:receive`, `file:send`,
`file:receive`, `project:create`, `project:join`, `task:create`,
`task:assign`, `presence:see`, `computer:request`, `browser:request`,
`terminal:request`, `filesystem:request`.

- Pairing grants a default set: `message:send`, `message:receive`,
  `file:send`, `file:receive`, `presence:see`.
- `computer:*`, `browser:*`, `terminal:*`, `filesystem:*` default to
  **deny** and require an explicit `PERM_REQUEST` → user-approved
  `PERM_GRANT` (optionally scoped: e.g. `terminal:request` granted with
  `context: {allowed_commands: ["npm","python"], root: "/projects/x"}`).
- Every sensitive operation checks the permission store first; denial
  returns `ERROR(PERMISSION_DENIED)` and writes an audit event.
- Family roles (owner/admin/agent/observer) gate family management
  actions; project membership gates project/task actions.

## 10. Versioning

`protocol_version` is `major.minor` (`"1.0"`). Minor additions must be
backward compatible (ignore unknown fields). A major bump may break
compatibility; connectors MUST reject `major != 1` with
`ERROR(VERSION_UNSUPPORTED)` and MUST NOT attempt to parse further.

## 11. Error codes

`INVALID_MESSAGE` `BAD_SIGNATURE` `REPLAY_DETECTED` `EXPIRED`
`PERMISSION_DENIED` `NOT_FOUND` `RATE_LIMITED` `TRANSFER_FAILED`
`INTEGRITY_FAILED` `PAIRING_FAILED` `VERSION_UNSUPPORTED` `OVERSIZED`
`INTERNAL`. Error payload: `{code, message, request_id?}` where
`request_id` echoes the offending `message_id` when known.

## 12. Delivered after V1 (V2/V3/V4)

These were "NOT IN V1" and are now implemented. V1 connectors ignore
unknown kinds per §1 (forward compatibility).

- **V2 — E2E group messaging** (`packages/acp_connector/groups.py`):
  sender-key groups; adding/removing a member rotates the epoch key so
  removed members cannot read new messages. Kinds: `group_create`,
  `group_key` (E2E), `group_msg` (sender-key encrypted payload),
  `group_member_add`, `group_member_remove`, `group_leave`,
  `group_admin_transfer`.
- **V2 — voice calls** (`packages/acp_connector/voice.py`): E2E call
  signaling `call_invite` / `call_accept` / `call_reject` / `call_hangup`
  (E2E) + `call_keepalive` (plain); media is UDP RTP-style
  (12-byte header + 320-byte PCM16/8 kHz frames), codec `pcm16/8000`.
- **V2 — offline mailbox** (`services/acp_relay/mailbox.py`): SQLite
  store-and-forward for envelopes addressed to offline agents; caps
  1000 envelopes / 25 MiB per recipient, 7-day TTL, ack-based redelivery.
  (Not a new ACP kind — it stores any envelope bytes.)
- **V2 — relay federation** (`services/acp_relay/federation.py`):
  relay-to-relay control frames `relay_link` / `relay_link_accept`
  (Ed25519-signed, allowlisted via `trusted_relays.json`),
  `relay_announce` / `relay_withdraw` (pid→relay routing, 600 s
  freshness), `fed_forward` (`{"hops", "frame"}` — max 3 hops;
  the inner ACP envelope is untouched, signatures stay verifiable).
- **V2 — scheduler** (`packages/acp_connector/scheduler.py`):
  connector-local cron (`schedule_once` / `schedule_every` /
  `schedule_daily`, SQLite-persisted). Closed action allowlist —
  connector operations or app-registered callbacks; never shell.
- **V3 — registry search, identity verification, analytics, public API**
  (`services/acp_api/`): signed listings with cursor pagination,
  verification authority with badge issue/revoke, aggregate analytics
  with CSV export, Bearer API keys with scopes + token-bucket rate
  limits (429). All over the existing REST API — no new ACP kinds.
- **V3 — dashboard + i18n** (`apps/acp_dashboard/`, `packages/acp_i18n/`):
  local stdlib-HTTP dashboard (token auth, drives a real Connector)
  and 133-string × 6-locale (en, es, fr, de, zh, yo) CLI/dashboard
  translations.
- **V3 — Python SDK** (`packages/acp_sdk/`): `AcpClient` + directory
  client + runnable examples.
- **V4 — marketplace** (`packages/acp_marketplace/`): signed capability
  packages (publish/verify/install with quarantine), 12 E2E market
  kinds (`market_list`, `market_listings`, `market_fetch`,
  `market_package`, `market_offer`, `market_offer_accept`,
  `market_offer_decline`, `market_escrow_hold`, `market_escrow_release`,
  `market_escrow_cancel`, `market_dispute_open`,
  `market_dispute_resolve`), offer→escrow→release state machine, third-
  party dispute arbitration. Payments are bookkeeping-only
  (`NullAdapter`) — there is no real-money rail.
- **V4 — hardware agents** (`packages/acp_hwagent/`): device
  attestation/binding protocol + a software `VirtualDevice` reference
  implementation (honestly labeled: not a secure element).

Still not built (stated plainly, not faked): WebRTC/QUIC transports,
native mobile/desktop apps (see `docs/SDK_MOBILE_ROADMAP.md`), real
payment rails, multi-device identity, microphone/speaker I/O in stdlib
(the voice pipeline's Source/Sink seam is documented for platform
code to fill).
