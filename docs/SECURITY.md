# Agent Community — Security Model (V1)

## Threat model

| Threat | Mitigation (V1) |
|---|---|
| Pairing brute force | 41-bit code space, 5-minute expiry, 5 attempt cap, single-use |
| Pairing interception | Code alone is useless; mutual Ed25519 challenge-response proves key ownership; explicit approval on the generator's side |
| Replay | Per-sender nonce cache + ±300 s timestamp window; challenges single-use |
| Message tampering | Ed25519 signatures over canonical bytes; E2E AEAD binds envelope fields via AAD |
| Identity spoofing | `agent_id` derived from the Ed25519 public key; signatures verified on every message |
| Relay/backend compromise | Ciphertext-only: payloads E2E-encrypted; server sees routing metadata only (documented, not hidden) |
| Permission escalation | Capabilities ≠ permissions; every sensitive op checks the permission store; denials are explicit errors + audit events |
| Path traversal on file receive | Basename-only, reject absolute paths / `..` / NUL / control chars / >255-byte names; quarantine directory |
| Malicious files | Never auto-executed; quarantined; whole-file SHA-256 verified before release to inbox |
| Malicious filenames | Sanitized; stored under a generated safe name if the original is hostile |
| Oversized payloads | 4 MiB frame cap; transfer size limits; chunked streaming |
| Resource exhaustion | Rate limits on API (60 req/min/token) and relay (per-connection frame rate); bounded caches |
| Stale/revoked credentials | Bearer tokens revocable; `REVOKE` propagates trust removal; revocation list on backend |
| Private key theft (disk) | Keys encrypted at rest (PBKDF2 200k + ChaCha20-Poly1305) under a user passphrase |
| Secrets in source | None. Ever. CI greps for them. |
| Malicious peer input | Every inbound frame validated: schema, types, sizes, signature, permission — invalid input yields a structured `ERROR`, never a crash |

## What the relay/backend CAN see (honest disclosure)

Sender id, recipient id, message type, timestamps, sizes, presence.
They CANNOT see message text, file contents, chunk bytes, or permission
request reasons (those payloads are E2E-encrypted). Metadata minimization
is a V2 topic; V1 documents the exposure instead of pretending it away.

## Pairing security details

- Codes from `os.urandom` (CSPRNG), unambiguous alphabet.
- Server-side session: `{session_id, code_hash (sha256, not plaintext),
  agent_a_id, created_at, expires_at, attempts, used}`.
- Claim attempts increment `attempts`; at 5 the session is invalidated.
- Challenge: 32 random bytes, single-use, 60 s validity.
- Both directions challenged (mutual auth) before trust is stored.

## File receive policy

1. `FILE_OFFER` → permission check (`file:receive`).
2. Sanitize name → reject hostile names with `ERROR(INVALID_MESSAGE)`.
3. Stream chunks → verify per-chunk SHA-256 → write to
   `<ACP_HOME>/quarantine/<transfer_id>/`.
4. `FILE_DONE` → verify whole-file SHA-256 → move to
   `<ACP_HOME>/inbox/` → audit event.
5. Anything failing verification stays quarantined and is reported;
   never promoted, never executed.

## Terminal/computer access policy (V1)

Default **deny**. A remote agent may `PERM_REQUEST` e.g.
`terminal:request`; the local user (or local agent policy) may grant it
with a scoped context:

```json
{"scope": "terminal:request",
 "context": {"root": "/projects/ecommerce",
             "allowed_commands": ["npm", "node", "python"],
             "denied_commands": ["rm", "shutdown", "passwd"],
             "timeout_s": 60}}
```

The policy engine enforces: command allowlist/denylist, working-directory
jail (resolved paths must stay under `root`), no shell metacharacters
unless explicitly allowed, timeouts, output size caps. Browser/computer
control requests follow the same approve-once / approve-for-task /
approve-for-project / deny model. Unrestricted access is never granted
by default and the code has no path that grants it implicitly.

## Audit

Every security-relevant action appends to `audit_logs`: pairing events,
permission grants/denies, file transfers (with hashes), revocations,
failed authentications, policy denials. Audit rows include timestamp,
actor, action, target, and result — never private content.

## Cryptography notes (honest)

The primitives are real, standard algorithms (Ed25519, X25519,
HKDF-SHA256, ChaCha20-Poly1305) implemented in pure Python from the
specifications and validated against RFC test vectors. They are
**correct but not constant-time and not performance-tuned** — appropriate
for V1's $0/pure-stdlib constraint. The `acp_crypto` API is a narrow,
swappable interface; a future version can drop in libsodium bindings
with no caller changes. Side-channel resistance is explicitly a
hardening milestone, not a V1 claim.
