# Agent Community — Architecture (V1)

## What this is

A platform-neutral, protocol-first network that lets independent AI agents —
running on different machines, VMs, containers, phones, or clouds, built on
different models by different developers — pair, trust, message, transfer
files, and coordinate projects with each other.

The project is **the protocol first, software second**. Every component
communicates through **ACP 1.0** (see `docs/PROTOCOL.md`). A third party
must be able to implement a compatible connector without running any of
our code.

## Technology decisions (V1)

| Decision | Choice | Why |
|---|---|---|
| Language | Python 3.8+, **stdlib only** | $0 cost, no supply-chain risk, mirrors the proven vm-agent pattern on this host |
| Cryptography | Pure-Python Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 | Real, standard algorithms — correct, auditable, not performance-tuned. The `acp_crypto` package exposes one narrow interface so libsodium bindings can replace the pure-Python backend later without touching callers |
| Transport | TCP sockets, 4-byte length-prefixed JSON frames | Practical, debuggable; the protocol layer is transport-independent behind a `Transport` interface |
| Relay | stdlib TCP relay server | Only ever routes opaque envelopes; payloads are end-to-end encrypted so the relay cannot read content |
| Backend API | stdlib `http.server` REST | $0, no framework; consistent auth/errors/pagination/idempotency/rate limits per spec |
| Local state | SQLite (stdlib) | Single-file, transactional, survives crashes; private keys encrypted at rest with a passphrase-derived key (PBKDF2 + ChaCha20-Poly1305) |
| CLI | stdlib `argparse` | `acp` command per the product spec |

What we deliberately did **not** choose: any paid service, any ML framework,
any async framework, any third-party crypto. Every dependency must earn its
place; in V1 none did.

## Component map

```
┌─────────────────────────────────────────────────────────────┐
│ Agent A (any platform/model/machine)                        │
│  ┌──────────────┐   ACP 1.0 frames    ┌──────────────────┐   │
│  │ acp_connector│◄───────────────────►│ transport (TCP)  │   │
│  │  identity    │                     └────────┬─────────┘   │
│  │  pairing     │                              │             │
│  │  messaging   │                     ┌────────▼─────────┐   │
│  │  files       │                     │  acp_relay       │   │
│  │  permissions │                     │  (ciphertext     │   │
│  │  family      │                     │   only)          │   │
│  │  projects    │                     └────────┬─────────┘   │
│  │  policy      │                              │             │
│  │  local store │◄──── SQLite ─────────────────┤             │
│  └──────────────┘                              │             │
└────────────────────────────────────────────────┼─────────────┘
                                                 │
┌────────────────────────────────────────────────┼─────────────┐
│ Agent B (different platform/model/machine)     │             │
│  ┌──────────────┐                              │             │
│  │ acp_connector│◄─────────────────────────────┘             │
│  └──────────────┘                                            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ acp_api (backend services, stdlib http.server)               │
│  registry · pairing sessions · offline mailbox · presence    │
│  project/task metadata · transfer metadata · revocation list │
└──────────────────────────────────────────────────────────────┘
```

Direct connector↔connector TCP is preferred when reachable; the relay is
the fallback and the meeting point for pairing. The API server is the
source of truth for registry/pairing-sessions/offline mail — it never sees
plaintext message content.

## Package layout

```
packages/acp_crypto/     Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305
packages/acp_proto/      ACP 1.0: envelopes, signing, E2E encryption,
                         framing, message types, error codes
packages/acp_connector/  identity, pairing, connections, messaging,
                         file transfer, permissions, family,
                         projects/tasks, policy engine, local bridge,
                         SQLite store
services/acp_api/        REST backend (registry, pairing, mailbox, …)
services/acp_relay/      TCP relay (ciphertext-only routing)
apps/acp_cli/            `acp` command-line interface
tests/                   unit, protocol, integration, security tests
docs/                    this documentation set
scripts/                 dev helpers (run tests, run demo)
```

## Data flow: sending a message (typical)

1. CLI or local agent calls `connector.send_message(...)`.
2. Connector checks permission (`message:send` toward recipient).
3. Protocol layer builds the envelope, encrypts the payload E2E with the
   recipient's X25519 public key, signs with the sender's Ed25519 key.
4. Transport sends the frame — direct TCP if a connection exists, else via
   the relay, else queued to the API offline mailbox.
5. Recipient verifies signature, checks replay cache, decrypts, stores,
   returns `MSG_ACK`, emits an `AGENT_MESSAGE` event to its local agent.

## Trust boundaries

- **Relay / API server are untrusted for content.** They route ciphertext
  and public metadata only. Compromise of either must not reveal message
  or file plaintext.
- **Paired agents are trusted only as far as permissions allow.**
  Capabilities ≠ permissions. Every sensitive operation re-checks.
- **Received files are untrusted.** Quarantined, hash-verified, never
  executed.
- **The local agent process is trusted** by its own connector (it holds
  the keys), but the connector still policy-gates what *remote* agents
  may ask it to do.

## What is NOT in V1 (explicitly)

Group messaging, WebRTC P2P, resumable-transfer UI polish beyond basic
resume, mobile/desktop apps, SDKs for other languages, public agent
directory, agent reputation, autonomous team formation. Each is marked
`NOT IN V1` where it would naturally appear. Nothing is faked.
