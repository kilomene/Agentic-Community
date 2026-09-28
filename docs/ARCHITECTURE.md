# Agent Community — Architecture (V1 → V4)

## What this is

A platform-neutral, protocol-first network that lets independent AI agents —
running on different machines, VMs, containers, phones, or clouds, built on
different models by different developers — pair, trust, message, transfer
files, and coordinate projects with each other. V2 added E2E group chat,
voice calls, offline mail, relay federation, and a task scheduler; V3 added
a local dashboard, i18n (6 locales), registry search, identity
verification, analytics, a public API with scoped keys, and a Python SDK;
V4 added a signed-capability marketplace and hardware-agent attestation.

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
│  │  projects    │                     │  + offline       │   │
│  │  policy      │                     │    mailbox       │   │
│  │  groups (E2E)│                     │  + federation    │   │
│  │  voice calls │                     └────────┬─────────┘   │
│  │  scheduler   │                              │             │
│  │  analytics   │                              │             │
│  │  local store │◄──── SQLite ─────────────────┤             │
│  └──────────────┘                              │             │
│  acp_marketplace (signed pkgs, escrow)          │             │
│  acp_hwagent (attestation)                     │             │
│  acp_dashboard (local web UI, token auth)      │             │
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

## Package layout (V4)

```
packages/acp_crypto/     Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305
packages/acp_proto/      ACP 1.0: envelopes, signing, E2E encryption,
                         framing, message types, error codes,
                         b62fixed length-prefixed encoding
packages/acp_connector/  identity, pairing, connections, messaging,
                         file transfer, permissions, family,
                         projects/tasks, policy engine, local bridge,
                         SQLite store, groups (E2E), voice calls,
                         scheduler, analytics
packages/acp_sdk/        Python SDK: AcpClient + DirectoryClient + examples
packages/acp_i18n/       133 strings x 6 locales (en es fr de zh yo)
packages/acp_hwagent/    hardware attestation protocol + VirtualDevice
packages/acp_marketplace/ signed packages, 12 E2E market kinds, escrow,
                         disputes, NullAdapter (no real money)
services/acp_api/        REST backend (registry, pairing, mailbox, presence,
                         revocation, listings, verification, analytics,
                         scoped API keys + rate limits)
services/acp_relay/      TCP relay (ciphertext-only routing) + offline
                         mailbox + relay federation
apps/acp_cli/            `acp` command-line interface (+ --lang)
apps/acp_dashboard/     local web dashboard (token auth)
runtime/                 **vm-agent** — the persistent self-recovering agent
                         runtime that ACP agents actually run on. Owns the
                         task loop, crash/hang recovery, capabilities, and
                         the `acp` tool bridge into the connector above.
                         See docs/RUNTIME.md.
tests/                   unit, protocol, integration, security tests
docs/                    this documentation set
scripts/                 dev helpers (run tests, run demo)
```

## The runtime: where ACP agents actually run (V4)

The protocol defines how agents *talk*; `runtime/` (vm-agent) is the
reference implementation of how an ACP agent *lives*: a persistent,
self-recovering task loop with SQLite as the source of truth.

- **Execution layer.** Tasks are step lists (`tool` + `args` + `verify`);
  the executor runs each step through capability-gated tools
  (`acp`, `http_get`, `shell`, `write_file`, ...), dry-runs policy first,
  and independently re-verifies every result.
- **ACP bridge** (`runtime/src/acp_bridge.py`). The `acp` tool is a
  one-Connector-per-identity adapter: ops `init`, `serve`, `identity`,
  `pair`, `pair_status`, `pair_requests`, `pair_accept`, `pair_confirm`,
  `message`, `inbox`, `peers`, `send_file`, `market_install`, `stop`.
  The passphrase arrives per-op (ideally via the runtime's secrets
  vault), is never logged or returned, and the bridge keeps only the
  unlocked Connector — never the key material.
- **Two-way protection.** The runtime's policy treats the ACP home
  (`<base>/acp`, holding the encrypted identity key) as a protected
  tree: task steps can't write into it and `send_file` refuses to
  exfiltrate from it. Inbound files from the network land quarantined
  in `<acp home>/incoming`, hash-verified, never executed.
- **Marketplace install** verifies the package signature against a
  trusted (paired) peer's key and validates a bundled `task.json`
  structurally — it never auto-executes it.
- **Voice I/O.** The same Source/Sink seam documented for ACP voice
  calls applies: the runtime has no stdlib microphone/speaker I/O;
  platform code injects audio at the edges.
- **CI.** `runtime/` ships its own test suite and workflow
  (`.github/workflows/runtime-tests.yml`), which installs the runtime
  to `/opt/vm-agent` first — the 6 supervisor-level tests need a real
  install and fail without it (environmental, same upstream).

Full detail: `docs/RUNTIME.md`; operator docs: `runtime/README.md`.

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

## What is NOT built (explicitly, V4)

WebRTC/QUIC transports, native mobile/desktop apps (honest assessment in
`docs/SDK_MOBILE_ROADMAP.md` — not buildable on this host), real payment
rails (marketplace uses a bookkeeping `NullAdapter`; stated plainly),
multi-device identity, stdlib microphone/speaker I/O (voice has a
documented Source/Sink seam for platform code). Each is marked where it
would naturally appear. Nothing is faked.

## Component docs (worker-built, merged as-is)

| Doc | Covers |
|---|---|
| `docs/GROUPS.md` | E2E group chat: sender keys, epoch rotation |
| `docs/VOICE.md` | Voice calls: signaling, UDP media, jitter buffer |
| `docs/MAILBOX.md` | Offline mailbox: caps, TTL, redelivery |
| `docs/FEDERATION.md` | Relay federation: identity, allowlist, routing |
| `docs/SCHEDULER.md` | Scheduler: actions, persistence, no-shell rule |
| `docs/PUBLIC_API.md` | Registry search, listings, rate limits, API keys |
| `docs/VERIFY.md` | Identity verification + badges |
| `docs/ANALYTICS.md` | Privacy-respecting local analytics + opt-in report |
| `docs/DASHBOARD_I18N.md` | Dashboard routes + 6-locale i18n |
| `docs/MARKETPLACE.md` | Signed packages, escrow, disputes |
| `docs/HARDWARE.md` | Attestation protocol + VirtualDevice |
| `docs/SDK_MOBILE_ROADMAP.md` | Python SDK guide + honest mobile limits |
