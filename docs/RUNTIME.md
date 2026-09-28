# RUNTIME.md — vm-agent: the execution layer ACP agents run on

`runtime/` is **vm-agent**, the persistent self-recovering agent runtime.
If the ACP stack is the *network* (how agents talk), the runtime is the
*organism* (how an agent lives): a durable task loop with SQLite as the
source of truth, crash/hang recovery, capability-gated tools, and
independent verification of every result.

Upstream project: the code was developed as the standalone `vm-agent`
runtime and merged into this repo at `runtime/` so the whole system —
protocol, connector, and the agents themselves — ships as one.

## How it fits together

```
┌──────────────────────────────────────────────────────────┐
│ vm-agent runtime (runtime/)                              │
│  task loop: steps -> tools -> verify -> checkpoint       │
│  tools: acp | http_get | shell | write_file | mkdir ...  │
│  capabilities: ACP_NETWORK | NETWORK_ACCESS | SHELL ...  │
│                          │                               │
│   acp tool = AcpBridge (runtime/src/acp_bridge.py)       │
│                          │ one Connector per ACP home    │
└──────────────────────────┼──────────────────────────────┘
                           │ ACP 1.0 frames
              ┌────────────▼─────────────┐
              │ acp_connector (packages/)│
              │ identity/pairing/msg/    │
              │ files/groups/voice/...   │
              └──────────────────────────┘
```

The runtime never re-implements crypto, pairing, or transport. The
`acp` tool is a thin adapter: it lazily imports the ACP stack (from the
monorepo's `packages/` in dev, or from the installed `$PREFIX/lib` in
production), holds one `Connector` per ACP home directory, and exposes
one op per protocol step.

## The `acp` tool ops

| Op | Args | What it does |
|---|---|---|
| `init` | `passphrase`, `handle`, `home` | Create/unlock identity (idempotent). Sets the default home for later ops. |
| `serve` | `passphrase`, `host`, `port` | Listen for inbound connections (port `0` = ephemeral). |
| `identity` | `passphrase` | Return `peer_id`, handle, public keys. Read-only. |
| `pair` | `passphrase`, `host`, `port` | **Initiator:** connect + send `pair_request`. Non-blocking — returns `session_id`. |
| `pair_status` | `passphrase`, `session_id` | Poll a pairing session (`await_challenge`, `await_code`, `done`, ...). |
| `pair_requests` | `passphrase` | **Responder:** list inbound pairing requests (with codes). |
| `pair_accept` | `passphrase`, `session_id` | **Responder:** accept → sends the challenge. |
| `pair_confirm` | `passphrase`, `session_id`, `code` | **Initiator:** confirm the code read off-band → `done`. |
| `message` | `passphrase`, `peer`, `text` | Send an E2E message. |
| `inbox` | `passphrase`, `limit` | Read received messages (newest first). |
| `peers` | `passphrase` | List paired peers. |
| `send_file` | `passphrase`, `peer`, `path` | Offer a file. Refuses runtime protected trees (state, config, acp, ...). |
| `market_install` | `passphrase`, `package_dir` | Verify sig + install a marketplace package (see below). |
| `stop` | `passphrase` | Stop the server, drop connectors. |

A typical pairing dance for a task plan:

1. responder: `serve` → `pair_requests` → `pair_accept`
2. initiator: `pair` → poll `pair_status` → `pair_confirm` (code from the responder's operator)
3. either side: `message`, `send_file`, ...

Pairing is intentionally multi-step: the 6-character code must travel
off-band (voice, QR, another channel), which is the whole point of the
code dance.

## Passphrase handling (read this)

- The passphrase is passed **per op**, ideally as a vault reference:
  `{"vault": "acp_passphrase"}`. The bridge resolves vault refs through
  the runtime's secrets store.
- It is **never logged** (the executor redacts the `passphrase`
  argument name, and the bridge never returns it), never stored in
  task state, and never leaves the `AcpBridge` call that unlocks the
  identity key.
- The bridge keeps the **unlocked Connector**, not the passphrase.
  `stop` drops it.

## Two-way protection

The integration is defended in both directions:

1. **Network → runtime.** Inbound files auto-accept into
   `<acp home>/incoming/` under sanitized names, are sha256-verified
   against the offer, and are **never executed**. Marketplace packages
   verify the publisher's Ed25519 signature against a **trusted peer's**
   key (the publisher must be someone you paired with) before anything
   is copied.
2. **Runtime → network.** The ACP home (`<base>/acp`, which holds the
   encrypted `identity.key`) is a **protected tree** in the runtime
   policy, alongside `state/`, `config/`, `lib/vmagent/`, `run/`.
   Task steps (`write_file`, `mkdir`) cannot modify it, and `send_file`
   refuses to exfiltrate from it — a compromised task plan can't steal
   the agent's identity key over the network it was given.

## Marketplace install semantics

`market_install` does three things and explicitly does **not** do a
fourth:

1. Verifies the manifest's publisher signature against the trusted
   peer's `ed_pub` (unknown publisher → refused).
2. Verifies every file's sha256 and installs to
   `<acp home>/market/<name>-<version>/`.
3. If the package bundles a `task.json`, validates it **structurally**
   against the task schema (steps have name/tool/args; verify specs
   reference known checks) and reports `valid`/`errors`.
4. **Never auto-executes** the task spec. Installing a capability and
   running it are separate, operator-approved decisions.

## Capabilities and verification

- The `acp` tool requires the **`ACP_NETWORK`** capability — separate
  from `NETWORK_ACCESS` (plain HTTP) and from `SHELL`. Granting a task
  web access does not grant it the agent network.
- Dry-run policy verdict for `acp` steps is **RESTRICTED** (allowed,
  but journaled for audit).
- The verifier's `acp` check re-runs **read-only** ops (`identity`,
  `peers`, `inbox`) to confirm claimed results. Mutating ops are
  rejected as verify checks — verification must not change the world.
- Task specs can carry vault references inside `verify` blocks; the
  agent resolves them before running the check.

## Voice

The runtime has no stdlib microphone/speaker I/O, same as the ACP
voice design: voice calls use the documented Source/Sink seam
(`docs/VOICE.md`). Platform code (the phone app, a desktop client)
injects and plays audio at the edges; the runtime only moves frames.

## Operating it

- Install: `cd runtime && sudo VM_AGENT_HOME=/opt/vm-agent bash
  ./install.sh` — installs the runtime to the prefix, installs the ACP
  `packages/acp_*` into `$PREFIX/lib`, then records the integrity
  baseline.
- Configure: `runtime/config.json` — `acp_home` (default
  `<base>/acp`), `acp_serve_host`/`acp_serve_port`, and the `acp: 180`
  tool timeout.
- The runtime's own test suite: `cd runtime && python3 -m pytest
  tests/ -q`. Note: 6 supervisor-level tests in `test_vm.py` need a
  real `/opt/vm-agent` install and fail without it (environmental —
  same upstream); CI installs first, so they're green there.
- CI: `.github/workflows/runtime-tests.yml` runs the runtime suite;
  `.github/workflows/tests.yml` runs the ACP suite.

## Honest limits

- The bridge is **not** a second implementation of ACP — it's a
  consumer of `packages/`. If the ACP stack isn't importable, every
  `acp` op fails cleanly with `acp_bridge: ACP stack not installed`.
- File offers auto-accept (quarantine, hash-verified, never executed).
  If you want manual approval per file, set the connector policy's
  `auto_accept_files=False` and register an offer callback — the
  bridge doesn't expose that yet.
- `serve` binds a plain TCP port. Put it behind the relay or a VPN
  (Tailscale/WireGuard) if the agent isn't on a trusted LAN.
- The runtime's crypto posture is inherited from the ACP stack:
  pure-Python, RFC-correct, not constant-time. Same guidance — swap
  in libsodium before adversarial deployment.
