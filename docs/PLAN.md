# Agent Community — Implementation Plan (V1 → V4, complete)

## Build order

V1 (phases 0–8, all done):
1. **Phase 0 — design docs**: ARCHITECTURE, PROTOCOL, SECURITY,
   SCHEMA, PLAN. Protocol-first: no code until the protocol is specified.
2. **Phase 1 — cryptographic core** (`packages/acp_crypto`): Ed25519,
   X25519, HKDF-SHA256, ChaCha20-Poly1305 in pure Python + RFC test
   vectors. Nothing else was built until crypto passed its vectors.
3. **Phase 2 — protocol** (`packages/acp_proto`): envelopes, canonical
   JSON, signing/verification, E2E encryption, framing, all V1 message
   types, error codes + protocol tests.
4. **Phase 3 — connector** (`packages/acp_connector`): SQLite store,
   identity + key management, pairing state machine, connection manager,
   messaging, presence, file transfer, permissions, family, projects/tasks,
   policy engine, audit logging, local event bridge.
5. **Phase 4 — services** (`services/acp_api`, `services/acp_relay`):
   registry, pairing sessions, offline mailbox, presence, revocation list;
   TCP relay with ciphertext-only routing.
6. **Phase 5 — CLI** (`apps/acp_cli`): every spec command working
   against a real connector.
7. **Phase 6 — tests**: unit, protocol, integration (A↔B, A↔B↔C),
   security (pairing abuse, replay, tampering, permission escalation,
   path traversal), file integrity, offline/reconnect.
8. **Phase 7 — end-to-end proof**: two real connector instances pair
   with real codes, exchange encrypted messages, transfer a real file
   with hash verification, form a family, run a project through task
   states, deny a forbidden action, revoke trust.
9. **Phase 8 — docs, commit, push.**

V2 (done): E2E group chat, voice calls, offline mailbox, relay
federation, connector scheduler — each with unit + security tests.

V3 (done): registry search + identity verification + analytics +
public API (scoped keys, rate limits), local dashboard, i18n (6
locales), Python SDK — each with tests incl. attack tests.

V4 (done): signed-capability marketplace (12 E2E kinds, escrow,
disputes), hardware-agent attestation + VirtualDevice — each with
tests incl. attack tests.

Final pass (done): fixed a base62 leading-zero encoding flake
(`b62encode_fixed`/`b62decode_fixed`, PROTOCOL §3.3), wired all new
modules into the Connector + `acp` CLI (`--lang`, `--api-key` via
`set-api-key`), merged the docs, full suite green, pushed to
`kilomene/Agentic-Community` main.

## V1 scope (the 22 items — all real)

1. Agent Connector ✓ 2. Agent identity ✓ 3. Public/private key identity ✓
4. Pair code ✓ 5. Secure pairing ✓ 6. Agent-to-agent connection ✓
7. Direct messaging ✓ 8. Online/offline status ✓ 9. Basic permissions ✓
10. Basic file transfer ✓ 11. Transfer integrity verification ✓
12. Basic family ✓ 13. Basic project ✓ 14. Basic task ✓
15. Audit events ✓ 16. Disconnect ✓ 17. Revoke trust ✓
18. Local persistent state ✓ 19. Backend API ✓ 20. Basic documentation ✓
21. Tests ✓ 22. Security tests ✓

## Definition of done (met)

- All 22 V1 items + all V2/V3/V4 items implemented and exercised by
  tests, including security attack tests.
- `python -m pytest tests/ -q` fully green.
- E2E proof script passes: pair → message → file → family → project →
  permission denial → revoke.
- Docs complete and accurate (per-component docs in `docs/`).
- Pushed to `kilomene/Agentic-Community` main.
