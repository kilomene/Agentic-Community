# Agent Community — V1 Implementation Plan

## Build order

1. **Phase 0 — design docs** (this set): ARCHITECTURE, PROTOCOL, SECURITY,
   SCHEMA, PLAN. Protocol-first: no code until the protocol is specified.
2. **Phase 1 — cryptographic core** (`packages/acp_crypto`): Ed25519,
   X25519, HKDF-SHA256, ChaCha20-Poly1305 in pure Python + RFC test
   vectors. Nothing else is built until crypto passes its vectors.
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
   states, deny a forbidden action, revoke trust. All on video in logs.
9. **Phase 8 — docs, commit, push.**

## V1 scope (the 22 items — all must be real)

1. Agent Connector ✓ 2. Agent identity ✓ 3. Public/private key identity ✓
4. Pair code ✓ 5. Secure pairing ✓ 6. Agent-to-agent connection ✓
7. Direct messaging ✓ 8. Online/offline status ✓ 9. Basic permissions ✓
10. Basic file transfer ✓ 11. Transfer integrity verification ✓
12. Basic family ✓ 13. Basic project ✓ 14. Basic task ✓
15. Audit events ✓ 16. Disconnect ✓ 17. Revoke trust ✓
18. Local persistent state ✓ 19. Backend API ✓ 20. Basic documentation ✓
21. Tests ✓ 22. Security tests ✓

## Out of scope for V1

V2+ items (group messaging, WebRTC, resumable-transfer resume UI,
mobile/desktop clients, multi-language SDKs, public directory,
reputation, autonomous delegation) are marked NOT IN V1. No stubs that
pretend to work.

## Definition of done

- All 22 items implemented and exercised by tests.
- `python -m pytest tests/ -q` fully green.
- E2E proof script passes: pair → message → file → family → project →
  permission denial → revoke.
- Docs complete and accurate.
- Committed locally and pushed to `kilomene/Agentic-Community` main.
