# SDK Mobile Roadmap — an honest document

## Plain statement

**A native Android/iOS app is not buildable in this environment.**
This workspace is a Linux-only, Python-3-stdlib build host: no
Android SDK/NDK, no Xcode, no Kotlin/Swift toolchains, no signing
keys, no physical or emulated devices to test on. Any APK/IPA or
"screenshot" produced here would be fake, and shipping a fake would
be worse than shipping nothing. So there is no APK, no mock UI, and
no pretend screenshots in this repo — only the plan below, and the
protocol work that makes the plan possible.

## What IS real today (and why it matters for mobile)

The ACP 1.0 protocol is **transport-independent by design**:

- Envelopes are JSON with a 4-byte length prefix; nothing about them
  requires TCP specifically — the same bytes ride a WebSocket, BLE
  GATT characteristic, or HTTPS POST.
- All crypto is standard algorithms (Ed25519, X25519, HKDF-SHA256,
  ChaCha20-Poly1305), not Python-specific constructions. Any
  platform with these primitives speaks ACP byte-for-byte.
- `canonical()` is specified JSON (sorted keys, no whitespace,
  UTF-8) — reimplementable in any language and testable against the
  vectors in `tests/test_crypto.py` and `tests/test_proto.py`.
- The `acp_sdk` API surface (`AcpClient` methods) is the product
  spec for the mobile SDKs: same method names, same semantics, same
  error codes.

## Module port map (Python → native)

| Python module | Kotlin (Android) | Swift (iOS) | Notes |
|---|---|---|---|
| `acp_crypto` | libsodium via JNI (`crypto_sign_*`, `crypto_scalarmult`, `crypto_aead_chacha20poly1305_ietf`) | swift-sodium / CryptoKit (note: CryptoKit lacks Ed25519ph-verify compat subtleties — use libsodium-objc) | Must pass the RFC vectors in `test_crypto.py` before anything else |
| `acp_proto` | JSON framing + canonical JSON + envelope verify/open | same | Pure logic; unit-test against `test_proto.py` vectors |
| `acp_connector` (transport, pairing, messaging, files) | Android `Service` (foreground) + `Thread`/`Coroutine` I/O | iOS `Network.framework` / `URLSessionWebSocketTask`, background modes | Pairing UX: QR or 6-char code entry |
| `acp_connector` (store) | Room / SQLDelight | Core Data / GRDB | Schema mirrors `store.py` |
| `acp_connector` (identity) | Android Keystore | iOS Keychain / Secure Enclave | Never export identity keys — this is where mobile beats the Linux reference |
| `acp_hwagent` (device side) | StrongBox / Titan M attestation feeding `hw_attest` | Secure Enclave + DeviceCheck/AppAttest feeding `hw_attest` | The protocol kinds already exist; mobile fills them with *real* hardware roots |
| `acp_sdk` (`AcpClient`) | Kotlin SDK facade | Swift SDK facade | Same method names as this SDK |

## Phased roadmap

**P1 — protocol + crypto parity (no UI).** Port `acp_crypto`
semantics to libsodium bindings and `acp_proto` to JSON framing in
Kotlin and Swift. Gate: the ported code verifies the existing
`test_crypto.py` / `test_proto.py` vectors byte-for-byte, and a
Kotlin client and a Swift client can exchange a signed plaintext
envelope with the Python connector on localhost.

**P2 — connector service.** Port the connector runtime as a
background service: pairing handshake (with the code UX),
E2E messaging, chunked file transfer, presence. Gate: the
`test_connector.py` scenario (pair → message → file) runs between a
phone build and the Python connector, driven over the real network.

**P3 — UI.** Thin native UI over the P2 service: peer list, chat,
file inbox, pairing screen, attestation status badge (from
`hw_attest`). The UI holds no keys and implements no crypto — it
calls the SDK facade. Gate: dogfood two phones pairing and
messaging with no Python in the loop.

## Non-goals / explicit exclusions

- No cross-platform framework shortcut is assumed; the plan above is
  native-first because key custody (Keystore/Keychain/Secure
  Enclave) is the whole point of a mobile agent.
- The Python `AcpClient` remains the reference implementation and
  the interop test oracle for every phase.
- Push notifications, relay fallback for NAT traversal, and
  multi-device identity are out of scope for P1–P3 and need their
  own design docs.
