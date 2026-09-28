# ACP Hardware Agent Support

## The one thing to understand first

This is a **software reference speaking the real protocol**. Every
attestation below is a real Ed25519 signature that really verifies —
but the device private key lives in process memory, exactly like a
test double. Real hardware would generate and keep `device_priv`
inside a secure element / TPM and sign there, never exposing it to
the host OS. **The protocol is hardware-ready; the reference
implementation is not hardware.** `VirtualDevice.SOFTWARE_REFERENCE`
is `True`, and the docstrings say so on every class, because the
distinction matters.

## Protocol extension: new kinds

Registered via `acp_proto.register_kind` on `import acp_hwagent`
(all three are E2E-encrypted, signed like every other E2E kind):

| Kind | Schema | Direction |
|---|---|---|
| `hw_attest_challenge` | `{challenge}` | verifier → device agent |
| `hw_attest` | `{attestation}` (+`binding` alongside) | device agent → verifier |
| `hw_capabilities` | `{device_id, capabilities, fw_hash}` | device agent → verifier |

`hw_attest` carries the `binding` as an extra field next to the
spec'd `attestation` field; extra fields are ignored per PROTOCOL.md
§10, and the kind schema only *requires* `attestation`.

## Attestation format

**Attestation** (signed by the *device* key):

```json
{
  "agent_id":      "<b62 Ed25519 agent public key>",
  "device_id":     "<b62 Ed25519 device public key>",
  "hw_model":      "acp-virtual-1",
  "firmware_hash": "<sha256 hex of the firmware image>",
  "ts":            1759...,
  "device_sig":    "<b62 Ed25519_sign(device_priv, canonical({agent_id, device_id, hw_model, firmware_hash, ts}))>"
}
```

**Binding** (signed by the *agent* identity key — proves the agent
claims this device key):

```json
{
  "agent_id":   "<b62 Ed25519 agent public key>",
  "device_pub": "<b62 Ed25519 device public key>",
  "ts":         1759...,
  "agent_sig":  "<b62 Ed25519_sign(agent_priv, canonical({agent_id, device_pub, ts}))>"
}
```

## Verification

`acp_hwagent.protocol.check_attestation` (raises `AcpError`) /
`verify_attestation` (returns bool):

1. `binding.agent_id == attestation.agent_id == expected peer id`
2. `agent_sig` verifies with the agent's identity key from the trust store
3. `attestation.device_id == b62(device_pub from binding)` — the bound
   key is the signing key (catches device-key mismatch)
4. `device_sig` verifies with that device key
5. both timestamps fresh (`|now - ts| <= max_age`, default 300 s)
6. optional: `firmware_hash` in the verifier's allowlist

`HardwareAgent.request_attestation(peer_id)` additionally checks the
attestation is **newer than the challenge** it just sent, so a replayed
older attestation is rejected even if its signatures are valid.

Error codes: `INVALID_SIG` (bad binding or device signature),
`EXPIRED` (stale or pre-challenge attestation), `BAD_ENVELOPE`
(id mismatch, key mismatch, malformed), `POLICY_DENIED` (firmware not
in allowlist).

## Reference implementation

`packages/acp_hwagent/`:

- `protocol.py` — kinds, signing, verification (pure functions)
- `device.py` — `VirtualDevice`: generates a device Ed25519 keypair,
  produces attestations (`attest`), answers `hw_attest_challenge`
  (`attach(connector)`), advertises capabilities
  (`advertise_capabilities(peer_id)`), e.g. `sensor:temperature`,
  `actuator:led`
- `verifier.py` — `HardwareAgent` mixin: `request_attestation(peer_id)`
  → attestation dict or raises; `verify_attestation(peer_id,
  attestation, binding)` → bool; `on_capabilities(cb)`

## What real hardware would do differently

Only key custody and the signing venue change; the wire format is
identical:

- generate `device_priv` inside the secure element at manufacture;
  it never leaves
- `device_sig` computed inside the secure element over the same
  canonical bytes
- `firmware_hash` measured by secure boot, not a constant
- the agent's `binding` signature still comes from the agent identity
  key (already the trust anchor)

A verifier cannot tell the reference apart from real hardware from
the bytes alone — that is the point of a protocol-level spec — which
is why the *claim* "this attestation came from hardware" is only as
strong as the supply chain behind the device key. The allowlist is
where that trust is pinned.
