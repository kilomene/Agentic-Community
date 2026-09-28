"""Hardware-attestation wire format and verification (protocol core).

Attestation (produced by the device)::

    attestation = {
        "agent_id":     b62(Ed25519 agent public key),
        "device_id":    b62(Ed25519 device public key),
        "hw_model":     "acp-virtual-1",
        "firmware_hash": sha256 hex of the running firmware image,
        "ts":           unix seconds when the device signed,
        "device_sig":   b62(Ed25519_sign(device_priv,
                            canonical({agent_id, device_id, hw_model,
                                       firmware_hash, ts}))),
    }

Binding (produced by the agent, proving it claims this device key)::

    binding = {
        "agent_id":   b62(Ed25519 agent public key),
        "device_pub": b62(Ed25519 device public key),
        "ts":         unix seconds when the agent signed,
        "agent_sig":  b62(Ed25519_sign(agent_priv,
                            canonical({agent_id, device_pub, ts}))),
    }

The pair travels inside ``hw_attest`` (E2E): the ``attestation`` field
is the spec'd payload; ``binding`` rides alongside as an extra field
(unknown/extra fields are ignored per PROTOCOL.md section 10, and the
kind schema only *requires* ``attestation``).

Verification (``check_attestation`` / ``verify_attestation``):

1. ``binding.agent_id == attestation.agent_id == expected peer id``.
2. ``agent_sig`` verifies with the agent's identity key
   (``binding`` is genuine).
3. ``attestation.device_id == b62(device_pub from binding)``
   (the device key in the binding is the key that signed).
4. ``device_sig`` verifies with that device key
   (the attestation is genuine).
5. Both ``ts`` values are fresh (``|now - ts| <= max_age``).
6. Optionally, ``firmware_hash`` is in an allowlist.

The software reference in ``device.py`` signs with a device key held in
process memory. Real hardware would keep ``device_priv`` in a secure
element and sign there; the bytes on the wire are identical either way.
"""
import time

from acp_crypto import ed25519_sign, ed25519_verify
from acp_proto import AcpError, b62encode, b62decode_fixed, b62encode_fixed, canonical

ATTESTATION_MAX_AGE = 300  # seconds


# ------------------------------------------------------------------ signing

def _attestation_body(agent_id, device_id, hw_model, firmware_hash, ts):
    return {"agent_id": agent_id, "device_id": device_id,
            "hw_model": hw_model, "firmware_hash": firmware_hash, "ts": ts}


def _binding_body(agent_id, device_pub_b62, ts):
    return {"agent_id": agent_id, "device_pub": device_pub_b62, "ts": ts}


def sign_attestation(device_priv: bytes, agent_id: str, device_id: str,
                     hw_model: str, firmware_hash: str,
                     ts=None) -> dict:
    """Build a device-signed attestation dict (sigs b62-encoded)."""
    ts = int(time.time()) if ts is None else int(ts)
    body = _attestation_body(agent_id, device_id, hw_model,
                             firmware_hash, ts)
    sig = ed25519_sign(device_priv, canonical(body))
    return dict(body, device_sig=b62encode_fixed(sig))


def sign_binding(agent_priv: bytes, agent_id: str,
                 device_pub: bytes, ts=None) -> dict:
    """Build an agent-signed binding dict (sigs b62-encoded)."""
    ts = int(time.time()) if ts is None else int(ts)
    body = _binding_body(agent_id, b62encode_fixed(device_pub), ts)
    sig = ed25519_sign(agent_priv, canonical(body))
    return dict(body, agent_sig=b62encode_fixed(sig))


# -------------------------------------------------------------- verification

def check_attestation(attestation: dict, binding: dict,
                      agent_pub: bytes, expected_agent_id=None,
                      now=None, max_age=ATTESTATION_MAX_AGE,
                      firmware_allowlist=None):
    """Verify an attestation + binding pair. Raises AcpError; returns
    True on success. ``agent_pub`` is the agent's 32-byte Ed25519 key."""
    now = int(time.time()) if now is None else now
    if not isinstance(attestation, dict) or not isinstance(binding, dict):
        raise AcpError("BAD_ENVELOPE", "attestation/binding must be dicts")

    agent_id = attestation.get("agent_id")
    if agent_id != binding.get("agent_id"):
        raise AcpError("BAD_ENVELOPE",
                       "agent_id mismatch between attestation and binding")
    if expected_agent_id is not None and agent_id != expected_agent_id:
        raise AcpError("BAD_ENVELOPE",
                       "attestation is not for the expected agent")

    # 2. binding signature (agent identity key)
    try:
        b_pub_raw = b62decode_fixed(binding["device_pub"])
        b_sig = b62decode_fixed(binding["agent_sig"])
    except (KeyError, ValueError, AttributeError) as e:
        raise AcpError("BAD_ENVELOPE", "binding encoding invalid: %s" % e)
    b_body = _binding_body(binding["agent_id"], binding["device_pub"],
                           binding["ts"])
    if not ed25519_verify(agent_pub, canonical(b_body), b_sig):
        raise AcpError("INVALID_SIG", "binding agent_sig invalid")

    # 3. device key agreement: the key the agent bound must be the key
    #    named (and signing) in the attestation.
    if len(b_pub_raw) != 32:
        raise AcpError("BAD_ENVELOPE", "binding device_pub wrong length")
    if attestation.get("device_id") != b62encode(b_pub_raw):
        raise AcpError("BAD_ENVELOPE",
                       "device key mismatch: binding names a different "
                       "device key than the attestation")

    # 4. attestation signature (device key)
    try:
        a_sig = b62decode_fixed(attestation["device_sig"])
    except (KeyError, ValueError, AttributeError) as e:
        raise AcpError("BAD_ENVELOPE",
                       "attestation encoding invalid: %s" % e)
    a_body = _attestation_body(attestation["agent_id"],
                               attestation["device_id"],
                               attestation["hw_model"],
                               attestation["firmware_hash"],
                               attestation["ts"])
    if not ed25519_verify(b_pub_raw, canonical(a_body), a_sig):
        raise AcpError("INVALID_SIG", "attestation device_sig invalid")

    # 5. freshness on both timestamps
    for label, ts in (("attestation", attestation.get("ts")),
                      ("binding", binding.get("ts"))):
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            raise AcpError("BAD_ENVELOPE",
                           "%s ts is not an integer" % label)
        if abs(now - ts) > max_age:
            raise AcpError("EXPIRED",
                           "%s ts=%d is outside the %ds acceptance window"
                           % (label, ts, max_age))

    # 6. firmware allowlist (optional)
    if firmware_allowlist is not None:
        if attestation.get("firmware_hash") not in firmware_allowlist:
            raise AcpError("POLICY_DENIED",
                           "firmware_hash not in allowlist")
    return True


def verify_attestation(attestation: dict, binding: dict, agent_pub: bytes,
                       expected_agent_id=None, now=None,
                       max_age=ATTESTATION_MAX_AGE,
                       firmware_allowlist=None) -> bool:
    """Boolean wrapper around :func:`check_attestation`. Never raises;
    returns False for any verification failure (including malformed
    input)."""
    try:
        check_attestation(attestation, binding, agent_pub,
                          expected_agent_id=expected_agent_id, now=now,
                          max_age=max_age,
                          firmware_allowlist=firmware_allowlist)
        return True
    except (AcpError, Exception):
        return False
