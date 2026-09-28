"""acp_hwagent: hardware-agent support for ACP 1.0 (SOFTWARE reference).

This package implements the hardware-attestation protocol extension:

* three new E2E kinds, registered via ``acp_proto.register_kind``:
  ``hw_attest_challenge``, ``hw_attest``, ``hw_capabilities``;
* the attestation + binding wire format (``protocol.py``);
* ``VirtualDevice`` (``device.py``): a SOFTWARE reference device that
  speaks the real protocol — generates a device Ed25519 keypair,
  produces attestations, answers challenges, advertises capabilities;
* ``HardwareAgent`` (``verifier.py``): a mixin showing how a connector
  requests and verifies attestation from a peer.

HONESTY NOTE, repeated deliberately: ``VirtualDevice`` is a software
reference. It keeps the device private key in process memory, exactly
like a test double. The *protocol* is hardware-ready (a real device
would keep ``device_priv`` in a secure element / TPM and sign there);
this *reference implementation* is not hardware. Do not mistake one
for the other.
"""
from acp_proto import register_kind

# ------------------------------------------------------------------ kinds
# Registered on import so any connector in this process accepts them.
HW_ATTEST_CHALLENGE = register_kind(
    "hw_attest_challenge", e2e=True, schema=("challenge",))
HW_ATTEST = register_kind(
    "hw_attest", e2e=True, schema=("attestation",))
HW_CAPABILITIES = register_kind(
    "hw_capabilities", e2e=True,
    schema=("device_id", "capabilities", "fw_hash"))

from .protocol import (  # noqa: E402
    ATTESTATION_MAX_AGE,
    check_attestation,
    sign_attestation,
    sign_binding,
    verify_attestation,
)
from .device import VirtualDevice  # noqa: E402
from .verifier import HardwareAgent  # noqa: E402

__all__ = [
    "HW_ATTEST_CHALLENGE",
    "HW_ATTEST",
    "HW_CAPABILITIES",
    "ATTESTATION_MAX_AGE",
    "VirtualDevice",
    "HardwareAgent",
    "sign_attestation",
    "sign_binding",
    "check_attestation",
    "verify_attestation",
]
