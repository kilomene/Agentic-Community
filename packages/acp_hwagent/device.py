"""VirtualDevice: SOFTWARE reference implementation of an ACP device.

Read this twice: this class is a *software* reference. It generates a
device Ed25519 keypair in process memory, signs attestations with it,
answers attestation challenges, and advertises capabilities — all with
real signatures over the real wire format, so every byte it emits is
indistinguishable from what compliant hardware would emit. What makes
it *not* hardware is key custody: real hardware would generate and
keep ``device_priv`` inside a secure element / TPM and sign there,
never exposing the private key to the host OS. This reference keeps
the key in a Python attribute. The protocol is hardware-ready; this
reference is not hardware.

Typical wiring (agent side)::

    from acp_hwagent import VirtualDevice
    device = VirtualDevice()            # SOFTWARE reference device
    device.attach(connector)            # answer hw_attest_challenge
    device.advertise_capabilities(peer_id)
"""
import hashlib
import threading
import time

from acp_crypto import generate_ed25519_keypair
from acp_proto import AcpError, b62encode

from . import HW_ATTEST, HW_ATTEST_CHALLENGE, HW_CAPABILITIES
from .protocol import sign_attestation, sign_binding

#: Firmware hash the reference device reports. A verifier allowlist
#: would pin this value (or real firmware measurements).
REFERENCE_FIRMWARE_HASH = hashlib.sha256(
    b"acp-virtual-device-firmware-v1").hexdigest()

#: Capabilities the reference device advertises.
REFERENCE_CAPABILITIES = ("sensor:temperature", "actuator:led")


class VirtualDevice:
    """SOFTWARE reference device. See module docstring for the honesty
    notice: real hardware keeps the device key in a secure element."""

    #: Set True anywhere to confirm this is the software reference.
    SOFTWARE_REFERENCE = True

    def __init__(self, hw_model="acp-virtual-1",
                 capabilities=None, firmware_hash=None):
        self.device_priv, self.device_pub = generate_ed25519_keypair()
        self.device_id = b62encode(self.device_pub)
        self.hw_model = hw_model
        self.capabilities = list(capabilities) if capabilities is not None \
            else list(REFERENCE_CAPABILITIES)
        self.firmware_hash = firmware_hash or REFERENCE_FIRMWARE_HASH
        self._connector = None
        self._lock = threading.Lock()
        self.challenges_answered = 0

    # ------------------------------------------------------------ attestation
    def attest(self, agent_id: str, agent_priv: bytes, ts=None):
        """Produce ``(attestation, binding)`` for ``agent_id``.

        ``agent_priv`` is the agent's 32-byte Ed25519 identity key; the
        binding signature proves the agent claims this device key. In
        real hardware the device would sign only the attestation half
        and the agent would sign the binding half itself; the reference
        does both here because it holds both keys in software.
        """
        attestation = sign_attestation(
            self.device_priv, agent_id, self.device_id, self.hw_model,
            self.firmware_hash, ts=ts)
        binding = sign_binding(agent_priv, agent_id, self.device_pub,
                               ts=ts)
        return attestation, binding

    # --------------------------------------------------------------- wiring
    def attach(self, connector):
        """Answer ``hw_attest_challenge`` envelopes on this connector.

        The challenge handler signs a fresh attestation + binding with
        the connector's identity (agent) key and the device key, and
        sends ``hw_attest`` back E2E. Idempotent.
        """
        with self._lock:
            if self._connector is connector:
                return self
            self._connector = connector
        connector.register_kind_handler(HW_ATTEST_CHALLENGE,
                                        self._on_challenge)
        return self

    def advertise_capabilities(self, peer_id):
        """Proactively send ``hw_capabilities`` to a paired peer."""
        c = self._require_connector()
        c._send_e2e(HW_CAPABILITIES, peer_id, {
            "device_id": self.device_id,
            "capabilities": list(self.capabilities),
            "fw_hash": self.firmware_hash,
        })

    # -------------------------------------------------------------- internals
    def _require_connector(self):
        if self._connector is None:
            raise AcpError("INTERNAL",
                           "device is not attached — call attach(connector)")
        return self._connector

    def _on_challenge(self, conn, env, payload):
        c = self._connector
        peer_id = env["from"]
        attestation, binding = self.attest(c.identity.peer_id,
                                           c.identity.ed_priv)
        c._send_e2e(HW_ATTEST, peer_id,
                    {"attestation": attestation, "binding": binding})
        with self._lock:
            self.challenges_answered += 1
        c.audit.log("hw.attestation_sent", actor=peer_id, result="ok",
                    details={"device_id": self.device_id,
                             "challenge": str(payload.get("challenge"))[:16]})
