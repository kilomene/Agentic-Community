"""HardwareAgent: mixin showing how a connector requests and verifies
hardware attestation from a peer.

Usage::

    from acp_hwagent import HardwareAgent

    class MyAgent(HardwareAgent):
        def __init__(self, connector):
            super().__init__(connector,
                             firmware_allowlist={"<sha256 hex>", ...})

    agent = MyAgent(connector)
    attestation = agent.request_attestation(peer_id)   # raises on failure
    ok = agent.verify_attestation(peer_id, attestation, binding)

The verifier side never touches device private keys — it only checks
signatures against the peer's agent identity key (from the trust
store) and the device key the agent bound in ``binding``.

The firmware allowlist is optional: pass a set of accepted
``firmware_hash`` values to pin the peer's firmware, or None to skip
that check (attestation still proves *which* device key signed, and
that the agent claimed it).
"""
import threading
import time

from acp_crypto import random_bytes
from acp_proto import AcpError

from . import HW_ATTEST, HW_ATTEST_CHALLENGE, HW_CAPABILITIES
from .protocol import (ATTESTATION_MAX_AGE, check_attestation,
                       verify_attestation as _verify)

ATTEST_TIMEOUT = 30


class HardwareAgent:
    """Verifier mixin. Instantiate with a live Connector (or subclass)."""

    def __init__(self, connector, firmware_allowlist=None,
                 attestation_max_age=ATTESTATION_MAX_AGE):
        self._hw = connector
        self._hw_allowlist = (set(firmware_allowlist)
                              if firmware_allowlist is not None else None)
        self._hw_max_age = attestation_max_age
        self._hw_lock = threading.Lock()
        # peer_id -> {"event", "challenge", "sent_at",
        #             "attestation", "binding"}
        self._hw_pending = {}
        self._hw_attested = {}  # peer_id -> (attestation, binding)
        self._hw_cap_cbs = []
        connector.register_kind_handler(HW_ATTEST, self._on_hw_attest)
        connector.register_kind_handler(HW_CAPABILITIES,
                                        self._on_hw_capabilities)

    # --------------------------------------------------------------- request
    def request_attestation(self, peer_id, timeout=ATTEST_TIMEOUT):
        """Challenge a peer's device and return its attestation dict.

        Sends ``hw_attest_challenge`` E2E, waits for ``hw_attest``,
        then fully verifies (binding sig with the peer's agent key,
        device sig with the bound device key, freshness — including
        that the attestation is newer than the challenge, so replays
        of older attestations are rejected — and the firmware
        allowlist when configured). Returns the attestation dict;
        raises AcpError on any failure.
        """
        c = self._hw
        c._require_peer(peer_id)  # unknown/revoked peer -> AcpError
        challenge = random_bytes(16).hex()
        ev = threading.Event()
        sent_at = time.time()
        with self._hw_lock:
            self._hw_pending[peer_id] = {
                "event": ev, "challenge": challenge, "sent_at": sent_at,
                "attestation": None, "binding": None,
            }
        try:
            c._send_e2e(HW_ATTEST_CHALLENGE, peer_id,
                        {"challenge": challenge})
            if not ev.wait(timeout):
                raise AcpError("INTERNAL",
                               "no hw_attest response from %s within %ds"
                               % (peer_id[:12], timeout))
            with self._hw_lock:
                slot = self._hw_pending.pop(peer_id)
            attestation, binding = (slot["attestation"], slot["binding"])
            if attestation is None:
                raise AcpError("INTERNAL",
                               "hw_attest arrived without an attestation")
            # The answer must be newer than the challenge: a replayed
            # older attestation fails here even if its signatures are
            # otherwise valid.
            try:
                a_ts = int(attestation.get("ts", 0))
            except (TypeError, ValueError):
                raise AcpError("BAD_ENVELOPE",
                               "attestation ts is not an integer")
            if a_ts < int(sent_at) - 5:
                raise AcpError("EXPIRED",
                               "attestation predates the challenge "
                               "(possible replay)")
            self._check(peer_id, attestation, binding)
            with self._hw_lock:
                self._hw_attested[peer_id] = (attestation, binding)
            c.audit.log("hw.attestation_verified", actor=peer_id,
                        result="ok",
                        details={"device_id": attestation.get("device_id")})
            return attestation
        finally:
            with self._hw_lock:
                self._hw_pending.pop(peer_id, None)

    # ---------------------------------------------------------------- verify
    def verify_attestation(self, peer_id, attestation, binding) -> bool:
        """Verify a (attestation, binding) pair for ``peer_id`` against
        the peer's agent identity key from the trust store. Returns
        True/False, never raises (unknown peer -> False)."""
        try:
            peer = self._hw.store.get_peer(peer_id)
            if peer is None or peer["revoked"] or not peer["ed_pub"]:
                return False
            agent_pub = bytes.fromhex(peer["ed_pub"])
        except (ValueError, TypeError, KeyError):
            return False
        return _verify(attestation, binding, agent_pub,
                       expected_agent_id=peer_id, max_age=self._hw_max_age,
                       firmware_allowlist=self._hw_allowlist)

    def get_attestation(self, peer_id):
        """Last verified (attestation, binding) for a peer, or None."""
        with self._hw_lock:
            return self._hw_attested.get(peer_id)

    # ----------------------------------------------------------- capabilities
    def on_capabilities(self, cb):
        """Register ``cb(peer_id, payload)`` for inbound
        ``hw_capabilities``. Payload: ``{"device_id", "capabilities",
        "fw_hash"}``."""
        self._hw_cap_cbs.append(cb)

    # -------------------------------------------------------------- internals
    def _check(self, peer_id, attestation, binding):
        """Full verification that raises AcpError with a precise code."""
        peer = self._hw.store.get_peer(peer_id)
        if peer is None or peer["revoked"] or not peer["ed_pub"]:
            raise AcpError("NOT_FOUND", "unknown peer %s" % peer_id[:12])
        agent_pub = bytes.fromhex(peer["ed_pub"])
        check_attestation(attestation, binding, agent_pub,
                          expected_agent_id=peer_id,
                          max_age=self._hw_max_age,
                          firmware_allowlist=self._hw_allowlist)

    def _on_hw_attest(self, conn, env, payload):
        peer_id = env["from"]
        with self._hw_lock:
            slot = self._hw_pending.get(peer_id)
        if slot is None:
            self._hw.audit.log("hw.unexpected_attest", actor=peer_id,
                               result="denied", details={})
            return
        with self._hw_lock:
            slot["attestation"] = payload.get("attestation")
            slot["binding"] = payload.get("binding")
            slot["event"].set()

    def _on_hw_capabilities(self, conn, env, payload):
        peer_id = env["from"]
        self._hw.audit.log("hw.capabilities_received", actor=peer_id,
                           result="ok",
                           details={"device_id": payload.get("device_id"),
                                    "capabilities":
                                        payload.get("capabilities")})
        for cb in list(self._hw_cap_cbs):
            try:
                cb(peer_id, payload)
            except Exception as e:
                self._hw.audit.log("hw.capability_callback_error",
                                   actor=peer_id, result="failed",
                                   details={"error": str(e)})
