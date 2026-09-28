"""Tests for acp_hwagent: attestation protocol + VirtualDevice +
HardwareAgent verifier, including attack tests.

Conventions: pure verification tests build attestations directly with
VirtualDevice.attest(); the wire tests pair two real Connectors and
run request_attestation / capabilities over E2E envelopes.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_connector import Connector, AcpError  # noqa: E402
from acp_crypto import generate_ed25519_keypair  # noqa: E402
from acp_proto import (  # noqa: E402
    ALL_KINDS, E2E_KINDS, b62encode, b62decode,
    b62encode_fixed, b62decode_fixed,
)
from acp_hwagent import (  # noqa: E402
    HW_ATTEST, HW_ATTEST_CHALLENGE, HW_CAPABILITIES,
    ATTESTATION_MAX_AGE, HardwareAgent, VirtualDevice,
    check_attestation, verify_attestation,
)
from acp_hwagent.device import REFERENCE_FIRMWARE_HASH  # noqa: E402


# ------------------------------------------------------------------ fixtures

def _agent_keys():
    priv, pub = generate_ed25519_keypair()
    return priv, b62encode(pub)


@pytest.fixture()
def dev_and_agent():
    device = VirtualDevice()  # SOFTWARE reference — see module docstring
    agent_priv, agent_id = _agent_keys()
    attestation, binding = device.attest(agent_id, agent_priv)
    agent_pub = b62decode(agent_id)
    return device, agent_priv, agent_id, agent_pub, attestation, binding


def _pair(c1, c2, port2):
    """Pair c1 -> c2 (raw connectors)."""
    got = threading.Event()
    box = {}

    def on_req(s):
        box["code"] = s.code
        s.accept()
        got.set()

    c2.on_pairing_request(on_req)
    s1 = c1.pair_initiate("127.0.0.1", port2)
    assert got.wait(30), "responder never got pair_request"
    deadline = time.time() + 30
    while s1.state == "await_challenge" and time.time() < deadline:
        time.sleep(0.1)
    assert s1.state == "await_code", "challenge never processed"
    s1.confirm(box["code"])
    deadline = time.time() + 30
    while s1.state != "done" and time.time() < deadline:
        time.sleep(0.1)
    assert s1.state == "done", "pairing did not complete"
    return s1


@pytest.fixture()
def paired(tmp_path):
    c1 = Connector(str(tmp_path / "h1"), "hw-test-1", handle="verifier")
    c2 = Connector(str(tmp_path / "h2"), "hw-test-2", handle="device-agent")
    c1.start_server("127.0.0.1", 0)
    port2 = c2.start_server("127.0.0.1", 0)
    _pair(c1, c2, port2)
    yield c1, c2
    c1.stop()
    c2.stop()


# ------------------------------------------------------------- protocol tests

def test_kinds_registered_and_e2e():
    for kind in (HW_ATTEST_CHALLENGE, HW_ATTEST, HW_CAPABILITIES):
        assert kind in ALL_KINDS
        assert kind in E2E_KINDS


def test_valid_attestation_verifies(dev_and_agent):
    _, _, agent_id, agent_pub, attestation, binding = dev_and_agent
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id) is True
    assert check_attestation(attestation, binding, agent_pub,
                             expected_agent_id=agent_id) is True


def test_forged_device_sig_fails(dev_and_agent):
    device, agent_priv, agent_id, agent_pub, attestation, binding = \
        dev_and_agent
    attestation = dict(attestation)
    # attacker flips the device signature bytes
    raw = bytearray(b62decode_fixed(attestation["device_sig"]))
    raw[0] ^= 0xFF
    attestation["device_sig"] = b62encode_fixed(bytes(raw))
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id) is False
    with pytest.raises(AcpError) as exc:
        check_attestation(attestation, binding, agent_pub,
                          expected_agent_id=agent_id)
    assert exc.value.code == "INVALID_SIG"


def test_attestation_replay_old_ts_rejected(dev_and_agent):
    device, agent_priv, agent_id, agent_pub, _, _ = dev_and_agent
    old_ts = int(time.time()) - (ATTESTATION_MAX_AGE + 3600)
    attestation, binding = device.attest(agent_id, agent_priv, ts=old_ts)
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id) is False
    with pytest.raises(AcpError) as exc:
        check_attestation(attestation, binding, agent_pub,
                          expected_agent_id=agent_id)
    assert exc.value.code == "EXPIRED"


def test_binding_signed_by_wrong_agent_key_rejected(dev_and_agent):
    device, agent_priv, agent_id, agent_pub, attestation, _ = dev_and_agent
    wrong_priv, _ = generate_ed25519_keypair()
    # attacker re-signs the binding with a different agent key
    from acp_hwagent.protocol import sign_binding
    bad_binding = sign_binding(wrong_priv, agent_id, device.device_pub)
    assert verify_attestation(attestation, bad_binding, agent_pub,
                              expected_agent_id=agent_id) is False
    with pytest.raises(AcpError) as exc:
        check_attestation(attestation, bad_binding, agent_pub,
                          expected_agent_id=agent_id)
    assert exc.value.code == "INVALID_SIG"


def test_device_key_mismatch_rejected(dev_and_agent):
    device, agent_priv, agent_id, agent_pub, _, _ = dev_and_agent
    other = VirtualDevice()  # a *different* device key
    attestation, _ = other.attest(agent_id, agent_priv)
    # binding names device's key, attestation is signed by other's key
    _, binding = device.attest(agent_id, agent_priv)
    assert attestation["device_id"] != binding["device_pub"]
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id) is False
    with pytest.raises(AcpError) as exc:
        check_attestation(attestation, binding, agent_pub,
                          expected_agent_id=agent_id)
    assert exc.value.code == "BAD_ENVELOPE"


def test_tampered_firmware_hash_fails(dev_and_agent):
    _, _, agent_id, agent_pub, attestation, binding = dev_and_agent
    attestation = dict(attestation, firmware_hash="00" * 32)
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id) is False


def test_firmware_allowlist(dev_and_agent):
    _, _, agent_id, agent_pub, attestation, binding = dev_and_agent
    assert verify_attestation(
        attestation, binding, agent_pub, expected_agent_id=agent_id,
        firmware_allowlist={REFERENCE_FIRMWARE_HASH}) is True
    assert verify_attestation(
        attestation, binding, agent_pub, expected_agent_id=agent_id,
        firmware_allowlist={"deadbeef"}) is False
    # no allowlist -> not checked
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id=agent_id,
                              firmware_allowlist=None) is True


def test_wrong_expected_agent_id_rejected(dev_and_agent):
    _, _, _, agent_pub, attestation, binding = dev_and_agent
    assert verify_attestation(attestation, binding, agent_pub,
                              expected_agent_id="someone-else") is False


def test_malformed_input_never_raises(dev_and_agent):
    _, _, agent_id, agent_pub, _, _ = dev_and_agent
    assert verify_attestation(None, None, agent_pub) is False
    assert verify_attestation({}, {}, agent_pub) is False
    assert verify_attestation({"agent_id": agent_id}, {}, agent_pub) is False


# ---------------------------------------------------------------- wire tests

def test_request_attestation_over_wire(paired):
    c1, c2 = paired
    device = VirtualDevice().attach(c2)  # SOFTWARE reference device
    verifier = HardwareAgent(c1,
                             firmware_allowlist={REFERENCE_FIRMWARE_HASH})

    attestation = verifier.request_attestation(c2.peer_id, timeout=30)
    assert attestation["agent_id"] == c2.peer_id
    assert attestation["device_id"] == device.device_id
    assert attestation["hw_model"] == "acp-virtual-1"
    assert device.challenges_answered == 1

    _, binding = verifier.get_attestation(c2.peer_id)
    assert verifier.verify_attestation(c2.peer_id, attestation,
                                       binding) is True


def test_verify_unknown_peer_returns_false(paired):
    c1, _ = paired
    verifier = HardwareAgent(c1)
    assert verifier.verify_attestation("no-such-peer", {}, {}) is False


def test_replayed_attestation_rejected_on_wire(paired):
    """An attestation older than the challenge is rejected even though
    its signatures are valid and fresh (anti-replay)."""
    c1, c2 = paired
    device = VirtualDevice().attach(c2)
    verifier = HardwareAgent(c1)

    real_attest = device.attest

    def stale_attest(agent_id, agent_priv, ts=None):
        return real_attest(agent_id, agent_priv,
                           ts=int(time.time()) - 100)

    device.attest = stale_attest
    try:
        with pytest.raises(AcpError) as exc:
            verifier.request_attestation(c2.peer_id, timeout=30)
        assert exc.value.code == "EXPIRED"
    finally:
        device.attest = real_attest


def test_capabilities_advertised_over_wire(paired):
    c1, c2 = paired
    device = VirtualDevice().attach(c2)
    verifier = HardwareAgent(c1)
    got = []
    arrived = threading.Event()
    verifier.on_capabilities(
        lambda peer_id, payload: (got.append((peer_id, payload)),
                                  arrived.set()))
    device.advertise_capabilities(c1.peer_id)
    assert arrived.wait(30), "capabilities never arrived"
    peer_id, payload = got[0]
    assert peer_id == c2.peer_id
    assert payload["device_id"] == device.device_id
    assert "sensor:temperature" in payload["capabilities"]
    assert "actuator:led" in payload["capabilities"]
    assert payload["fw_hash"] == REFERENCE_FIRMWARE_HASH


def test_attestation_requires_pairing(paired):
    c1, _ = paired
    verifier = HardwareAgent(c1)
    with pytest.raises(AcpError):
        verifier.request_attestation("unknown-peer-id", timeout=5)
