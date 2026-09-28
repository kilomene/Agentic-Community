"""Protocol-layer tests: canonical JSON, envelopes, E2E, framing."""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_crypto import generate_ed25519_keypair, generate_x25519_keypair
from acp_proto import (
    canonical, b62encode, b62decode, b62encode_fixed, b62decode_fixed,
    make_envelope, make_e2e_envelope, verify_envelope, open_e2e_envelope,
    frame_envelope, parse_frames, validate_payload, check_freshness,
    AcpError, MSG, PAIR_REQUEST, PROTOCOL_VERSION,
)


def make_identity():
    s_priv, s_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    pid = b62encode(s_pub)
    return {"pid": pid, "s_priv": s_priv, "s_pub": s_pub,
            "x_priv": x_priv, "x_pub": x_pub}


A = make_identity()
B = make_identity()
PUBKEYS = {A["pid"]: A["s_pub"], B["pid"]: B["s_pub"]}


def test_canonical_deterministic():
    o1 = {"b": 2, "a": 1, "nested": {"z": [3, 2], "a": "x"}}
    o2 = {"nested": {"a": "x", "z": [3, 2]}, "a": 1, "b": 2}
    assert canonical(o1) == canonical(o2)
    assert b" " not in canonical(o1)
    print("canonical JSON deterministic: OK")


def test_b62_roundtrip():
    for raw in (b"\x00" * 32, b"\xff" * 32, os.urandom(32)):
        assert b62decode_fixed(b62encode_fixed(raw)) == raw
    print("base62 fixed roundtrip: OK")


def test_plaintext_envelope_roundtrip():
    env = make_envelope(PAIR_REQUEST, A["pid"], B["pid"],
                        {"handle": "alice", "x_pub": b62encode(A["x_pub"]),
                         "ipub": b62encode(A["s_pub"])},
                        A["s_priv"])
    out = verify_envelope(env, PUBKEYS.get)
    assert out["payload"]["handle"] == "alice"
    assert out["acp"] == PROTOCOL_VERSION
    print("plaintext envelope sign/verify: OK")


def test_envelope_tamper_rejected():
    env = make_envelope(PAIR_REQUEST, A["pid"], B["pid"],
                        {"handle": "alice", "x_pub": b62encode(A["x_pub"]),
                         "ipub": b62encode(A["s_pub"])},
                        A["s_priv"])
    env["payload"] = dict(env["payload"], handle="mallory")
    try:
        verify_envelope(env, PUBKEYS.get)
        raise AssertionError("tampered envelope verified!")
    except AcpError as e:
        assert e.code == "INVALID_SIG", e.code
    print("envelope tamper -> INVALID_SIG: OK")


def test_unknown_sender_rejected():
    env = make_envelope(PAIR_REQUEST, A["pid"], B["pid"],
                        {"handle": "alice", "x_pub": b62encode(A["x_pub"]),
                         "ipub": b62encode(A["s_pub"])},
                        A["s_priv"])
    try:
        verify_envelope(env, lambda pid: None)
        raise AssertionError("unknown sender verified!")
    except AcpError as e:
        assert e.code == "UNKNOWN_SENDER", e.code
    print("unknown sender rejected: OK")


def test_expired_rejected():
    env = make_envelope(PAIR_REQUEST, A["pid"], B["pid"],
                        {"handle": "alice", "x_pub": b62encode(A["x_pub"]),
                         "ipub": b62encode(A["s_pub"])},
                        A["s_priv"], ts=int(time.time()) - 1000)
    try:
        verify_envelope(env, PUBKEYS.get, max_age=300)
        raise AssertionError("expired envelope verified!")
    except AcpError as e:
        assert e.code == "EXPIRED", e.code
    print("expired envelope rejected: OK")


def test_e2e_roundtrip():
    payload = {"text": "hello, encrypted world", "msg_id": "m1"}
    env = make_e2e_envelope(MSG, A["pid"], B["pid"], payload, A["s_priv"],
                            A["x_priv"], A["x_pub"], B["x_pub"])
    assert "box" in env and "payload" not in env
    got = open_e2e_envelope(env, PUBKEYS.get, B["x_priv"])
    assert got == payload, got
    print("E2E encrypt/decrypt roundtrip: OK")


def test_e2e_wrong_recipient_fails():
    C = make_identity()
    env = make_e2e_envelope(MSG, A["pid"], B["pid"],
                            {"text": "secret", "msg_id": "m2"}, A["s_priv"],
                            A["x_priv"], A["x_pub"], B["x_pub"])
    # C tries to open it with B's pubkey registry but C's x_priv
    pubkeys = dict(PUBKEYS)
    pubkeys[C["pid"]] = C["s_pub"]
    try:
        open_e2e_envelope(env, pubkeys.get, C["x_priv"])
        raise AssertionError("wrong recipient decrypted!")
    except AcpError as e:
        assert e.code == "DECRYPT_FAIL", e.code
    print("E2E wrong-recipient -> DECRYPT_FAIL: OK")


def test_e2e_tampered_box_rejected():
    env = make_e2e_envelope(MSG, A["pid"], B["pid"],
                            {"text": "secret", "msg_id": "m3"}, A["s_priv"],
                            A["x_priv"], A["x_pub"], B["x_pub"])
    env["box"] = dict(env["box"])
    ct = bytearray(b62decode_fixed(env["box"]["ct"]))
    ct[0] ^= 1
    env["box"]["ct"] = b62encode_fixed(bytes(ct))
    # re-sign so signature passes and decryption is what fails
    from acp_crypto import ed25519_sign
    from acp_proto import canonical, _unsigned
    env["sig"] = b62encode_fixed(
        ed25519_sign(A["s_priv"], canonical(_unsigned(env))))
    try:
        open_e2e_envelope(env, PUBKEYS.get, B["x_priv"])
        raise AssertionError("tampered box decrypted!")
    except AcpError as e:
        assert e.code == "DECRYPT_FAIL", e.code
    print("E2E tampered box -> DECRYPT_FAIL: OK")


def test_framing():
    e1 = make_envelope(PAIR_REQUEST, A["pid"], B["pid"],
                       {"handle": "a", "x_pub": b62encode(A["x_pub"]),
                        "ipub": b62encode(A["s_pub"])}, A["s_priv"])
    e2 = make_e2e_envelope(MSG, B["pid"], A["pid"],
                           {"text": "hi", "msg_id": "m4"}, B["s_priv"],
                           B["x_priv"], B["x_pub"], A["x_pub"])
    wire = frame_envelope(e1) + frame_envelope(e2)
    # partial read: feed all but last 10 bytes, then the rest
    envs, rest = parse_frames(wire[:-10])
    assert len(envs) == 1, len(envs)
    envs2, rest2 = parse_frames(rest + wire[len(wire) - 10:])
    assert len(envs2) == 1 and rest2 == b""
    assert envs[0]["kind"] == PAIR_REQUEST and envs2[0]["kind"] == MSG
    print("framing + partial reads: OK")


def test_payload_schema_enforced():
    try:
        validate_payload(MSG, {"text": "missing msg_id"})
        raise AssertionError("bad payload accepted!")
    except AcpError as e:
        assert e.code == "BAD_ENVELOPE", e.code
    try:
        validate_payload("nope_kind", {})
        raise AssertionError("bad kind accepted!")
    except AcpError as e:
        assert e.code == "UNKNOWN_KIND", e.code
    print("payload schema enforced: OK")


if __name__ == "__main__":
    test_canonical_deterministic()
    test_b62_roundtrip()
    test_plaintext_envelope_roundtrip()
    test_envelope_tamper_rejected()
    test_unknown_sender_rejected()
    test_expired_rejected()
    test_e2e_roundtrip()
    test_e2e_wrong_recipient_fails()
    test_e2e_tampered_box_rejected()
    test_framing()
    test_payload_schema_enforced()
    print("ALL PROTOCOL TESTS PASSED")
