"""RFC test-vector validation for acp_crypto.

Ed25519: RFC 8032 §7.1. X25519: RFC 7748 §6.1. ChaCha20-Poly1305:
RFC 8439 §2.8.2. HKDF-SHA256: RFC 5869 Test Case 1.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_crypto import (
    ed25519_publickey, ed25519_sign, ed25519_verify,
    generate_ed25519_keypair, generate_x25519_keypair,
    x25519, x25519_base, x25519_derive,
    aead_encrypt, aead_decrypt, hkdf_sha256, random_bytes,
)


def hx(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


# ------------------------------------------------ Ed25519 (RFC 8032 §7.1)

ED_VECTORS = [
    # (secret, public, message, signature)
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def test_ed25519_rfc8032():
    for i, (sk_h, pk_h, msg_h, sig_h) in enumerate(ED_VECTORS):
        sk, pk, msg, sig = hx(sk_h), hx(pk_h), hx(msg_h), hx(sig_h)
        assert ed25519_publickey(sk) == pk, f"vector {i}: pubkey mismatch"
        assert ed25519_sign(sk, msg) == sig, f"vector {i}: signature mismatch"
        assert ed25519_verify(pk, msg, sig), f"vector {i}: verify failed"
    print("ed25519 RFC 8032 vectors: OK")


def test_ed25519_rejects_tampered():
    sk, pk = generate_ed25519_keypair()
    msg = b"hello agent community"
    sig = ed25519_sign(sk, msg)
    assert ed25519_verify(pk, msg, sig)
    bad = bytearray(sig)
    bad[10] ^= 1
    assert not ed25519_verify(pk, msg, bytes(bad))
    assert not ed25519_verify(pk, b"other message", sig)
    assert not ed25519_verify(pk, msg, b"\x00" * 64)
    print("ed25519 tamper rejection: OK")


# ------------------------------------------------ X25519 (RFC 7748 §6.1)

def test_x25519_rfc7748():
    alice_priv = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_pub = hx("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected = hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert x25519(alice_priv, bob_pub) == expected, "RFC 7748 shared secret mismatch"
    print("x25519 RFC 7748 vector: OK")


def test_x25519_dh_symmetry():
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()
    assert x25519_derive(a_priv, b_pub) == x25519_derive(b_priv, a_pub)
    assert x25519_base(a_priv) == a_pub
    print("x25519 DH symmetry: OK")


# ------------------------------------------------ ChaCha20-Poly1305 (RFC 8439 §2.8.2)

def test_aead_rfc8439():
    key = bytes(range(0x80, 0xA0))
    nonce = hx("070000004041424344454647")
    aad = hx("50515253c0c1c2c3c4c5c6c7")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could "
                 b"offer you only one tip for the future, sunscreen would be it.")
    ct_tag = aead_encrypt(key, nonce, plaintext, aad)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 tag mismatch"
    assert ct.hex() == (
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"), "RFC 8439 ciphertext mismatch"
    assert aead_decrypt(key, nonce, ct_tag, aad) == plaintext
    print("chacha20poly1305 RFC 8439 vector: OK")


def test_aead_tamper_detected():
    key = random_bytes(32)
    nonce = random_bytes(12)
    ct = aead_encrypt(key, nonce, b"secret chunk data", b"aad")
    bad = bytearray(ct)
    bad[3] ^= 1
    try:
        aead_decrypt(key, nonce, bytes(bad), b"aad")
        raise AssertionError("tampered ciphertext decrypted!")
    except ValueError:
        pass
    try:
        aead_decrypt(key, nonce, ct, b"wrong aad")
        raise AssertionError("wrong AAD decrypted!")
    except ValueError:
        pass
    print("aead tamper detection: OK")


# ------------------------------------------------ HKDF (RFC 5869 TC1)

def test_hkdf_rfc5869():
    ikm = b"\x0b" * 22
    salt = hx("000102030405060708090a0b0c")
    info = hx("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865"), "RFC 5869 mismatch"
    print("hkdf RFC 5869 vector: OK")


if __name__ == "__main__":
    test_ed25519_rfc8032()
    test_ed25519_rejects_tampered()
    test_x25519_rfc7748()
    test_x25519_dh_symmetry()
    test_aead_rfc8439()
    test_aead_tamper_detected()
    test_hkdf_rfc5869()
    print("ALL CRYPTO TESTS PASSED")
