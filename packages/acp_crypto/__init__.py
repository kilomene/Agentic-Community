"""acp_crypto — narrow, swappable cryptographic interface for ACP.

All primitives are real standard algorithms implemented in pure Python
(see _curve.py, _aead.py) and validated against RFC test vectors.

Public API (stable — a future libsodium backend must implement exactly
these functions with identical semantics):
"""

from ._curve import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_verify,
    x25519,
    x25519_base,
    random_bytes,
)
from ._aead import (
    chacha20poly1305_encrypt,
    chacha20poly1305_decrypt,
    hkdf_sha256,
    hkdf_extract,
    pbkdf2_sha256,
)

__all__ = [
    "generate_ed25519_keypair",
    "generate_x25519_keypair",
    "ed25519_sign",
    "ed25519_verify",
    "x25519_derive",
    "hkdf_sha256",
    "aead_encrypt",
    "aead_decrypt",
    "derive_key_passphrase",
    "random_bytes",
]


def generate_ed25519_keypair():
    """-> (private_key: bytes[32], public_key: bytes[32])"""
    priv = random_bytes(32)
    return priv, ed25519_publickey(priv)


def generate_x25519_keypair():
    """-> (private_key: bytes[32], public_key: bytes[32])"""
    priv = random_bytes(32)
    return priv, x25519_base(priv)


def x25519_derive(private_key: bytes, peer_public_key: bytes) -> bytes:
    """ECDH shared secret -> 32 bytes."""
    return x25519(private_key, peer_public_key)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """ChaCha20-Poly1305; returns ciphertext || 16-byte tag."""
    return chacha20poly1305_encrypt(key, nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes = b"") -> bytes:
    """Returns plaintext; raises ValueError on authentication failure."""
    return chacha20poly1305_decrypt(key, nonce, ct_and_tag, aad)


def derive_key_passphrase(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    """PBKDF2-HMAC-SHA256 -> 32-byte key for at-rest key encryption."""
    return pbkdf2_sha256(password, salt, iterations)
