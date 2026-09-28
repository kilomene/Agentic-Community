"""ChaCha20-Poly1305 (RFC 8439) and HKDF-SHA256 (RFC 5869), pure Python.

Correct implementations validated against RFC test vectors.
Not constant-time — see docs/SECURITY.md.
"""

import hashlib
import struct


# ------------------------------------------------------------ ChaCha20

def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl(b, 7)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("chacha20 needs 32-byte key and 12-byte nonce")
    consts = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    k = struct.unpack("<8I", key)
    state = list(consts) + list(k) + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    work = list(state)
    for _ in range(10):  # 20 rounds = 10 double rounds
        work[0], work[4], work[8], work[12] = _quarter_round(work[0], work[4], work[8], work[12])
        work[1], work[5], work[9], work[13] = _quarter_round(work[1], work[5], work[9], work[13])
        work[2], work[6], work[10], work[14] = _quarter_round(work[2], work[6], work[10], work[14])
        work[3], work[7], work[11], work[15] = _quarter_round(work[3], work[7], work[11], work[15])
        work[0], work[5], work[10], work[15] = _quarter_round(work[0], work[5], work[10], work[15])
        work[1], work[6], work[11], work[12] = _quarter_round(work[1], work[6], work[11], work[12])
        work[2], work[7], work[8], work[13] = _quarter_round(work[2], work[7], work[8], work[13])
        work[3], work[4], work[9], work[14] = _quarter_round(work[3], work[4], work[9], work[14])
    return struct.pack("<16I", *[((w + s) & 0xFFFFFFFF) for w, s in zip(work, state)])


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out += bytes(c ^ k for c, k in zip(chunk, block))
    return bytes(out)


# ------------------------------------------------------------ Poly1305

def _poly1305_mac(msg: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("poly1305 needs a 32-byte one-time key")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _aead_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    def pad16(d):
        return d + b"\x00" * ((-len(d)) % 16)
    return (pad16(aad) + pad16(ciphertext)
            + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))


# ------------------------------------------------------------ AEAD

def chacha20poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                             aad: bytes = b"") -> bytes:
    """Returns ciphertext || 16-byte tag."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    otk = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, nonce, plaintext, counter=1)
    tag = _poly1305_mac(_aead_mac_data(aad, ct), otk)
    return ct + tag


def chacha20poly1305_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes,
                             aad: bytes = b"") -> bytes:
    """Returns plaintext; raises ValueError if authentication fails."""
    if len(key) != 32 or len(ct_and_tag) < 16:
        raise ValueError("bad input")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    expected = _poly1305_mac(_aead_mac_data(aad, ct), otk)
    # constant-time compare for the tag check (cheap to do right)
    if len(tag) != len(expected):
        raise ValueError("authentication failed")
    diff = 0
    for a, b in zip(tag, expected):
        diff |= a ^ b
    if diff:
        raise ValueError("authentication failed")
    return _chacha20_xor(key, nonce, ct, counter=1)


# ------------------------------------------------------------ HKDF (RFC 5869)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return _hmac(salt, ikm)


def _hmac(key: bytes, msg: bytes) -> bytes:
    import hmac
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 per RFC 5869."""
    if length <= 0 or length > 255 * 32:
        raise ValueError("bad length")
    prk = hkdf_extract(salt, ikm)
    okm = b""
    t = b""
    for i in range(1, -(-length // 32) + 1):
        t = _hmac(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 32)
