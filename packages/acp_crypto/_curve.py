"""Pure-Python Ed25519 (RFC 8032) and X25519 (RFC 7748).

Correct, auditable implementations of the standard algorithms.
NOT constant-time and NOT performance-tuned — see docs/SECURITY.md.
The public API in acp_crypto/__init__.py is narrow and swappable so a
future version can use libsodium bindings with no caller changes.
"""

import hashlib
import os

# ---------------------------------------------------------------- Ed25519

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _H(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv((_D * y * y + 1) % _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


_B = None  # base point, computed once below


def _edwards(P, Q):
    # Twisted Edwards addition for a = -1 (Ed25519):
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)   <- note + for a=-1
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv((1 + _D * x1 * x2 * y1 * y2) % _Q)
    y3 = (y1 * y2 + x1 * x2) * _inv((1 - _D * x1 * x2 * y1 * y2) % _Q)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(P, e: int):
    # Double-and-add (simple; not constant-time — documented limitation)
    Q = (0, 1)  # identity
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


def _encodepoint(P) -> bytes:
    x, y = P
    b = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        b[31] |= 0x80
    return bytes(b)


def _decodepoint(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _Q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def _init_base():
    global _B
    by = 4 * _inv(5) % _Q
    bx = _xrecover(by)
    _B = (bx, by)


_init_base()


def ed25519_publickey(sk: bytes) -> bytes:
    """32-byte secret key -> 32-byte public key."""
    if len(sk) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = _H(sk)
    a = (1 << 254) + sum((1 << i) * _bit(h, i) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


def ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    """Sign; returns 64-byte signature."""
    if len(sk) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = _H(sk)
    a = (1 << 254) + sum((1 << i) * _bit(h, i) for i in range(3, 254))
    r = _hint(h[32:64] + msg)
    R = _scalarmult(_B, r)
    pk = ed25519_publickey(sk)
    S = (r + _hint(_encodepoint(R) + pk + msg) * a) % _L
    return _encodepoint(R) + S.to_bytes(32, "little")


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify; returns True/False (never raises on bad input)."""
    try:
        if len(pk) != 32 or len(sig) != 64:
            return False
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
        S = int.from_bytes(sig[32:], "little")
        if S >= _L:
            return False
        h = _hint(_encodepoint(R) + pk + msg)
        v1 = _scalarmult(_B, S)
        v2 = _edwards(R, _scalarmult(A, h))
        return _encodepoint(v1) == _encodepoint(v2)
    except Exception:
        return False


# ---------------------------------------------------------------- X25519

_P25519 = (1 << 255) - 19
_A24 = 121665  # (486662 - 2) / 4, RFC 7748 section 5


def _cswap(swap: int, x, y):
    # swap is 0 or 1 (simple branch; not constant-time — documented limitation)
    return (y, x) if swap else (x, y)


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 scalar multiplication. k, u 32 bytes -> 32 bytes."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(bytes(kb), "little")
    x1 = int.from_bytes(u, "little") % _P25519
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    P = _P25519
    for t in range(254, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = pow(DA + CB, 2, P)
        z3 = (x1 * pow(DA - CB, 2, P)) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + _A24 * E)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


def x25519_base(k: bytes) -> bytes:
    """Public key from private key (scalar * base point u=9)."""
    return x25519(k, (9).to_bytes(32, "little"))


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
