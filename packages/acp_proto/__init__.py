"""ACP 1.0 protocol layer: envelopes, canonical JSON, signing, E2E
encryption, framing, error codes, and payload validation.

Wire format (JSON):
  {"acp":"1.0","kind":str,"from":b62,"to":b62,"ts":int,"nonce":b62,
   "payload":{...} | "box":{"nonce":b62,"ct":b62}, "x_pub":b62?, "sig":b62}

- ``payload`` for plaintext kinds, ``box`` for E2E kinds (msg, file_*,
  pair_confirm, pair_welcome).
- ``sig`` = Ed25519 signature over canonical JSON of the envelope
  with ``sig`` removed.
- Binary fields (``sig``, ``x_pub``, ``box.nonce``, ``box.ct``) use
  length-prefixed base62 (``b62encode_fixed``: ``"<len>:<b62>"``) so
  leading zero bytes survive the round trip. Plain ``b62encode`` is
  only for opaque id strings (``from``/``to``/``nonce``) where exact
  byte length is not required.
- E2E: X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305. ``x_pub`` is the
  sender's X25519 public key in plaintext (public keys are public);
  AAD binds from/to/ts/nonce/kind.
- Framing: 4-byte big-endian length prefix + JSON bytes.
"""
import json
import time

from acp_crypto import (
    ed25519_sign, ed25519_verify, x25519_derive, hkdf_sha256, random_bytes,
)

PROTOCOL_VERSION = "1.0"

# ---------------------------------------------------------------- errors

ERRORS = {
    "BAD_ENVELOPE": "envelope is malformed",
    "BAD_VERSION": "unsupported protocol version",
    "INVALID_SIG": "signature verification failed",
    "UNKNOWN_SENDER": "sender identity is not known",
    "EXPIRED": "envelope timestamp outside acceptance window",
    "REPLAY": "nonce already seen",
    "DECRYPT_FAIL": "E2E decryption failed",
    "UNKNOWN_KIND": "message kind not recognized",
    "POLICY_DENIED": "denied by permission policy",
    "PAIRING_FAILED": "pairing handshake failed",
    "FILE_REJECTED": "file transfer rejected",
    "FILE_HASH_MISMATCH": "reassembled file hash does not match manifest",
    "FILE_TOO_LARGE": "file exceeds size limit",
    "RATE_LIMITED": "too many messages",
    "INTERNAL": "internal error",
}


class AcpError(Exception):
    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail or ERRORS.get(code, '')}")


# ---------------------------------------------------------------- kinds

# Plaintext kinds (signed only)
PAIR_REQUEST = "pair_request"
PAIR_CHALLENGE = "pair_challenge"
# E2E kinds (signed + encrypted)
PAIR_CONFIRM = "pair_confirm"
PAIR_WELCOME = "pair_welcome"
MSG = "msg"
MSG_ACK = "msg_ack"
FILE_OFFER = "file_offer"
FILE_ACCEPT = "file_accept"
FILE_REJECT = "file_reject"
FILE_CHUNK = "file_chunk"
FILE_DONE = "file_done"
FILE_ACK = "file_ack"
# Control kinds
PRESENCE = "presence"
KEY_ROTATE = "key_rotate"
REVOKE_NOTICE = "revoke_notice"
ERROR = "error"

E2E_KINDS = {
    PAIR_CONFIRM, PAIR_WELCOME, MSG, MSG_ACK,
    FILE_OFFER, FILE_ACCEPT, FILE_REJECT, FILE_CHUNK, FILE_DONE, FILE_ACK,
}

ALL_KINDS = {
    PAIR_REQUEST, PAIR_CHALLENGE, PRESENCE, KEY_ROTATE, REVOKE_NOTICE, ERROR,
} | E2E_KINDS


def register_kind(name, e2e=False, schema=()):
    """Extension hook for V2+ message kinds (backward compatible).

    Registers a new protocol kind at runtime so V2+ modules (groups,
    voice, marketplace, ...) can add message types without editing this
    file. Unknown fields remain ignored per PROTOCOL.md §10. The sets
    are mutated in place so ``from acp_proto import ALL_KINDS`` holders
    (e.g. the connector) see new kinds immediately.
    """
    import re as _re
    if not isinstance(name, str) or not _re.match(r"^[a-z][a-z0-9_]{1,40}$",
                                                  name):
        raise AcpError("BAD_ENVELOPE", "bad kind name: %r" % (name,))
    if name in ALL_KINDS:
        return name  # idempotent
    ALL_KINDS.add(name)
    if e2e:
        E2E_KINDS.add(name)
    PAYLOAD_SCHEMA[name] = tuple(schema)
    return name

# Required payload fields per kind (after decryption for E2E kinds)
PAYLOAD_SCHEMA = {
    PAIR_REQUEST: ("handle", "x_pub", "ipub"),
    PAIR_CHALLENGE: ("code_hash", "x_pub", "ipub", "handle", "expires"),
    PAIR_CONFIRM: ("x_pub", "ipub", "handle"),
    PAIR_WELCOME: ("handle",),
    MSG: ("text", "msg_id"),
    MSG_ACK: ("msg_id",),
    FILE_OFFER: ("file_id", "name", "size", "sha256", "chunks"),
    FILE_ACCEPT: ("file_id", "chunk_size"),
    FILE_REJECT: ("file_id", "reason"),
    FILE_CHUNK: ("file_id", "index", "data"),
    FILE_DONE: ("file_id",),
    FILE_ACK: ("file_id",),
    PRESENCE: ("state",),
    KEY_ROTATE: ("ipub", "x_pub"),
    REVOKE_NOTICE: ("revoked_pid",),
    ERROR: ("code",),
}


def validate_payload(kind, payload):
    if kind not in ALL_KINDS:
        raise AcpError("UNKNOWN_KIND", kind)
    required = PAYLOAD_SCHEMA.get(kind, ())
    missing = [f for f in required if f not in payload]
    if missing:
        raise AcpError("BAD_ENVELOPE", f"{kind} missing fields: {missing}")
    return True


# ---------------------------------------------------------------- base62

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def b62encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    if n == 0:
        return _B62[0]
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(_B62[r])
    return "".join(reversed(out))


def b62decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 62 + _B62.index(ch)
    # restore leading zero bytes: base62 drops them, so we need the length.
    # Callers that need exact length (keys) pad explicitly.
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")


def b62encode_fixed(raw: bytes) -> str:
    """Encode with a length prefix so decode restores exact bytes."""
    if not raw:
        return "0:"
    return f"{len(raw)}:{b62encode(raw)}"


def b62decode_fixed(s: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError("bad fixed b62 encoding")
    ln, _, val = s.partition(":")
    ln = int(ln)
    if ln == 0:
        if val not in ("", "0"):
            raise ValueError("bad fixed b62 encoding")
        return b""
    raw = b62decode(val)
    if len(raw) > ln:
        raise ValueError("fixed b62 payload longer than declared length")
    return raw.rjust(ln, b"\x00")


# ---------------------------------------------------------------- canonical JSON

def canonical(obj) -> bytes:
    """Deterministic encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def new_nonce() -> str:
    return b62encode(random_bytes(16))


# ---------------------------------------------------------------- E2E

_E2E_SALT = b"acp-e2e-v1"
_E2E_INFO = b"acp-pairwise-key"


def _pairwise_key(my_x_priv: bytes, peer_x_pub: bytes) -> bytes:
    shared = x25519_derive(my_x_priv, peer_x_pub)
    return hkdf_sha256(shared, salt=_E2E_SALT, info=_E2E_INFO, length=32)


def _aad_for(kind, from_pid, to_pid, ts, nonce) -> bytes:
    return canonical({"kind": kind, "from": from_pid, "to": to_pid,
                      "ts": ts, "nonce": nonce})


def e2e_encrypt(my_x_priv: bytes, peer_x_pub: bytes, plaintext: bytes,
                kind, from_pid, to_pid, ts, nonce) -> dict:
    from acp_crypto import aead_encrypt
    key = _pairwise_key(my_x_priv, peer_x_pub)
    iv = random_bytes(12)
    aad = _aad_for(kind, from_pid, to_pid, ts, nonce)
    ct = aead_encrypt(key, iv, plaintext, aad)
    return {"nonce": b62encode_fixed(iv), "ct": b62encode_fixed(ct)}


def e2e_decrypt(my_x_priv: bytes, peer_x_pub: bytes, box: dict,
                kind, from_pid, to_pid, ts, nonce) -> bytes:
    from acp_crypto import aead_decrypt
    key = _pairwise_key(my_x_priv, peer_x_pub)
    try:
        iv = b62decode_fixed(box["nonce"])
        ct = b62decode_fixed(box["ct"])
        aad = _aad_for(kind, from_pid, to_pid, ts, nonce)
        return aead_decrypt(key, iv, ct, aad)
    except (KeyError, ValueError) as e:
        raise AcpError("DECRYPT_FAIL", str(e))


# ---------------------------------------------------------------- envelopes

def _base_envelope(kind, from_pid, to_pid, ts=None, nonce=None):
    return {
        "acp": PROTOCOL_VERSION,
        "kind": kind,
        "from": from_pid,
        "to": to_pid,
        "ts": ts if ts is not None else int(time.time()),
        "nonce": nonce or new_nonce(),
    }


def make_envelope(kind, from_pid, to_pid, payload: dict, sign_priv: bytes,
                  ts=None, nonce=None) -> dict:
    """Plaintext (signed-only) envelope."""
    validate_payload(kind, payload)
    env = _base_envelope(kind, from_pid, to_pid, ts, nonce)
    env["payload"] = payload
    env["sig"] = b62encode_fixed(ed25519_sign(sign_priv,
                                              canonical(_unsigned(env))))
    return env


def make_e2e_envelope(kind, from_pid, to_pid, payload: dict, sign_priv: bytes,
                      my_x_priv: bytes, my_x_pub: bytes, peer_x_pub: bytes,
                      ts=None, nonce=None) -> dict:
    """E2E-encrypted envelope. Sender's X25519 public key rides plaintext."""
    if kind not in E2E_KINDS:
        raise AcpError("BAD_ENVELOPE", f"{kind} is not an E2E kind")
    validate_payload(kind, payload)
    env = _base_envelope(kind, from_pid, to_pid, ts, nonce)
    env["x_pub"] = b62encode_fixed(my_x_pub)
    env["box"] = e2e_encrypt(my_x_priv, peer_x_pub, canonical(payload),
                             kind, from_pid, to_pid, env["ts"], env["nonce"])
    env["sig"] = b62encode_fixed(ed25519_sign(sign_priv,
                                              canonical(_unsigned(env))))
    return env


def _unsigned(env: dict) -> dict:
    return {k: v for k, v in env.items() if k != "sig"}


def _get_verify_key(env, get_pubkey):
    pid = env.get("from")
    if not pid:
        raise AcpError("BAD_ENVELOPE", "missing from")
    vkey = get_pubkey(pid)
    if vkey is None:
        raise AcpError("UNKNOWN_SENDER", pid)
    return vkey


def verify_envelope(env: dict, get_pubkey, max_age=300, now=None) -> dict:
    """Verify structure, version, signature, freshness. Returns envelope."""
    if not isinstance(env, dict):
        raise AcpError("BAD_ENVELOPE", "not a dict")
    if env.get("acp") != PROTOCOL_VERSION:
        raise AcpError("BAD_VERSION", str(env.get("acp")))
    kind = env.get("kind")
    if kind not in ALL_KINDS:
        raise AcpError("UNKNOWN_KIND", str(kind))
    for f in ("from", "to", "ts", "nonce", "sig"):
        if f not in env:
            raise AcpError("BAD_ENVELOPE", f"missing {f}")
    if ("payload" in env) == ("box" in env):
        raise AcpError("BAD_ENVELOPE", "need exactly one of payload/box")
    vkey = _get_verify_key(env, get_pubkey)
    try:
        sig = b62decode_fixed(env["sig"])
    except (ValueError, KeyError):
        raise AcpError("BAD_ENVELOPE", "bad sig encoding")
    if not ed25519_verify(vkey, canonical(_unsigned(env)), sig):
        raise AcpError("INVALID_SIG")
    check_freshness(env["ts"], max_age=max_age, now=now)
    return env


def check_freshness(ts, max_age=300, now=None):
    now = int(time.time()) if now is None else now
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        raise AcpError("BAD_ENVELOPE", f"bad envelope ts: {ts!r}")
    if abs(now - ts) > max_age:
        raise AcpError("EXPIRED", f"ts={ts} now={now}")
    return True


def open_e2e_envelope(env: dict, get_pubkey, my_x_priv: bytes,
                      max_age=300, now=None) -> dict:
    """Verify an E2E envelope and return the decrypted payload dict."""
    verify_envelope(env, get_pubkey, max_age=max_age, now=now)
    if env["kind"] not in E2E_KINDS or "box" not in env:
        raise AcpError("BAD_ENVELOPE", "not an E2E envelope")
    try:
        peer_x_pub = b62decode_fixed(env["x_pub"])
    except (ValueError, KeyError, TypeError):
        raise AcpError("BAD_ENVELOPE", "bad x_pub encoding")
    pt = e2e_decrypt(my_x_priv, peer_x_pub, env["box"], env["kind"],
                     env["from"], env["to"], env["ts"], env["nonce"])
    try:
        payload = json.loads(pt.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise AcpError("DECRYPT_FAIL", f"payload not JSON: {e}")
    validate_payload(env["kind"], payload)
    return payload


# ---------------------------------------------------------------- framing

def frame_envelope(env: dict) -> bytes:
    data = canonical(env)
    if len(data) > 4 * 1024 * 1024:
        raise AcpError("BAD_ENVELOPE", "frame too large")
    return len(data).to_bytes(4, "big") + data


def parse_frames(buf: bytes):
    """Parse as many whole frames as possible. Returns (envs, rest)."""
    envs = []
    off = 0
    while len(buf) - off >= 4:
        ln = int.from_bytes(buf[off:off + 4], "big")
        if ln > 4 * 1024 * 1024:
            raise AcpError("BAD_ENVELOPE", "frame too large")
        if len(buf) - off - 4 < ln:
            break
        raw = buf[off + 4:off + 4 + ln]
        try:
            envs.append(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as e:
            raise AcpError("BAD_ENVELOPE", f"frame not JSON: {e}")
        off += 4 + ln
    return envs, buf[off:]
