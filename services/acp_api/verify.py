"""verify.py — attestation-based agent identity verification (ACP 1.0).

The API server holds an *authority* Ed25519 keypair (generated once on
first run, stored in the server's db dir as ``authority.key``, never
leaving the operator's machine).  Agents prove *key ownership* by
signing a statement with the identity key registered for their handle;
the server then issues a signed *badge*:

  badge = {handle, agent_id, level, external_ref, issued_at, expires_at,
           authority_sig}

where ``authority_sig`` = b62(Ed25519_sign(authority_priv,
canonical(badge without authority_sig))).

Levels:
  "self"         — proof of key ownership only.  The authority attests
                   "this handle controlled this identity key at issued_at".
  "owner-linked" — the owner claims an external account/handle
                   (``external_ref``, e.g. a social handle).  The
                   authority attests only that the key owner *made the
                   claim* — it does NOT verify the external account.

This is attestation, not identity proofing: there is no KYC, no
document check, no external lookup.  See docs/VERIFY.md for the honest
threat model.
"""
import os
import sys
import time

# make acp_crypto / acp_proto importable however this module is loaded
_packages = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "..", "packages")
if _packages not in sys.path:
    sys.path.insert(0, _packages)

from acp_crypto import (
    ed25519_sign, ed25519_verify, ed25519_publickey, random_bytes,
)
from acp_proto import b62encode, b62decode, canonical

AUTHORITY_KEY_FILE = "authority.key"
VERIFY_LEVELS = ("self", "owner-linked")
BADGE_TTL_S = 90 * 24 * 3600  # badges expire 90 days after issuance
FRESHNESS_S = 300


def authority_key_path(db_dir):
    return os.path.join(db_dir, AUTHORITY_KEY_FILE)


def load_authority(db_dir):
    """Load (or generate once) the authority keypair.

    Returns (priv: bytes[32], pub: bytes[32]).  The private key file is
    created with mode 0o600.
    """
    os.makedirs(db_dir, exist_ok=True)
    path = authority_key_path(db_dir)
    if os.path.exists(path):
        with open(path, "rb") as f:
            priv = f.read()
        if len(priv) != 32:
            raise ValueError("authority.key is corrupt (not 32 bytes)")
        return priv, ed25519_publickey(priv)
    priv = random_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, priv)
    finally:
        os.close(fd)
    return priv, ed25519_publickey(priv)


def badge_payload(handle, agent_id, level, external_ref, issued_at,
                  expires_at=None):
    return {
        "handle": handle,
        "agent_id": agent_id,
        "level": level,
        "external_ref": external_ref or "",
        "issued_at": issued_at,
        "expires_at": (expires_at if expires_at is not None
                       else issued_at + BADGE_TTL_S),
    }


def sign_badge(authority_priv, payload):
    """Return a badge dict: payload + authority_sig (base62)."""
    sig = ed25519_sign(authority_priv, canonical(payload))
    badge = dict(payload)
    badge["authority_sig"] = b62encode(sig)
    return badge


def verify_badge(badge, authority_pub):
    """True iff authority_sig is a valid authority signature over the
    badge fields.  Does NOT check expiry or revocation — callers do."""
    if not isinstance(badge, dict):
        return False
    sig_b62 = badge.get("authority_sig")
    if not isinstance(sig_b62, str) or not sig_b62:
        return False
    try:
        sig = b62decode(sig_b62).rjust(64, b"\x00")
    except (ValueError, KeyError):
        return False
    payload = {k: v for k, v in badge.items() if k != "authority_sig"}
    return ed25519_verify(authority_pub, canonical(payload), sig)


def badge_expired(badge, now=None):
    now = int(time.time()) if now is None else now
    try:
        return int(badge.get("expires_at", 0)) <= now
    except (TypeError, ValueError):
        return True
