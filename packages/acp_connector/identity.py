"""Agent identity: Ed25519 signing keypair + X25519 E2E keypair.

Stored in ``home_dir/identity.key`` encrypted with a passphrase-derived
key: PBKDF2-HMAC-SHA256(passphrase, salt, 200k iterations) +
ChaCha20-Poly1305 (via acp_crypto).

File layout: salt(16) || nonce(12) || ciphertext.
Plaintext: canonical JSON {v, handle, ed_priv, ed_pub, x_priv, x_pub,
created_at} with AAD b"acp-identity-v1".

peer id = b62encode(ed25519 verify key).
"""
import json
import os
import time

from acp_crypto import (
    generate_ed25519_keypair, generate_x25519_keypair,
    derive_key_passphrase, aead_encrypt, aead_decrypt, random_bytes,
)
from acp_proto import b62encode, AcpError

_IDENTITY_AAD = b"acp-identity-v1"
_KDF_ITERS = 200_000


class Identity:
    def __init__(self, home_dir, passphrase, handle="default"):
        self.path = os.path.join(home_dir, "identity.key")
        self.handle = handle
        if os.path.exists(self.path):
            self._load(passphrase)
        else:
            self._create(passphrase, handle)

    # ------------------------------------------------------------ lifecycle
    def _create(self, passphrase, handle):
        ed_priv, ed_pub = generate_ed25519_keypair()
        x_priv, x_pub = generate_x25519_keypair()
        self.ed_priv, self.ed_pub = ed_priv, ed_pub
        self.x_priv, self.x_pub = x_priv, x_pub
        self.created_at = int(time.time())
        self._save(passphrase)

    def _load(self, passphrase):
        with open(self.path, "rb") as f:
            blob = f.read()
        if len(blob) < 28:
            raise AcpError("INTERNAL", "identity.key is corrupt")
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        key = derive_key_passphrase(passphrase.encode("utf-8"), salt,
                                    _KDF_ITERS)
        try:
            pt = aead_decrypt(key, nonce, ct, _IDENTITY_AAD)
            doc = json.loads(pt.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AcpError("INTERNAL",
                           "cannot decrypt identity.key: wrong passphrase or"
                           " corrupt file")
        try:
            self.ed_priv = bytes.fromhex(doc["ed_priv"])
            self.ed_pub = bytes.fromhex(doc["ed_pub"])
            self.x_priv = bytes.fromhex(doc["x_priv"])
            self.x_pub = bytes.fromhex(doc["x_pub"])
            self.handle = doc.get("handle", "default")
            self.created_at = int(doc.get("created_at", 0))
        except (KeyError, ValueError, TypeError):
            raise AcpError("INTERNAL", "identity.key has invalid contents")
        if not (len(self.ed_priv) == len(self.ed_pub) == 32
                and len(self.x_priv) == len(self.x_pub) == 32):
            raise AcpError("INTERNAL", "identity.key has invalid key lengths")

    def _save(self, passphrase):
        doc = {
            "v": 1,
            "handle": self.handle,
            "ed_priv": self.ed_priv.hex(),
            "ed_pub": self.ed_pub.hex(),
            "x_priv": self.x_priv.hex(),
            "x_pub": self.x_pub.hex(),
            "created_at": self.created_at,
        }
        pt = json.dumps(doc, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")
        salt = random_bytes(16)
        nonce = random_bytes(12)
        key = derive_key_passphrase(passphrase.encode("utf-8"), salt,
                                    _KDF_ITERS)
        ct = aead_encrypt(key, nonce, pt, _IDENTITY_AAD)
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(salt + nonce + ct)
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------ API
    @property
    def peer_id(self):
        """Agent id: b62encode(Ed25519 verify key)."""
        return b62encode(self.ed_pub)

    def change_passphrase(self, new_passphrase):
        """Re-encrypt the identity file under a new passphrase."""
        self._save(new_passphrase)

    def rotate_e2e(self):
        """Generate a fresh X25519 E2E keypair, persist, return it.

        Callers must broadcast the new x_pub (KEY_ROTATE) themselves.
        """
        self.x_priv, self.x_pub = generate_x25519_keypair()
        return self.x_priv, self.x_pub

    def save(self, passphrase):
        """Persist current key material (used after rotate_e2e)."""
        self._save(passphrase)
