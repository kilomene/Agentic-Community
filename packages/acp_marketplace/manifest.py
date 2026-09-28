"""Capability-package manifest: build, sign, verify.

Manifest format (all fields JSON-serializable)::

    {
      "name": "my-capability",          # package name
      "version": "1.0.0",               # version string
      "description": "...",             # human description
      "capabilities": ["summarize"],    # capability tags
      "entry_point": "main.py",         # basename of the entry file
      "files": [                        # every file shipped
        {"path": "main.py", "sha256": "<hex>"},
      ],
      "publisher_id": "<b62 peer id>",
      "ts": 1759000000,                 # unix time of signing
      "sig": "<b62 ed25519 signature>",  # over canonical(manifest-minus-sig)
    }

``sig`` is Ed25519 over ``acp_proto.canonical(manifest minus "sig")``,
signed with the publisher's Ed25519 identity key. Install-time checks:

  1. manifest parses and has all required fields;
  2. ``sig`` verifies against the publisher's known Ed25519 public key;
  3. every ``files[]`` entry sha256-matches the delivered bytes;
  4. every ``path`` is sanitized exactly like acp_connector.files:
     basename only, reject ``..`` segments, absolute paths, NUL bytes,
     and names that sanitize to nothing or exceed 255 bytes.

A package is NEVER executed at install time: install only writes files
and records an audit event. Running package code is a separate,
explicit local action and is not part of this module.
"""
import hashlib
import json
import os
import time

from acp_crypto import ed25519_sign, ed25519_verify
from acp_proto import AcpError, b62decode, b62encode, canonical
from acp_connector.files import sanitize_filename

REQUIRED_FIELDS = ("name", "version", "description", "capabilities",
                   "entry_point", "files", "publisher_id", "ts", "sig")


def _check_path(path):
    """Validate a manifest file path. Returns the sanitized basename.

    Raises AcpError("FILE_REJECTED") on anything hostile: absolute
    paths, ``..`` segments, NUL bytes, or names the files.py sanitizer
    refuses.
    """
    if not isinstance(path, str):
        raise AcpError("FILE_REJECTED", "file path is not a string")
    if "\x00" in path:
        raise AcpError("FILE_REJECTED", "NUL byte in file path")
    norm = path.replace("\\", "/")
    if norm.startswith("/"):
        raise AcpError("FILE_REJECTED",
                       f"absolute path not allowed: {path!r}")
    if any(seg == ".." for seg in norm.split("/")):
        raise AcpError("FILE_REJECTED",
                       f"path traversal not allowed: {path!r}")
    safe = sanitize_filename(norm.split("/")[-1])
    if safe is None:
        raise AcpError("FILE_REJECTED",
                       f"unsafe file name: {path!r}")
    return safe


def _collect_files(source_dir):
    """Walk source_dir, return [(relpath, bytes)] sorted by relpath."""
    entries = []
    for root, _dirs, files in os.walk(source_dir):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, source_dir)
            with open(full, "rb") as f:
                entries.append((rel, f.read()))
    entries.sort(key=lambda e: e[0])
    return entries


def build_manifest(source_dir, name, version, description, capabilities,
                   entry_point, publisher_id):
    """Build an unsigned manifest dict from a package source directory."""
    if not os.path.isdir(source_dir):
        raise AcpError("INTERNAL", f"not a directory: {source_dir}")
    entries = _collect_files(source_dir)
    if not entries:
        raise AcpError("INTERNAL", "package source dir is empty")
    seen = set()
    files = []
    entry_ok = False
    for rel, data in entries:
        safe = _check_path(rel)
        if safe in seen:
            raise AcpError("FILE_REJECTED",
                           f"name collision after sanitizing: {safe!r}")
        seen.add(safe)
        files.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest()})
        if safe == sanitize_filename(entry_point):
            entry_ok = True
    if not entry_ok:
        raise AcpError("INTERNAL",
                       f"entry_point {entry_point!r} not in package files")
    return {
        "name": name,
        "version": version,
        "description": description,
        "capabilities": list(capabilities),
        "entry_point": entry_point,
        "files": files,
        "publisher_id": publisher_id,
        "ts": int(time.time()),
    }


def sign_manifest(manifest, ed_priv):
    """Return a copy of manifest with a publisher Ed25519 signature."""
    unsigned = {k: v for k, v in manifest.items() if k != "sig"}
    signed = dict(unsigned)
    signed["sig"] = b62encode(ed25519_sign(ed_priv, canonical(unsigned)))
    return signed


def verify_manifest(manifest, get_pubkey):
    """Verify structure + publisher signature. Returns the manifest.

    Raises AcpError("BAD_ENVELOPE") on structural problems and
    AcpError("INVALID_SIG") on signature failure.
    """
    if not isinstance(manifest, dict):
        raise AcpError("BAD_ENVELOPE", "manifest is not a dict")
    missing = [f for f in REQUIRED_FIELDS if f not in manifest]
    if missing:
        raise AcpError("BAD_ENVELOPE",
                       f"manifest missing fields: {missing}")
    if not isinstance(manifest["files"], list) or not manifest["files"]:
        raise AcpError("BAD_ENVELOPE", "manifest files must be a non-empty"
                                       " list")
    for entry in manifest["files"]:
        if (not isinstance(entry, dict) or "path" not in entry
                or "sha256" not in entry):
            raise AcpError("BAD_ENVELOPE", "bad files[] entry")
        _check_path(entry["path"])
    vkey = get_pubkey(manifest["publisher_id"])
    if vkey is None:
        raise AcpError("UNKNOWN_SENDER",
                       f"unknown publisher {manifest['publisher_id'][:16]}")
    unsigned = {k: v for k, v in manifest.items() if k != "sig"}
    try:
        sig = b62decode(manifest["sig"])
    except (ValueError, KeyError):
        raise AcpError("BAD_ENVELOPE", "bad manifest sig encoding")
    if not ed25519_verify(vkey, canonical(unsigned), sig):
        raise AcpError("INVALID_SIG", "publisher signature invalid")
    return manifest


def verify_package_files(manifest, files_by_path):
    """Check every manifest file sha256 against delivered bytes.

    ``files_by_path`` maps manifest ``path`` -> bytes. Raises
    AcpError("FILE_HASH_MISMATCH") on any mismatch or missing file.
    """
    for entry in manifest["files"]:
        data = files_by_path.get(entry["path"])
        if data is None:
            raise AcpError("FILE_HASH_MISMATCH",
                           f"missing file: {entry['path']!r}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            raise AcpError("FILE_HASH_MISMATCH",
                           f"sha256 mismatch: {entry['path']!r}")
    return True


def manifest_to_json(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
