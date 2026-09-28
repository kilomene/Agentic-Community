"""DirectoryClient — tiny urllib helper for the acp_api directory (stdlib only).

Used by tests and (later) the CLI.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "packages"))

from acp_crypto import ed25519_sign
from acp_proto import b62encode, canonical


class DirectoryError(Exception):
    """HTTP error from the directory: .status (int), .body (str)."""

    def __init__(self, status, body):
        super().__init__("directory HTTP %d: %s" % (status, body))
        self.status = status
        self.body = body


class DirectoryClient:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method, path, body=None, params=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raise DirectoryError(e.code, e.read().decode("utf-8", "replace"))

    # -- directory ---------------------------------------------------

    def register(self, handle, ipub_b62, x_pub_b62):
        """Register a handle. Returns the response dict."""
        _, body = self._request("POST", "/v1/register",
                                {"handle": handle, "ipub": ipub_b62,
                                 "x_pub": x_pub_b62})
        return body

    def resolve(self, handle):
        """Resolve a handle to its keys. Returns the response dict."""
        _, body = self._request("GET", "/v1/resolve",
                                params={"handle": handle})
        return body

    # -- presence ----------------------------------------------------

    def set_presence(self, handle, state, sign_priv, ts=None):
        """Sign and publish presence. sign_priv = 32-byte Ed25519 key."""
        ts = int(time.time()) if ts is None else ts
        msg = canonical({"handle": handle, "state": state, "ts": ts})
        sig = b62encode(ed25519_sign(sign_priv, msg))
        _, body = self._request("POST", "/v1/presence",
                                {"handle": handle, "state": state,
                                 "ts": ts, "sig": sig})
        return body

    def get_presence(self, handle):
        """Fetch presence for a handle. Returns the response dict."""
        _, body = self._request("GET", "/v1/presence",
                                params={"handle": handle})
        return body

    # -- health ------------------------------------------------------

    def healthz(self):
        _, body = self._request("GET", "/healthz")
        return body
