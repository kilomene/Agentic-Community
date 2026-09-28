"""DirectoryClient — tiny urllib helper for the acp_api directory (stdlib only).

Used by tests and (later) the CLI.

Keyed endpoints (listings write, presence write, analytics report,
verify request) need an operator-issued API key:
  DirectoryClient(url, api_key="acp_...")
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
    def __init__(self, base_url, timeout=10, api_key=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key

    def _request(self, method, path, body=None, params=None, raw=False):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read().decode("utf-8")
                if raw:
                    return resp.status, payload
                return resp.status, (json.loads(payload) if payload else {})
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
        """Sign and publish presence. sign_priv = 32-byte Ed25519 key.

        Requires the client api_key to carry the presence:write scope.
        """
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

    # -- registry ----------------------------------------------------

    def publish_listing(self, handle, display_name, capabilities, owner,
                        metadata, sign_priv, ts=None):
        """Publish (create/update) a registry listing for a handle.

        Requires the client api_key to carry the listings:write scope.
        """
        ts = int(time.time()) if ts is None else ts
        msg = canonical({"handle": handle, "display_name": display_name,
                         "capabilities": capabilities, "owner": owner,
                         "metadata": metadata, "ts": ts})
        sig = b62encode(ed25519_sign(sign_priv, msg))
        _, body = self._request("POST", "/v1/listings",
                                {"handle": handle,
                                 "display_name": display_name,
                                 "capabilities": capabilities, "owner": owner,
                                 "metadata": metadata, "ts": ts, "sig": sig})
        return body

    def search_listings(self, q=None, capability=None, owner=None,
                        limit=20, cursor=None):
        """Search the public registry. Returns {listings, next_cursor}."""
        params = {"limit": limit}
        if q is not None:
            params["q"] = q
        if capability is not None:
            params["capability"] = capability
        if owner is not None:
            params["owner"] = owner
        if cursor is not None:
            params["cursor"] = cursor
        _, body = self._request("GET", "/v1/listings/search", params=params)
        return body

    def get_listing(self, handle):
        """Fetch one listing. Returns the listing dict."""
        _, body = self._request(
            "GET", "/v1/listings/" + urllib.parse.quote(handle, safe=""))
        return body

    def delete_listing(self, handle, sign_priv, ts=None):
        """Delete a listing (sig-auth like publish).

        Requires the client api_key to carry the listings:write scope.
        """
        ts = int(time.time()) if ts is None else ts
        msg = canonical({"handle": handle, "ts": ts})
        sig = b62encode(ed25519_sign(sign_priv, msg))
        _, body = self._request(
            "DELETE", "/v1/listings/" + urllib.parse.quote(handle, safe=""),
            {"handle": handle, "ts": ts, "sig": sig})
        return body

    # -- verification ------------------------------------------------

    def get_verify_authority(self):
        """Fetch the server's verification authority public key."""
        _, body = self._request("GET", "/v1/verify/authority")
        return body

    def request_verification(self, handle, level, external_ref, sign_priv,
                             agent_id=None, ts=None):
        """Ask the authority for a badge.

        Builds statement = canonical({agent_id, level, external_ref, ts})
        and signs it with the agent's identity key.  agent_id defaults to
        b62encode of the signing key's public key (must match the key
        registered for handle).  Requires the client api_key to carry
        the verify:request scope.
        """
        from acp_crypto import ed25519_publickey
        ts = int(time.time()) if ts is None else ts
        agent_id = agent_id or b62encode(ed25519_publickey(sign_priv))
        statement = {"agent_id": agent_id, "level": level,
                     "external_ref": external_ref or "", "ts": ts}
        sig = b62encode(ed25519_sign(sign_priv, canonical(statement)))
        _, body = self._request("POST", "/v1/verify/request",
                                {"handle": handle, "level": level,
                                 "statement": statement, "ts": ts,
                                 "sig": sig})
        return body

    def get_badge(self, handle):
        """Fetch a badge (or a revoked flag) for a handle."""
        _, body = self._request(
            "GET", "/v1/verify/" + urllib.parse.quote(handle, safe=""))
        return body

    def revoke_verification(self, handle, reason, authority_priv, ts=None):
        """Revoke a badge (authority-signed; operator side)."""
        ts = int(time.time()) if ts is None else ts
        msg = canonical({"handle": handle, "reason": reason, "ts": ts})
        authority_sig = b62encode(ed25519_sign(authority_priv, msg))
        _, body = self._request("POST", "/v1/verify/revoke",
                                {"handle": handle, "reason": reason,
                                 "ts": ts, "authority_sig": authority_sig})
        return body

    def list_revoked(self):
        """Fetch the revocation list."""
        _, body = self._request("GET", "/v1/verify/revoked")
        return body

    # -- analytics ---------------------------------------------------

    def report_analytics(self, handle, day, counters, sign_priv, ts=None):
        """Opt-in: report aggregate counters for a day (signed).

        Requires the client api_key to carry the analytics:write scope.
        Only counters — never content — leave the connector.
        """
        ts = int(time.time()) if ts is None else ts
        msg = canonical({"handle": handle, "day": day,
                         "counters": counters, "ts": ts})
        sig = b62encode(ed25519_sign(sign_priv, msg))
        _, body = self._request("POST", "/v1/analytics/report",
                                {"handle": handle, "day": day,
                                 "counters": counters, "ts": ts, "sig": sig})
        return body

    def get_analytics(self, handle, days=30):
        """Fetch aggregate counters for a handle (public, counts only)."""
        _, body = self._request(
            "GET", "/v1/analytics/" + urllib.parse.quote(handle, safe=""),
            params={"days": days})
        return body

    def export_analytics(self, handle, days=30, format="csv"):
        """Export per-day counters (csv text or json)."""
        status, payload = self._request(
            "GET",
            "/v1/analytics/" + urllib.parse.quote(handle, safe="") + "/export",
            params={"days": days, "format": format}, raw=True)
        return payload

    # -- health ------------------------------------------------------

    def healthz(self):
        _, body = self._request("GET", "/healthz")
        return body
