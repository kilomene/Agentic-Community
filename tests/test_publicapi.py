"""Tests for the Public API surface: keys, scopes, rate limits.

Covers: key issuance (format, one-time display, sha256-only storage),
missing key -> 401, unknown key -> 401, scope escalation -> 403,
token-bucket burst -> 429 with Retry-After, public routes stay public,
key revocation, CLI entry points.

Attack tests:
  - key without listings:write tries POST /v1/listings        -> 403
  - rate-limited key bursts POST /v1/presence                  -> 429
  - replayed presence sig (stale ts)                           -> 401

Run:  python3 tests/test_publicapi.py
"""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_api"))

from acp_crypto import (  # noqa: E402
    ed25519_sign, generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import b62encode, canonical  # noqa: E402

import server as api_server  # noqa: E402
from client import DirectoryClient, DirectoryError  # noqa: E402
import keys as keys_mod  # noqa: E402
from keys import create_key, list_keys, revoke_key, lookup_key  # noqa: E402

API_HOST, API_PORT = "127.0.0.1", 18284
ALL_SCOPES = ["registry:read", "listings:write", "presence:write",
              "analytics:read", "analytics:write", "verify:request"]


def gen_identity():
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    return ed_priv, ed_pub, x_pub


class ApiKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="acp_keys_test_")
        self.db_path = os.path.join(self.tmp, "registry.db")
        api_server.init_db(self.db_path)

    def test_key_format(self):
        raw, rec = create_key(self.db_path, name="bot",
                              scopes=["presence:write"], per_min=60)
        self.assertTrue(raw.startswith("acp_"))
        self.assertEqual(len(raw), 4 + 32)
        body = raw[4:]
        self.assertTrue(all(c in
                            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz" for c in body))
        self.assertEqual(rec["scopes"], ["presence:write"])
        self.assertEqual(rec["per_min"], 60)

    def test_raw_key_never_stored(self):
        raw, _ = create_key(self.db_path, name="bot",
                            scopes=["presence:write"], per_min=60)
        conn = sqlite3.connect(self.db_path)
        try:
            blob = "\n".join(
                str(r[0]) for r in
                conn.execute("SELECT key_hash || name || scopes FROM api_keys"))
        finally:
            conn.close()
        self.assertNotIn(raw, blob)
        # ...but its sha256 is what the server looks up
        self.assertIn(hashlib.sha256(raw.encode()).hexdigest(), blob)

    def test_lookup_roundtrip(self):
        raw, _ = create_key(self.db_path, name="bot",
                            scopes=["listings:write"], per_min=10)
        rec = lookup_key(self.db_path, raw)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["scopes"], ["listings:write"])
        self.assertIsNone(lookup_key(self.db_path, "acp_" + "0" * 32))
        self.assertIsNone(lookup_key(self.db_path, "not-a-key"))

    def test_unknown_scope_rejected(self):
        with self.assertRaises(keys_mod.KeyError_):
            create_key(self.db_path, scopes=["admin:everything"],
                       per_min=60)

    def test_bad_rate_rejected(self):
        with self.assertRaises(keys_mod.KeyError_):
            create_key(self.db_path, scopes=["presence:write"], per_min=0)

    def test_list_hides_raw(self):
        raw, _ = create_key(self.db_path, name="bot",
                            scopes=["presence:write"], per_min=60)
        items = list_keys(self.db_path)
        self.assertEqual(len(items), 1)
        self.assertNotIn(raw, json.dumps(items))

    def test_revoke(self):
        raw, _ = create_key(self.db_path, name="bot",
                            scopes=["presence:write"], per_min=60)
        self.assertTrue(revoke_key(self.db_path, raw))
        self.assertIsNone(lookup_key(self.db_path, raw))
        self.assertFalse(revoke_key(self.db_path, raw))

    def test_cli_create_list_revoke(self):
        rc = keys_mod.main(["--db", self.db_path, "create",
                            "--scopes", "presence:write",
                            "--rate", "30", "--name", "cli-bot"])
        self.assertEqual(rc, 0)
        items = list_keys(self.db_path)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "cli-bot")
        self.assertEqual(items[0]["per_min"], 30)
        rc = keys_mod.main(["--db", self.db_path, "list"])
        self.assertEqual(rc, 0)
        # revoke by hash prefix
        prefix = items[0]["key_hash"][:8]
        rc = keys_mod.main(["--db", self.db_path, "revoke", prefix])
        self.assertEqual(rc, 0)
        self.assertEqual(list_keys(self.db_path), [])


class KeyedEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="acp_pubapi_test_")
        cls.db_path = os.path.join(cls.tmp, "registry.db")
        cls.server, cls.thread = api_server.run(API_HOST, API_PORT,
                                                db_path=cls.db_path)
        cls.base = "http://%s:%d" % (API_HOST, API_PORT)
        raw, _ = create_key(cls.db_path, name="full",
                            scopes=ALL_SCOPES, per_min=100000)
        cls.client = DirectoryClient(cls.base, api_key=raw)
        cls.plain = DirectoryClient(cls.base)
        cls.priv, cls.pub, x_pub = gen_identity()
        cls.client.register("api_agent", b62encode(cls.pub),
                            b62encode(x_pub))

    @classmethod
    def tearDownClass(cls):
        api_server.graceful_shutdown(cls.server, cls.thread)

    # -- presence is keyed ------------------------------------------------

    def _presence_post(self, client, ts):
        sig = b62encode(ed25519_sign(
            self.priv,
            canonical({"handle": "api_agent", "state": "online", "ts": ts})))
        return client._request("POST", "/v1/presence",
                               {"handle": "api_agent", "state": "online",
                                "ts": ts, "sig": sig})[1]

    def test_presence_with_key_200(self):
        resp = self._presence_post(self.client, int(time.time()))
        self.assertEqual(resp["ok"], True)

    def test_presence_no_key_401(self):
        with self.assertRaises(DirectoryError) as cm:
            self._presence_post(self.plain, int(time.time()))
        self.assertEqual(cm.exception.status, 401)

    def test_presence_bad_key_401(self):
        bad = DirectoryClient(self.base, api_key="acp_" + "z" * 32)
        with self.assertRaises(DirectoryError) as cm:
            self._presence_post(bad, int(time.time()))
        self.assertEqual(cm.exception.status, 401)

    def test_presence_wrong_scope_403(self):
        raw, _ = create_key(self.db_path, name="narrow",
                            scopes=["analytics:read"], per_min=100000)
        narrow = DirectoryClient(self.base, api_key=raw)
        with self.assertRaises(DirectoryError) as cm:
            self._presence_post(narrow, int(time.time()))
        self.assertEqual(cm.exception.status, 403)

    def test_presence_replayed_sig_401(self):
        # attacker replays a once-valid signature with a stale timestamp
        ts = int(time.time()) - 900
        with self.assertRaises(DirectoryError) as cm:
            self._presence_post(self.client, ts)
        self.assertEqual(cm.exception.status, 401)

    # -- scope escalation --------------------------------------------------

    def test_scope_escalation_listings_403(self):
        raw, _ = create_key(self.db_path, name="presence-only",
                            scopes=["presence:write"], per_min=100000)
        narrow = DirectoryClient(self.base, api_key=raw)
        ts = int(time.time())
        with self.assertRaises(DirectoryError) as cm:
            narrow._request("POST", "/v1/listings",
                            {"handle": "api_agent",
                             "display_name": "Evil",
                             "capabilities": [], "owner": "evil",
                             "metadata": {}, "ts": ts, "sig": "0"})
        self.assertEqual(cm.exception.status, 403)

    # -- rate limiting ------------------------------------------------------

    def test_rate_limit_burst_429(self):
        raw, _ = create_key(self.db_path, name="slow",
                            scopes=["presence:write"], per_min=3)
        limited = DirectoryClient(self.base, api_key=raw)
        statuses = []
        retry_afters = []
        for _ in range(6):
            ts = int(time.time())
            sig = b62encode(ed25519_sign(
                self.priv, canonical({"handle": "api_agent",
                                      "state": "online", "ts": ts})))
            body = json.dumps({"handle": "api_agent", "state": "online",
                               "ts": ts, "sig": sig}).encode()
            req = urllib.request.Request(
                self.base + "/v1/presence", data=body,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + raw}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    statuses.append(resp.status)
            except urllib.error.HTTPError as e:
                statuses.append(e.code)
                retry_afters.append(e.headers.get("Retry-After"))
        self.assertIn(429, statuses,
                      "burst of 6 against per_min=3 never hit 429: %s"
                      % statuses)
        ra = [r for r in retry_afters if r]
        self.assertTrue(ra, "429 without Retry-After header")
        self.assertGreaterEqual(int(ra[0]), 1)

    def test_rate_limit_does_not_hit_public(self):
        # public reads are not keyed and not rate-limited
        for _ in range(10):
            body = self.plain.healthz()
            self.assertEqual(body["ok"], True)

    # -- public routes -------------------------------------------------------

    def test_public_routes_no_key(self):
        self.assertEqual(self.plain.healthz()["ok"], True)
        self.assertEqual(self.plain.resolve("api_agent")["handle"],
                         "api_agent")
        self.assertIn("listings",
                      self.plain.search_listings(q="nothing_here"))
        self.assertIn("authority_pub",
                      self.plain.get_verify_authority())
        self.assertIn("revoked", self.plain.list_revoked())
        got = self.plain.get_analytics("api_agent")
        self.assertEqual(got["handle"], "api_agent")

    # -- revocation ------------------------------------------------------------

    def test_revoked_key_401(self):
        raw, _ = create_key(self.db_path, name="doomed",
                            scopes=["presence:write"], per_min=100000)
        doomed = DirectoryClient(self.base, api_key=raw)
        self.assertEqual(
            self._presence_post(doomed, int(time.time()))["ok"], True)
        self.assertTrue(revoke_key(self.db_path, raw))
        with self.assertRaises(DirectoryError) as cm:
            self._presence_post(doomed, int(time.time()))
        self.assertEqual(cm.exception.status, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
