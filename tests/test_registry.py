"""Tests for the Agent Registry Search (services/acp_api listings).

Covers: publish/get/update, multi-field search, capability/owner
filters, cursor pagination, limit caps, sig-auth (forged -> 401),
unregistered handle -> 404, stale ts -> 401, delete flow, and API-key
gating (missing key -> 401, wrong scope -> 403).

Run:  python3 tests/test_registry.py
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_api"))

from acp_crypto import (  # noqa: E402
    ed25519_publickey, ed25519_sign, ed25519_verify,
    generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import b62encode, b62decode, canonical  # noqa: E402

import server as api_server  # noqa: E402
from client import DirectoryClient, DirectoryError  # noqa: E402
from keys import create_key  # noqa: E402

API_HOST, API_PORT = "127.0.0.1", 18281
ALL_SCOPES = ["registry:read", "listings:write", "presence:write",
              "analytics:read", "analytics:write", "verify:request"]


def gen_identity():
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    return ed_priv, ed_pub, x_pub


def listing_sig(priv, handle, display_name, capabilities, owner, metadata,
                ts):
    msg = canonical({"handle": handle, "display_name": display_name,
                     "capabilities": capabilities, "owner": owner,
                     "metadata": metadata, "ts": ts})
    return b62encode(ed25519_sign(priv, msg))


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="acp_registry_test_")
        cls.db_path = os.path.join(cls.tmp, "registry.db")
        cls.server, cls.thread = api_server.run(API_HOST, API_PORT,
                                                db_path=cls.db_path)
        raw, _ = create_key(cls.db_path, name="test",
                            scopes=ALL_SCOPES, per_min=100000)
        cls.client = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                     api_key=raw)
        cls.plain = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT))
        # two registered agents
        cls.alice_priv, cls.alice_pub, alice_x = gen_identity()
        cls.bob_priv, cls.bob_pub, bob_x = gen_identity()
        cls.client.register("alice_r", b62encode(cls.alice_pub),
                            b62encode(alice_x))
        cls.client.register("bob_r", b62encode(cls.bob_pub),
                            b62encode(bob_x))

    @classmethod
    def tearDownClass(cls):
        api_server.graceful_shutdown(cls.server, cls.thread)

    # -- helpers ------------------------------------------------------

    def _publish(self, handle, priv, display_name="Alice Agent",
                 capabilities=("chat", "code-review"), owner="alice",
                 metadata=None, ts=None, client=None):
        metadata = {} if metadata is None else metadata
        ts = int(time.time()) if ts is None else ts
        sig = listing_sig(priv, handle, display_name, list(capabilities),
                          owner, metadata, ts)
        c = client or self.client
        return c._request("POST", "/v1/listings",
                          {"handle": handle, "display_name": display_name,
                           "capabilities": list(capabilities), "owner": owner,
                           "metadata": metadata, "ts": ts, "sig": sig})[1]

    # -- publish / get / update ---------------------------------------

    def test_publish_and_get(self):
        resp = self._publish("alice_r", self.alice_priv,
                             display_name="Alice the Helper",
                             capabilities=["chat", "summarize"],
                             owner="alice_owner",
                             metadata={"lang": "en", "tier": "free"})
        self.assertEqual(resp["ok"], True)
        got = self.client.get_listing("alice_r")
        self.assertEqual(got["handle"], "alice_r")
        self.assertEqual(got["display_name"], "Alice the Helper")
        self.assertEqual(got["capabilities"], ["chat", "summarize"])
        self.assertEqual(got["owner"], "alice_owner")
        self.assertEqual(got["metadata"], {"lang": "en", "tier": "free"})
        # the stored signature really verifies against the registered key
        sig = b62decode(got["listing_sig"]).rjust(64, b"\x00")
        msg = canonical({"handle": "alice_r",
                         "display_name": "Alice the Helper",
                         "capabilities": ["chat", "summarize"],
                         "owner": "alice_owner",
                         "metadata": {"lang": "en", "tier": "free"},
                         "ts": got["ts"]})
        self.assertTrue(ed25519_verify(self.alice_pub, msg, sig))

    def test_publish_update_overwrites(self):
        self._publish("bob_r", self.bob_priv, display_name="Bob v1",
                      capabilities=["chat"], owner="bob")
        self._publish("bob_r", self.bob_priv, display_name="Bob v2",
                      capabilities=["chat", "translate"], owner="bob")
        got = self.client.get_listing("bob_r")
        self.assertEqual(got["display_name"], "Bob v2")
        self.assertEqual(got["capabilities"], ["chat", "translate"])

    def test_get_unknown_404(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.get_listing("no_such_agent_xyz")
        self.assertEqual(cm.exception.status, 404)

    def test_search_is_public(self):
        # no API key needed for search
        body = self.plain.search_listings(q="alice")
        self.assertIn("listings", body)
        self.assertIn("next_cursor", body)

    # -- search --------------------------------------------------------

    def test_search_by_q(self):
        self._publish("alice_r", self.alice_priv,
                      display_name="Weather Bot Alpha",
                      capabilities=["weather"], owner="alice",
                      metadata={"desc": "hyperlocal forecasts"})
        body = self.client.search_listings(q="weather")
        handles = [l["handle"] for l in body["listings"]]
        self.assertIn("alice_r", handles)
        # metadata is searchable too
        body = self.client.search_listings(q="hyperlocal")
        self.assertIn("alice_r", [l["handle"] for l in body["listings"]])
        # no match
        body = self.client.search_listings(q="zzz_no_match_qqq")
        self.assertEqual(body["listings"], [])

    def test_search_capability_filter(self):
        self._publish("alice_r", self.alice_priv, capabilities=["vision"],
                      owner="alice")
        self._publish("bob_r", self.bob_priv, capabilities=["audio"],
                      owner="bob")
        body = self.client.search_listings(capability="vision")
        handles = [l["handle"] for l in body["listings"]]
        self.assertIn("alice_r", handles)
        self.assertNotIn("bob_r", handles)

    def test_search_owner_filter(self):
        self._publish("alice_r", self.alice_priv, owner="team_red")
        self._publish("bob_r", self.bob_priv, owner="team_blue")
        body = self.client.search_listings(owner="team_red")
        handles = [l["handle"] for l in body["listings"]]
        self.assertIn("alice_r", handles)
        self.assertNotIn("bob_r", handles)

    def test_search_pagination(self):
        # fresh handles so the page is exactly ours
        handles = []
        for i in range(5):
            h = "page_%d" % i
            priv, pub, x_pub = gen_identity()
            self.client.register(h, b62encode(pub), b62encode(x_pub))
            self._publish(h, priv, display_name="Pager %d" % i,
                          capabilities=["paging"], owner="pager")
            handles.append((h, priv))
        seen, cursor, pages = [], None, 0
        while True:
            body = self.client.search_listings(capability="paging", limit=2,
                                              cursor=cursor)
            seen += [l["handle"] for l in body["listings"]]
            pages += 1
            cursor = body["next_cursor"]
            if cursor is None:
                break
            self.assertLessEqual(pages, 10, "pagination did not terminate")
        self.assertEqual(sorted(seen), sorted(h for h, _ in handles))
        self.assertEqual(len(seen), len(set(seen)), "duplicate across pages")

    def test_search_limit_cap(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.search_listings(limit=101)
        self.assertEqual(cm.exception.status, 400)
        body = self.client.search_listings(limit=100)  # cap itself is fine
        self.assertIn("listings", body)

    def test_search_bad_cursor_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.search_listings(cursor="not-a-cursor")
        self.assertEqual(cm.exception.status, 400)

    # -- sig-auth attacks ----------------------------------------------

    def test_publish_forged_sig_401(self):
        evil_priv, _, _ = gen_identity()
        before = self.client.get_listing("alice_r")["display_name"]
        ts = int(time.time())
        with self.assertRaises(DirectoryError) as cm:
            self._publish("alice_r", evil_priv, ts=ts)
        self.assertEqual(cm.exception.status, 401)
        # the real listing is untouched
        after = self.client.get_listing("alice_r")["display_name"]
        self.assertEqual(before, after)

    def test_publish_unregistered_handle_404(self):
        ghost_priv, _, _ = gen_identity()
        ts = int(time.time())
        sig = listing_sig(ghost_priv, "ghost_xyz", "Ghost", [], "nobody",
                          {}, ts)
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/listings",
                {"handle": "ghost_xyz", "display_name": "Ghost",
                 "capabilities": [], "owner": "nobody", "metadata": {},
                 "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 404)

    def test_publish_stale_ts_401(self):
        ts = int(time.time()) - 600
        with self.assertRaises(DirectoryError) as cm:
            self._publish("alice_r", self.alice_priv, ts=ts)
        self.assertEqual(cm.exception.status, 401)

    def test_publish_tampered_field_401(self):
        # sign one display_name, send another
        ts = int(time.time())
        sig = listing_sig(self.alice_priv, "alice_r", "Real Name", [],
                          "alice", {}, ts)
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/listings",
                {"handle": "alice_r", "display_name": "Fake Name",
                 "capabilities": [], "owner": "alice", "metadata": {},
                 "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 401)

    # -- delete ----------------------------------------------------------

    def test_delete_listing(self):
        priv, pub, x_pub = gen_identity()
        self.client.register("del_me", b62encode(pub), b62encode(x_pub))
        self._publish("del_me", priv, display_name="Temporary")
        ts = int(time.time())
        sig = b62encode(ed25519_sign(
            priv, canonical({"handle": "del_me", "ts": ts})))
        resp = self.client._request(
            "DELETE", "/v1/listings/del_me",
            {"handle": "del_me", "ts": ts, "sig": sig})[1]
        self.assertEqual(resp, {"ok": True, "handle": "del_me"})
        with self.assertRaises(DirectoryError) as cm:
            self.client.get_listing("del_me")
        self.assertEqual(cm.exception.status, 404)

    def test_delete_forged_sig_401(self):
        self._publish("alice_r", self.alice_priv, display_name="Keep Me")
        evil_priv, _, _ = gen_identity()
        ts = int(time.time())
        sig = b62encode(ed25519_sign(
            evil_priv, canonical({"handle": "alice_r", "ts": ts})))
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "DELETE", "/v1/listings/alice_r",
                {"handle": "alice_r", "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 401)
        # still there, untouched
        self.assertEqual(self.client.get_listing("alice_r")["display_name"],
                         "Keep Me")

    def test_delete_missing_404(self):
        priv, pub, x_pub = gen_identity()
        self.client.register("del_none", b62encode(pub), b62encode(x_pub))
        ts = int(time.time())
        sig = b62encode(ed25519_sign(
            priv, canonical({"handle": "del_none", "ts": ts})))
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "DELETE", "/v1/listings/del_none",
                {"handle": "del_none", "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 404)

    # -- key gating ------------------------------------------------------

    def test_publish_no_key_401(self):
        with self.assertRaises(DirectoryError) as cm:
            self._publish("alice_r", self.alice_priv, client=self.plain)
        self.assertEqual(cm.exception.status, 401)

    def test_publish_wrong_scope_403(self):
        raw, _ = create_key(self.db_path, name="narrow",
                            scopes=["presence:write"], per_min=100000)
        narrow = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                 api_key=raw)
        with self.assertRaises(DirectoryError) as cm:
            self._publish("alice_r", self.alice_priv, client=narrow)
        self.assertEqual(cm.exception.status, 403)

    def test_delete_no_key_401(self):
        ts = int(time.time())
        sig = b62encode(ed25519_sign(
            self.alice_priv, canonical({"handle": "alice_r", "ts": ts})))
        with self.assertRaises(DirectoryError) as cm:
            self.plain._request("DELETE", "/v1/listings/alice_r",
                                {"handle": "alice_r", "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
