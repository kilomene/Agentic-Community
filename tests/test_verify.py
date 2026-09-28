"""Tests for Agent Identity Verification (services/acp_api verify).

Covers: authority key endpoint, self + owner-linked badge issuance,
badge signature verification against the authority key, 90-day expiry,
statement binding (agent_id/level/ts), forged statement sig -> 401,
stale ts -> 401, unregistered handle -> 404, revocation flow, forged
authority sig -> 401, revoked badge flagged revoked, revocation list.

This is attestation-based verification (the authority attests it saw a
valid key-ownership signature), not identity proofing — see
docs/VERIFY.md.

Run:  python3 tests/test_verify.py
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
    ed25519_sign, ed25519_verify,
    generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import b62encode, b62decode, canonical  # noqa: E402

import server as api_server  # noqa: E402
import verify as verify_mod  # noqa: E402
from client import DirectoryClient, DirectoryError  # noqa: E402
from keys import create_key  # noqa: E402

API_HOST, API_PORT = "127.0.0.1", 18282
ALL_SCOPES = ["registry:read", "listings:write", "presence:write",
              "analytics:read", "analytics:write", "verify:request"]
BADGE_TTL = 90 * 24 * 3600


def gen_identity():
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    return ed_priv, ed_pub, x_pub


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="acp_verify_test_")
        cls.db_path = os.path.join(cls.tmp, "registry.db")
        cls.server, cls.thread = api_server.run(API_HOST, API_PORT,
                                                db_path=cls.db_path)
        raw, _ = create_key(cls.db_path, name="test",
                            scopes=ALL_SCOPES, per_min=100000)
        cls.client = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                     api_key=raw)
        cls.plain = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT))
        cls.alice_priv, cls.alice_pub, alice_x = gen_identity()
        cls.bob_priv, cls.bob_pub, bob_x = gen_identity()
        cls.client.register("alice_v", b62encode(cls.alice_pub),
                            b62encode(alice_x))
        cls.client.register("bob_v", b62encode(cls.bob_pub),
                            b62encode(bob_x))
        # operator-side authority private key (same file the server made)
        cls.authority_priv, cls.authority_pub = \
            verify_mod.load_authority(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        api_server.graceful_shutdown(cls.server, cls.thread)

    # -- authority ----------------------------------------------------

    def test_authority_endpoint(self):
        body = self.plain.get_verify_authority()  # public, no key
        self.assertEqual(body["authority_pub"],
                         b62encode(self.authority_pub))

    def test_authority_key_stable(self):
        priv2, pub2 = verify_mod.load_authority(self.tmp)
        self.assertEqual(priv2, self.authority_priv)
        self.assertEqual(pub2, self.authority_pub)

    # -- issuance -------------------------------------------------------

    def test_self_badge(self):
        badge = self.client.request_verification(
            "alice_v", "self", "", self.alice_priv)
        self.assertEqual(badge["handle"], "alice_v")
        self.assertEqual(badge["agent_id"], b62encode(self.alice_pub))
        self.assertEqual(badge["level"], "self")
        self.assertEqual(badge["external_ref"], "")
        self.assertEqual(badge["expires_at"] - badge["issued_at"], BADGE_TTL)
        # the authority signature really verifies
        self.assertTrue(verify_mod.verify_badge(badge, self.authority_pub))
        sig = b62decode(badge["authority_sig"]).rjust(64, b"\x00")
        payload = {k: v for k, v in badge.items() if k != "authority_sig"}
        self.assertTrue(
            ed25519_verify(self.authority_pub, canonical(payload), sig))

    def test_owner_linked_badge(self):
        badge = self.client.request_verification(
            "bob_v", "owner-linked", "x:@bob_builder", self.bob_priv)
        self.assertEqual(badge["level"], "owner-linked")
        self.assertEqual(badge["external_ref"], "x:@bob_builder")
        self.assertTrue(verify_mod.verify_badge(badge, self.authority_pub))

    def test_get_badge(self):
        self.client.request_verification("alice_v", "self", "",
                                         self.alice_priv)
        badge = self.plain.get_badge("alice_v")  # public read
        self.assertEqual(badge["handle"], "alice_v")
        self.assertTrue(verify_mod.verify_badge(badge, self.authority_pub))

    def test_get_badge_unknown_404(self):
        with self.assertRaises(DirectoryError) as cm:
            self.plain.get_badge("nobody_v_xyz")
        self.assertEqual(cm.exception.status, 404)

    def test_reissue_supersedes(self):
        b1 = self.client.request_verification("bob_v", "self", "",
                                              self.bob_priv)
        time.sleep(1.05)
        b2 = self.client.request_verification(
            "bob_v", "owner-linked", "gh:bob", self.bob_priv)
        self.assertGreaterEqual(b2["issued_at"], b1["issued_at"])
        got = self.client.get_badge("bob_v")
        self.assertEqual(got["level"], "owner-linked")

    # -- statement binding ----------------------------------------------

    def _raw_request(self, handle, statement, priv, ts, client=None):
        sig = b62encode(ed25519_sign(priv, canonical(statement)))
        c = client or self.client
        return c._request("POST", "/v1/verify/request",
                          {"handle": handle, "level": statement["level"],
                           "statement": statement, "ts": ts,
                           "sig": sig})[1]

    def test_forged_statement_sig_401(self):
        evil_priv, _, _ = gen_identity()
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub), "level": "self",
                     "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, evil_priv, ts)
        self.assertEqual(cm.exception.status, 401)

    def test_agent_id_mismatch_400(self):
        evil_priv, evil_pub, _ = gen_identity()
        ts = int(time.time())
        # attacker signs a statement naming THEIR key for alice's handle
        statement = {"agent_id": b62encode(evil_pub), "level": "self",
                     "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, evil_priv, ts)
        self.assertEqual(cm.exception.status, 400)

    def test_level_mismatch_400(self):
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub),
                     "level": "owner-linked",
                     "external_ref": "x:@alice", "ts": ts}
        sig = b62encode(ed25519_sign(self.alice_priv, canonical(statement)))
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/verify/request",
                {"handle": "alice_v", "level": "self",
                 "statement": statement, "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 400)

    def test_statement_ts_mismatch_400(self):
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub), "level": "self",
                     "external_ref": "", "ts": ts - 10}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, self.alice_priv, ts)
        self.assertEqual(cm.exception.status, 400)

    def test_stale_ts_401(self):
        ts = int(time.time()) - 600
        statement = {"agent_id": b62encode(self.alice_pub), "level": "self",
                     "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, self.alice_priv, ts)
        self.assertEqual(cm.exception.status, 401)

    def test_unregistered_handle_404(self):
        ghost_priv, ghost_pub, _ = gen_identity()
        ts = int(time.time())
        statement = {"agent_id": b62encode(ghost_pub), "level": "self",
                     "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("ghost_v_xyz", statement, ghost_priv, ts)
        self.assertEqual(cm.exception.status, 404)

    def test_bad_level_400(self):
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub),
                     "level": "government-id", "external_ref": "", "ts": ts}
        sig = b62encode(ed25519_sign(self.alice_priv, canonical(statement)))
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/verify/request",
                {"handle": "alice_v", "level": "government-id",
                 "statement": statement, "ts": ts, "sig": sig})
        self.assertEqual(cm.exception.status, 400)

    def test_self_with_external_ref_400(self):
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub), "level": "self",
                     "external_ref": "x:@alice", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, self.alice_priv, ts)
        self.assertEqual(cm.exception.status, 400)

    def test_owner_linked_without_ref_400(self):
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.bob_pub),
                     "level": "owner-linked", "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("bob_v", statement, self.bob_priv, ts)
        self.assertEqual(cm.exception.status, 400)

    def test_request_no_key_401(self):
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v",
                              {"agent_id": b62encode(self.alice_pub),
                               "level": "self", "external_ref": "",
                               "ts": int(time.time())},
                              self.alice_priv, int(time.time()),
                              client=self.plain)
        self.assertEqual(cm.exception.status, 401)

    def test_request_wrong_scope_403(self):
        raw, _ = create_key(self.db_path, name="narrow",
                            scopes=["presence:write"], per_min=100000)
        narrow = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                 api_key=raw)
        ts = int(time.time())
        statement = {"agent_id": b62encode(self.alice_pub), "level": "self",
                     "external_ref": "", "ts": ts}
        with self.assertRaises(DirectoryError) as cm:
            self._raw_request("alice_v", statement, self.alice_priv, ts,
                              client=narrow)
        self.assertEqual(cm.exception.status, 403)

    # -- revocation -------------------------------------------------------

    def test_revoke_and_flagged(self):
        self.client.request_verification("alice_v", "self", "",
                                         self.alice_priv)
        resp = self.client.revoke_verification(
            "alice_v", "key compromise suspected", self.authority_priv)
        self.assertEqual(resp["ok"], True)
        # a revoked badge is FLAGGED, not silently served
        got = self.plain.get_badge("alice_v")
        self.assertEqual(got.get("revoked"), True)
        self.assertEqual(got["handle"], "alice_v")
        self.assertEqual(got["reason"], "key compromise suspected")
        self.assertNotIn("authority_sig", got)
        # and it shows up in the revocation list
        revoked = self.plain.list_revoked()["revoked"]
        self.assertIn("alice_v", [r["handle"] for r in revoked])

    def test_revoke_forged_authority_sig_401(self):
        evil_priv, _, _ = gen_identity()
        ts = int(time.time())
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/verify/revoke",
                {"handle": "bob_v", "reason": "evil",
                 "ts": ts,
                 "authority_sig": b62encode(ed25519_sign(
                     evil_priv, canonical({"handle": "bob_v",
                                           "reason": "evil", "ts": ts})))})
        self.assertEqual(cm.exception.status, 401)
        # bob's badge is untouched
        got = self.client.get_badge("bob_v")
        self.assertNotIn("revoked", got)

    def test_reissue_clears_revocation(self):
        self.client.request_verification("alice_v", "self", "",
                                         self.alice_priv)
        self.client.revoke_verification("alice_v", "oops",
                                        self.authority_priv)
        self.assertEqual(self.plain.get_badge("alice_v")["revoked"], True)
        self.client.request_verification("alice_v", "self", "",
                                         self.alice_priv)
        got = self.plain.get_badge("alice_v")
        self.assertNotIn("revoked", got)
        self.assertTrue(verify_mod.verify_badge(got, self.authority_pub))


if __name__ == "__main__":
    unittest.main(verbosity=2)
