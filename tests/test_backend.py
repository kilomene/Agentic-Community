"""Integration tests for the Agent Community backend services.

  services/acp_api   — public key directory + presence (HTTP/JSON)
  services/acp_relay — TCP relay for NAT traversal

Run:  python3 tests/test_backend.py
"""
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_api"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_relay"))

from acp_crypto import (  # noqa: E402
    ed25519_publickey, ed25519_sign,
    generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import (  # noqa: E402
    b62encode, canonical, make_envelope,
)

import server as api_server  # noqa: E402
from client import DirectoryClient, DirectoryError  # noqa: E402
from keys import create_key as _create_api_key  # noqa: E402
import relay as relay_mod  # noqa: E402
from relay import RelayClient  # noqa: E402

API_HOST, API_PORT = "127.0.0.1", 18080
RELAY_HOST, RELAY_PORT = "127.0.0.1", 19090


def gen_identity():
    """-> (ed_priv, ed_pub, x_priv, x_pub)"""
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return ed_priv, ed_pub, x_priv, x_pub


# ---------------------------------------------------------------- API

class ApiDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="acp_api_test_")
        db_path = os.path.join(cls.tmp, "registry.db")
        cls.server, cls.thread = api_server.run(API_HOST, API_PORT,
                                                db_path=db_path)
        # POST /v1/presence is key-gated (scope presence:write); the
        # directory client carries the operator-issued key.
        raw, _ = _create_api_key(
            db_path, name="test",
            scopes=["registry:read", "listings:write", "presence:write",
                    "analytics:read", "analytics:write", "verify:request"],
            per_min=100000)
        cls.client = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                     api_key=raw)

    @classmethod
    def tearDownClass(cls):
        api_server.graceful_shutdown(cls.server, cls.thread)

    # -- healthz ------------------------------------------------------

    def test_healthz(self):
        body = self.client.healthz()
        self.assertEqual(body, {"ok": True, "version": "1.0"})

    # -- register / resolve -------------------------------------------

    def test_register_and_resolve(self):
        ed_priv, ed_pub, x_priv, x_pub = gen_identity()
        resp = self.client.register("alice", b62encode(ed_pub),
                                    b62encode(x_pub))
        self.assertEqual(resp, {"ok": True, "handle": "alice"})
        got = self.client.resolve("alice")
        self.assertEqual(got["handle"], "alice")
        self.assertEqual(got["ipub"], b62encode(ed_pub))
        self.assertEqual(got["x_pub"], b62encode(x_pub))
        self.assertIsInstance(got["updated_at"], int)

    def test_register_duplicate_409(self):
        ed_priv, ed_pub, x_priv, x_pub = gen_identity()
        self.client.register("bob", b62encode(ed_pub), b62encode(x_pub))
        with self.assertRaises(DirectoryError) as cm:
            self.client.register("bob", b62encode(ed_pub), b62encode(x_pub))
        self.assertEqual(cm.exception.status, 409)

    def test_register_bad_handle_400(self):
        ed_priv, ed_pub, x_priv, x_pub = gen_identity()
        for bad in ("AB", "a", "has space", "UPPER", "with-dash",
                    "x" * 33, ""):
            with self.assertRaises(DirectoryError) as cm:
                self.client.register(bad, b62encode(ed_pub),
                                     b62encode(x_pub))
            self.assertEqual(cm.exception.status, 400, bad)

    def test_register_bad_key_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.register("badkey1", "not!!base62!!", "0")
        self.assertEqual(cm.exception.status, 400)

    def test_resolve_unknown_404(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.resolve("nobody_here_xyz")
        self.assertEqual(cm.exception.status, 404)

    # -- presence -----------------------------------------------------

    def _register(self, handle):
        ed_priv, ed_pub, x_priv, x_pub = gen_identity()
        self.client.register(handle, b62encode(ed_pub), b62encode(x_pub))
        return ed_priv

    def _sig(self, priv, handle, state, ts):
        return b62encode(ed25519_sign(
            priv, canonical({"handle": handle, "state": state, "ts": ts})))

    def test_presence_set_and_get(self):
        priv = self._register("carol")
        ts = int(time.time())
        sig = self._sig(priv, "carol", "online", ts)
        resp = self.client._request(
            "POST", "/v1/presence",
            {"handle": "carol", "state": "online", "ts": ts, "sig": sig})[1]
        self.assertEqual(resp["ok"], True)
        self.assertEqual(resp["state"], "online")
        got = self.client.get_presence("carol")
        self.assertEqual(got, {"handle": "carol", "state": "online", "ts": ts})

    def test_presence_update_state(self):
        priv = self._register("dave")
        ts = int(time.time())
        self.client._request(
            "POST", "/v1/presence",
            {"handle": "dave", "state": "online", "ts": ts,
             "sig": self._sig(priv, "dave", "online", ts)})
        ts2 = ts + 5
        self.client._request(
            "POST", "/v1/presence",
            {"handle": "dave", "state": "busy", "ts": ts2,
             "sig": self._sig(priv, "dave", "busy", ts2)})
        got = self.client.get_presence("dave")
        self.assertEqual(got["state"], "busy")
        self.assertEqual(got["ts"], ts2)

    def test_presence_bad_sig_401(self):
        self._register("erin")
        other_priv, _, _, _ = gen_identity()
        ts = int(time.time())
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/presence",
                {"handle": "erin", "state": "online", "ts": ts,
                 "sig": self._sig(other_priv, "erin", "online", ts)})
        self.assertEqual(cm.exception.status, 401)

    def test_presence_stale_ts_401(self):
        priv = self._register("frank")
        ts = int(time.time()) - 600
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/presence",
                {"handle": "frank", "state": "online", "ts": ts,
                 "sig": self._sig(priv, "frank", "online", ts)})
        self.assertEqual(cm.exception.status, 401)

    def test_presence_unknown_handle_404(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.get_presence("ghost_xyz")
        self.assertEqual(cm.exception.status, 404)

    def test_presence_bad_state_400(self):
        priv = self._register("grace")
        ts = int(time.time())
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/presence",
                {"handle": "grace", "state": "invisible", "ts": ts,
                 "sig": self._sig(priv, "grace", "invisible", ts)})
        self.assertEqual(cm.exception.status, 400)


# ---------------------------------------------------------------- relay

class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.thread = relay_mod.run(RELAY_HOST, RELAY_PORT)

    @classmethod
    def tearDownClass(cls):
        relay_mod.graceful_shutdown(cls.server, cls.thread)

    def setUp(self):
        self.a_priv, self.a_pub = generate_ed25519_keypair()[:2]
        self.b_priv, self.b_pub = generate_ed25519_keypair()[:2]
        self.cli_a, self.pid_a = RelayClient.connect(
            RELAY_HOST, RELAY_PORT, self.a_priv)
        self.cli_b, self.pid_b = RelayClient.connect(
            RELAY_HOST, RELAY_PORT, self.b_priv)
        # wait for both hello registrations to land on the server
        deadline = time.time() + 5
        while self.server.peer_count() < 2 and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.server.peer_count(), 2)

    def tearDown(self):
        self.cli_a.close()
        self.cli_b.close()

    def _envelope_frame(self, to_pid, kind="presence", payload=None,
                        priv=None):
        payload = payload if payload is not None else {"state": "online"}
        env = make_envelope(kind, self.pid_a, to_pid, payload,
                            priv or self.a_priv)
        return canonical(env)  # raw JSON bytes; send_frame adds the prefix

    def test_forward_exact_bytes(self):
        frame = self._envelope_frame(self.pid_b)
        self.cli_a.send_frame(frame)
        got = self.cli_b.recv_frame(timeout=10)
        self.assertEqual(got, frame)

    def test_forward_e2e_style_envelope(self):
        # relay only reads "to"; E2E content ("box") stays opaque
        from acp_proto import make_e2e_envelope
        _, _, ax_priv, ax_pub = gen_identity()
        _, _, bx_priv, bx_pub = gen_identity()
        env = make_e2e_envelope("msg", self.pid_a, self.pid_b,
                                {"text": "hello", "msg_id": "m1"},
                                self.a_priv, ax_priv, ax_pub, bx_pub)
        frame = canonical(env)
        self.cli_a.send_frame(frame)
        got = self.cli_b.recv_frame(timeout=10)
        self.assertEqual(got, frame)

    def test_offline_target_error(self):
        _, offline_pub = generate_ed25519_keypair()
        pid_c = b62encode(offline_pub)
        self.cli_a.send_frame(self._envelope_frame(pid_c))
        resp = self.cli_a.recv_json(timeout=10)
        self.assertEqual(resp, {"relayed": False, "to": pid_c,
                                "error": "offline"})

    def test_ping_pong(self):
        self.cli_a.send_json({"ping": 123456789})
        self.assertEqual(self.cli_a.recv_json(timeout=10),
                         {"pong": 123456789})

    def test_bad_hello_sig_closes(self):
        s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=5)
        try:
            _, pub = generate_ed25519_keypair()
            pid = b62encode(pub)
            ts = int(time.time())
            bad = canonical({"hello": {"pid": pid, "ts": ts,
                                        "sig": b62encode(b"\x00" * 64)}})
            s.sendall(struct.pack(">I", len(bad)) + bad)
            s.settimeout(5)
            try:
                data = s.recv(1)
            except (ConnectionResetError, socket.timeout):
                data = b""
            self.assertEqual(data, b"",
                             "relay kept connection open on bad hello sig")
        finally:
            s.close()

    def test_stale_hello_ts_closes(self):
        priv, _ = generate_ed25519_keypair()
        s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=5)
        try:
            pid = b62encode(ed25519_publickey(priv))
            ts = int(time.time()) - 900
            sig = b62encode(ed25519_sign(
                priv, canonical({"pid": pid, "ts": ts})))
            stale = canonical({"hello": {"pid": pid, "ts": ts, "sig": sig}})
            s.sendall(struct.pack(">I", len(stale)) + stale)
            s.settimeout(5)
            try:
                data = s.recv(1)
            except (ConnectionResetError, socket.timeout):
                data = b""
            self.assertEqual(data, b"",
                             "relay kept connection open on stale hello ts")
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
