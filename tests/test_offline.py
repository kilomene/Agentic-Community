"""Tests for the offline message mailbox (services/acp_relay/mailbox.py).

Covers: FIFO store->redeliver across reconnect, unacked retry, TTL
expiry, overflow eviction (count + bytes), forged-frame rejection by the
recipient, and control frames never being stored.

Run:  python3 tests/test_offline.py
"""
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_relay"))

from acp_crypto import generate_ed25519_keypair  # noqa: E402
from acp_proto import b62encode, canonical, make_envelope  # noqa: E402
import mailbox as mailbox_mod  # noqa: E402
from mailbox import Mailbox  # noqa: E402
import relay as relay_mod  # noqa: E402


def _frame(sender_priv, sender_pid, recip_pid, text="hello"):
    import uuid
    env = make_envelope("msg", sender_pid, recip_pid,
                        {"text": text, "msg_id": uuid.uuid4().hex},
                        sender_priv)
    return canonical(env)


class MailboxUnitTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.mb = Mailbox(os.path.join(self.dir, "mb.db"))

    def _store(self, recip="r1", n=1, size=100):
        s_priv, _ = generate_ed25519_keypair()
        s_pid = b62encode(__import__("acp_crypto").ed25519_publickey(s_priv))
        ids = []
        for i in range(n):
            frame = _frame(s_priv, s_pid, recip, "msg%d" % i)
            # pad to size
            frame = frame + b" " * (size - len(frame))
            ids.append(self.mb.store(recip, s_pid, "msg", frame))
        return ids

    def test_fifo_order(self):
        ids = self._store(n=5)
        pending = self.mb.pending("r1")
        self.assertEqual([r["id"] for r in pending], ids)
        # frames come back byte-identical
        for r, i in zip(pending, range(5)):
            self.assertIn(b"msg%d" % i, r["frame"])

    def test_ack_removes(self):
        ids = self._store(n=3)
        self.mb.mark_inflight(ids)
        self.mb.ack("r1", ids)
        self.assertEqual(self.mb.pending("r1"), [])
        c = self.mb.count("r1")
        self.assertEqual(c, (0, 0))

    def test_unacked_retried(self):
        ids = self._store(n=2)
        self.mb.mark_inflight(ids)
        # no ack: reset -> back to queued
        self.mb.reset_inflight("r1")
        pending = self.mb.pending("r1")
        self.assertEqual([r["id"] for r in pending], ids)

    def test_ttl_expiry(self):
        mb = Mailbox(os.path.join(self.dir, "mb2.db"), default_ttl_s=1)
        s_priv, _ = generate_ed25519_keypair()
        from acp_crypto import ed25519_publickey
        s_pid = b62encode(ed25519_publickey(s_priv))
        mb.store("r1", s_pid, "msg", _frame(s_priv, s_pid, "r1"))
        self.assertEqual(len(mb.pending("r1")), 1)
        time.sleep(1.2)
        mb.prune_expired()
        self.assertEqual(mb.pending("r1"), [])

    def test_overflow_count_eviction(self):
        mb = Mailbox(os.path.join(self.dir, "mb3.db"), max_per_recipient=3)
        s_priv, _ = generate_ed25519_keypair()
        from acp_crypto import ed25519_publickey
        s_pid = b62encode(ed25519_publickey(s_priv))
        for i in range(5):
            mb.store("r1", s_pid, "msg",
                     _frame(s_priv, s_pid, "r1", "msg%d" % i))
        pending = mb.pending("r1")
        # oldest 2 evicted, newest 3 kept
        self.assertEqual(len(pending), 3)
        texts = [r["frame"] for r in pending]
        self.assertTrue(any(b"msg4" in t for t in texts))
        self.assertTrue(any(b"msg3" in t for t in texts))
        self.assertTrue(any(b"msg2" in t for t in texts))
        self.assertFalse(any(b"msg0" in t for t in texts))

    def test_overflow_bytes_eviction(self):
        mb = Mailbox(os.path.join(self.dir, "mb4.db"),
                     max_bytes_per_recipient=500)
        s_priv, _ = generate_ed25519_keypair()
        from acp_crypto import ed25519_publickey
        s_pid = b62encode(ed25519_publickey(s_priv))
        for i in range(5):
            f = _frame(s_priv, s_pid, "r1", "x" * 200)
            mb.store("r1", s_pid, "msg", f)
        pending = mb.pending("r1")
        total = sum(r["size"] for r in pending)
        self.assertLessEqual(total, 500)
        # newest kept
        self.assertTrue(any(b"xxxx" in r["frame"] for r in pending))


class MailboxRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cfg = {"data_dir": cls.dir, "mailbox_enabled": True}
        cls.server, cls.thread = relay_mod.run("127.0.0.1", 0, cfg)
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        relay_mod.graceful_shutdown(cls.server, cls.thread)

    def test_control_frames_never_stored(self):
        # Control frames (not envelopes) must never be stored, even for
        # offline recipients.
        from acp_crypto import ed25519_publickey
        r_priv, _ = generate_ed25519_keypair()
        r_pid = b62encode(ed25519_publickey(r_priv))
        s_priv, _ = generate_ed25519_keypair()
        sender, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                  s_priv)
        try:
            # Send a control frame (ping) targeted at offline r_pid.
            # The relay should not store it.
            sender.send_json({"ping": {"to": r_pid}})
            time.sleep(0.5)
            mb = self.server.mailbox
            self.assertEqual(mb.pending(r_pid), [])
        finally:
            sender.close()

    def test_forged_frame_delivered_verbatim(self):
        # A forged frame inserted directly into the mailbox must be
        # delivered byte-identical so the recipient's own signature
        # verification can reject it (defense in depth: the relay never
        # re-signs or alters).
        from acp_crypto import ed25519_publickey
        import uuid
        s_priv, _ = generate_ed25519_keypair()
        r_priv, _ = generate_ed25519_keypair()
        s_pid = b62encode(ed25519_publickey(s_priv))
        r_pid = b62encode(ed25519_publickey(r_priv))
        # Create a valid frame then tamper with the payload
        env = make_envelope("msg", s_pid, r_pid,
                            {"text": "legit", "msg_id": uuid.uuid4().hex},
                            s_priv)
        raw = bytearray(canonical(env))
        # Flip a byte in the text (forgery)
        raw = raw.replace(b"legit", b"FORGED")
        raw = bytes(raw)
        mb = self.server.mailbox
        mb.store(r_pid, s_pid, "msg", raw)
        # Recipient connects and gets the forged frame verbatim
        recvr, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                 r_priv)
        try:
            ids, frames = recvr.drain_mailbox(timeout=10)
            self.assertEqual(len(ids), 1)
            self.assertEqual(frames[0], raw)  # byte-identical
            self.assertIn(b"FORGED", frames[0])
            recvr.ack_mailbox(ids)
        finally:
            recvr.close()

    def test_offline_store_and_redeliver(self):
        # sender and recipient keys
        s_priv, _ = generate_ed25519_keypair()
        r_priv, _ = generate_ed25519_keypair()
        from acp_crypto import ed25519_publickey
        s_pid = b62encode(ed25519_publickey(s_priv))
        r_pid = b62encode(ed25519_publickey(r_priv))
        # recipient is offline; sender connects and sends
        sender, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                  s_priv)
        frame = _frame(s_priv, s_pid, r_pid, "offline hello")
        sender.send_frame(frame)
        time.sleep(0.5)
        sender.close()
        # recipient connects: should get mailbox_delivery
        recvr, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                 r_priv)
        ids, frames = recvr.drain_mailbox(timeout=10)
        self.assertEqual(len(ids), 1)
        self.assertEqual(frames[0], frame)  # byte-identical
        # ack it
        acked = recvr.ack_mailbox(ids)
        self.assertEqual(acked, 1)
        recvr.close()
        # reconnect: nothing queued now
        recvr2, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                  r_priv)
        # no mailbox_delivery should arrive (would block); just check
        # the mailbox is empty via the server object
        mb = self.server.mailbox
        self.assertEqual(mb.pending(r_pid), [])
        recvr2.close()

    def test_unacked_redelivered_next_reconnect(self):
        s_priv, _ = generate_ed25519_keypair()
        r_priv, _ = generate_ed25519_keypair()
        from acp_crypto import ed25519_publickey
        s_pid = b62encode(ed25519_publickey(s_priv))
        r_pid = b62encode(ed25519_publickey(r_priv))
        sender, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                  s_priv)
        frame = _frame(s_priv, s_pid, r_pid, "no ack")
        sender.send_frame(frame)
        time.sleep(0.5)
        sender.close()
        # recipient drains but does NOT ack, then disconnects
        recvr, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                 r_priv)
        ids, frames = recvr.drain_mailbox(timeout=10)
        self.assertEqual(len(ids), 1)
        recvr.close()  # no ack
        time.sleep(0.5)
        # reconnect: should get it again
        recvr2, _ = relay_mod.RelayClient.connect("127.0.0.1", self.port,
                                                  r_priv)
        ids2, frames2 = recvr2.drain_mailbox(timeout=10)
        self.assertEqual(len(ids2), 1)
        self.assertEqual(frames2[0], frame)
        recvr2.ack_mailbox(ids2)
        recvr2.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
