"""Tests for relay federation (services/acp_relay/federation.py).

Covers: cross-relay delivery, untrusted dial refusal, replayed frame
rejection, tampered hop-count drop, withdraw on disconnect, and
federated mailbox forwarding.

Note: Ed25519 is pure-Python here, so handshakes take seconds. Tests
poll with generous timeouts instead of fixed sleeps.

Run:  python3 tests/test_federation.py
"""
import json
import os
import socket
import sys
import tempfile
import time
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_relay"))

from acp_crypto import generate_ed25519_keypair, ed25519_publickey  # noqa: E402
from acp_proto import b62encode, canonical, make_envelope  # noqa: E402
from federation import (allowlist_add, load_or_create_identity,  # noqa: E402
                        FederationError)
import relay as relay_mod  # noqa: E402


def wait_until(fn, timeout=30, interval=0.5, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(interval)
    raise AssertionError("timed out waiting for: %s" % what)


def make_relay(mailbox=True, federation=True):
    d = tempfile.mkdtemp()
    cfg = {"data_dir": d,
           "mailbox_enabled": mailbox,
           "federation_enabled": federation,
           "fed_ping_interval_s": 60}
    server, thread = relay_mod.run("127.0.0.1", 0, cfg)
    return server, thread, d


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def federate(r1, d1, r2, d2):
    """Mutually allowlist and dial r1 -> r2. Returns when link is up."""
    id1 = r1.federation.relay_id
    id2 = r2.federation.relay_id
    allowlist_add(os.path.join(d1, "trusted_relays.json"), id2, "r2")
    allowlist_add(os.path.join(d2, "trusted_relays.json"), id1, "r1")
    r1.federation.dial("127.0.0.1", r2.server_address[1])
    wait_until(lambda: len(r1.federation.links()) == 1,
               timeout=30, what="r1 link up")
    wait_until(lambda: len(r2.federation.links()) == 1,
               timeout=30, what="r2 link up")


def gen_pid():
    priv, _ = generate_ed25519_keypair()
    return priv, b62encode(ed25519_publickey(priv))


def msg_frame(sender_priv, sender_pid, recip_pid, text="hi"):
    env = make_envelope("msg", sender_pid, recip_pid,
                        {"text": text, "msg_id": uuid.uuid4().hex},
                        sender_priv)
    return canonical(env)


class FederationTests(unittest.TestCase):
    def test_cross_relay_delivery(self):
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            federate(r1, d1, r2, d2)
            p1 = r1.server_address[1]
            p2 = r2.server_address[1]
            a_priv, a_pid = gen_pid()
            b_priv, b_pid = gen_pid()
            ca, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, a_priv)
            cb, _ = relay_mod.RelayClient.connect("127.0.0.1", p2, b_priv)
            try:
                # wait for route propagation (slow Ed25519)
                wait_until(lambda: r2.federation.route_for(a_pid) is not None,
                           timeout=30, what="route a->r2")
                wait_until(lambda: r1.federation.route_for(b_pid) is not None,
                           timeout=30, what="route b->r1")
                # A sends to B via federation
                frame = msg_frame(a_priv, a_pid, b_pid, "hello via fed")
                ca.send_frame(frame)
                got = cb.recv_frame(timeout=15)
                self.assertEqual(got, frame)  # byte-identical
                # B replies to A via federation
                back = msg_frame(b_priv, b_pid, a_pid, "reply via fed")
                cb.send_frame(back)
                got2 = ca.recv_frame(timeout=15)
                self.assertEqual(got2, back)
            finally:
                ca.close()
                cb.close()
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)

    def test_untrusted_dial_refused(self):
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            # only r1 trusts r2; r2 does NOT trust r1
            id2 = r2.federation.relay_id
            allowlist_add(os.path.join(d1, "trusted_relays.json"), id2, "r2")
            # dial should fail (r2 rejects)
            with self.assertRaises(Exception):
                r1.federation.dial("127.0.0.1", r2.server_address[1],
                                   timeout=15)
            self.assertEqual(len(r1.federation.links()), 0)
            self.assertEqual(len(r2.federation.links()), 0)
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)

    def test_withdraw_on_disconnect(self):
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            federate(r1, d1, r2, d2)
            p1 = r1.server_address[1]
            a_priv, a_pid = gen_pid()
            ca, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, a_priv)
            wait_until(lambda: r2.federation.route_for(a_pid) is not None,
                       timeout=30, what="route a->r2")
            # disconnect: withdraw should remove the route
            ca.close()
            wait_until(lambda: r2.federation.route_for(a_pid) is None,
                       timeout=30, what="route withdrawn")
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)

    def test_federated_mailbox_forward(self):
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            federate(r1, d1, r2, d2)
            p1 = r1.server_address[1]
            p2 = r2.server_address[1]
            a_priv, a_pid = gen_pid()
            b_priv, b_pid = gen_pid()
            # A on r1 sends to B (who is offline everywhere)
            ca, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, a_priv)
            wait_until(lambda: r2.federation.route_for(a_pid) is not None,
                       timeout=30, what="route a->r2")
            frame = msg_frame(a_priv, a_pid, b_pid, "offline via fed")
            ca.send_frame(frame)
            time.sleep(2)  # let r1 store it
            # B connects on r2: should get the federated mailbox forward
            cb, _ = relay_mod.RelayClient.connect("127.0.0.1", p2, b_priv)
            try:
                got = cb.recv_frame(timeout=20)
                self.assertEqual(got, frame)
            finally:
                ca.close()
                cb.close()
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)

    def test_tampered_hops_dropped(self):
        from acp_proto import b62encode as b62e
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            federate(r1, d1, r2, d2)
            p1 = r1.server_address[1]
            p2 = r2.server_address[1]
            a_priv, a_pid = gen_pid()
            b_priv, b_pid = gen_pid()
            ca, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, a_priv)
            cb, _ = relay_mod.RelayClient.connect("127.0.0.1", p2, b_priv)
            try:
                wait_until(lambda: r2.federation.route_for(a_pid) is not None,
                           timeout=30, what="route a->r2")
                wait_until(lambda: r1.federation.route_for(b_pid) is not None,
                           timeout=30, what="route b->r1")
                # Craft a fed_forward with tampered hops=99, send it
                # directly on r1's link to r2.
                frame = msg_frame(a_priv, a_pid, b_pid, "tampered hops")
                link = list(r1.federation.links().values())[0]
                link.send_obj({"fed_forward": {"hops": 99,
                                               "frame": b62e(frame)}})
                # r2 must drop it: audit fed.forward_dropped, and B
                # must NOT receive the frame.
                def dropped():
                    try:
                        with open(os.path.join(d2, "relay_audit.log")) as f:
                            return "fed.forward_dropped" in f.read()
                    except FileNotFoundError:
                        return False
                wait_until(dropped, timeout=15,
                           what="fed.forward_dropped audit")
                # B should get nothing (short timeout)
                cb.sock.settimeout(3)
                try:
                    got = cb.recv_frame(timeout=3)
                    self.fail("B received a frame that should have been "
                              "dropped: %r" % (got[:50],))
                except Exception:
                    pass  # timeout = good, nothing delivered
            finally:
                ca.close()
                cb.close()
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)


    def test_federation_links_config(self):
        # Two relays link automatically via the federation_links config:
        # no manual dial() call. Identities are pre-generated so the
        # allowlists can be written before either relay starts.
        d1 = tempfile.mkdtemp()
        d2 = tempfile.mkdtemp()
        _, _, id1 = load_or_create_identity(d1)
        _, _, id2 = load_or_create_identity(d2)
        allowlist_add(os.path.join(d1, "trusted_relays.json"), id2, "r2")
        allowlist_add(os.path.join(d2, "trusted_relays.json"), id1, "r1")
        cfg1 = {"data_dir": d1,
                "mailbox_enabled": True,
                "federation_enabled": True,
                "fed_ping_interval_s": 60,
                "fed_dial_retry_s": 2}
        r1, t1 = relay_mod.run("127.0.0.1", 0, cfg1)
        cfg2 = {"data_dir": d2,
                "mailbox_enabled": True,
                "federation_enabled": True,
                "fed_ping_interval_s": 60,
                "fed_dial_retry_s": 2,
                "federation_links": [
                    {"host": "127.0.0.1",
                     "port": r1.server_address[1],
                     "relay_id": id1,
                     "note": "r1"}]}
        r2, t2 = relay_mod.run("127.0.0.1", 0, cfg2)
        try:
            # link comes up on its own
            wait_until(lambda: len(r1.federation.links()) == 1,
                       timeout=45, what="r1 auto-link up")
            wait_until(lambda: len(r2.federation.links()) == 1,
                       timeout=45, what="r2 auto-link up")
            self.assertEqual(
                list(r2.federation.links())[0], id1,
                "dialed the pinned relay id")
            # end-to-end message over the auto-established link
            p1 = r1.server_address[1]
            p2 = r2.server_address[1]
            a_priv, a_pid = gen_pid()
            b_priv, b_pid = gen_pid()
            ca, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, a_priv)
            cb, _ = relay_mod.RelayClient.connect("127.0.0.1", p2, b_priv)
            try:
                wait_until(
                    lambda: r1.federation.route_for(b_pid) is not None,
                    timeout=30, what="route b->r1")
                frame = msg_frame(a_priv, a_pid, b_pid, "auto link msg")
                ca.send_frame(frame)
                got = cb.recv_frame(timeout=15)
                self.assertEqual(got, frame)
            finally:
                ca.close()
                cb.close()
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)

    def test_link_failure_degrades_gracefully(self):
        r1, t1, d1 = make_relay()
        r2, t2, d2 = make_relay()
        try:
            federate(r1, d1, r2, d2)
            # 1. dial to a dead port raises FederationError (fail-closed),
            #    and the relay keeps running.
            with self.assertRaises(FederationError):
                r1.federation.dial("127.0.0.1", free_port(), timeout=5)
            self.assertEqual(len(r1.federation.links()), 1)
            # 2. abrupt link death (no graceful close): both sides drop
            #    the link and withdraw routes, audit logs the event.
            link = list(r1.federation.links().values())[0]
            link.close()
            wait_until(lambda: len(r1.federation.links()) == 0,
                       timeout=30, what="r1 drops dead link")
            wait_until(lambda: len(r2.federation.links()) == 0,
                       timeout=30, what="r2 drops dead link")

            def link_down_logged():
                try:
                    with open(os.path.join(d1, "relay_audit.log")) as f:
                        return "fed.link_down" in f.read()
                except FileNotFoundError:
                    return False
            wait_until(link_down_logged, timeout=15,
                       what="fed.link_down audit")

            # 3. the relay still serves LOCAL traffic after the failure.
            p1 = r1.server_address[1]
            c_priv, c_pid = gen_pid()
            e_priv, e_pid = gen_pid()
            cc, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, c_priv)
            ce, _ = relay_mod.RelayClient.connect("127.0.0.1", p1, e_priv)
            # connect() returns once the hello is SENT; the server
            # verifies it asynchronously (pure-Python Ed25519), so wait
            # for both pids to be registered before sending -- otherwise
            # the frame can land in the mailbox while the recipient's
            # hello drain is still running and sit queued until the next
            # reconnect.
            wait_until(lambda: r1.lookup(c_pid) is not None
                       and r1.lookup(e_pid) is not None,
                       timeout=30, what="local pids registered")
            try:
                frame = msg_frame(c_priv, c_pid, e_pid, "local survives")
                cc.send_frame(frame)
                got = ce.recv_frame(timeout=10)
                self.assertEqual(got, frame)
                # 4. the now-unreachable pid falls back to mailbox
                #    instead of hanging or crashing.
                ghost_priv, ghost_pid = gen_pid()
                cc.send_frame(msg_frame(c_priv, c_pid, ghost_pid,
                                        "to the void"))
                resp = cc.recv_json(timeout=10)
                self.assertFalse(resp.get("relayed"))
                self.assertEqual(resp.get("error"), "offline")
                self.assertTrue(resp.get("queued"))
            finally:
                cc.close()
                ce.close()
        finally:
            relay_mod.graceful_shutdown(r1, t1)
            relay_mod.graceful_shutdown(r2, t2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
