#!/usr/bin/env python3
"""pair_and_chat.py — pair two local agents and exchange a message.

Runs two AcpClients in one process (real TCP, real E2E encryption):
responder auto-accepts the pairing and shows the code; the initiator
reads it via the approve_callback.

    python3 -m acp_sdk.examples.pair_and_chat --text "hello bob"
"""
import argparse
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_sdk import AcpClient  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--home-a", default="/tmp/acp-sdk-alice")
    p.add_argument("--home-b", default="/tmp/acp-sdk-bob")
    p.add_argument("--passphrase", default="sdk-demo-pass")
    p.add_argument("--text", default="hello bob, this is alice")
    args = p.parse_args(argv)

    code_box = {}

    with AcpClient(args.home_a, args.passphrase, handle="alice") as alice, \
            AcpClient(args.home_b, args.passphrase, handle="bob") as bob:
        alice.start_server()
        bob_host, bob_port = bob.start_server()

        bob.on_pairing_request(
            lambda session: (code_box.setdefault("code", session.code),
                             session.accept()))

        got = threading.Event()
        inbox = []

        def on_msg(sender, text, msg_id):
            inbox.append((sender, text, msg_id))
            got.set()

        bob.on_message(on_msg)

        peer_id = alice.pair_with(bob_host, bob_port,
                                  approve_callback=lambda: code_box["code"])
        assert peer_id == bob.peer_id, "paired with the wrong peer"
        print("paired: alice -> bob (%s...)" % peer_id[:12])

        mid = alice.send_message(peer_id, args.text)
        assert got.wait(30), "bob never received the message"
        sender, text, got_mid = inbox[0]
        assert sender == alice.peer_id and text == args.text
        print("bob received: %r (msg %s...)" % (text, got_mid[:8]))
        print("OK: pair + chat works (msg id %s...)" % mid[:8])
    return 0


if __name__ == "__main__":
    sys.exit(main())
