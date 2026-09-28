#!/usr/bin/env python3
"""group_chat.py — fan-out chat with three agents.

Native group kinds (``acp_groups``) are an optional V2+ module and are
not installed in V1, so ``create_group`` raises a clear AcpError (shown
first, on purpose). The working demo is the honest V1 pattern: the
"group" is the local fan-out loop — one ``send_message`` per member —
which is exactly what a future groups module will optimize away.

    python3 -m acp_sdk.examples.group_chat --text "team standup"
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_proto import AcpError  # noqa: E402
from acp_sdk import AcpClient  # noqa: E402


def pair(initiator, responder):
    """Pair initiator -> responder. Returns the responder's peer id."""
    code_box = {}
    arrived = threading.Event()
    responder.on_pairing_request(
        lambda s: (code_box.setdefault("code", s.code),
                   s.accept(), arrived.set()))
    host, port = responder.server_address
    peer_id = initiator.pair_with(
        host, port,
        approve_callback=lambda: _wait_code(code_box, arrived))
    assert peer_id == responder.peer_id
    return peer_id


def _wait_code(code_box, arrived):
    assert arrived.wait(30), "responder never sent a pairing code"
    return code_box["code"]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--passphrase", default="sdk-demo-pass")
    p.add_argument("--text", default="team standup at 10")
    args = p.parse_args(argv)

    with AcpClient("/tmp/acp-sdk-alice", args.passphrase,
                   handle="alice") as alice, \
            AcpClient("/tmp/acp-sdk-bob", args.passphrase,
                      handle="bob") as bob, \
            AcpClient("/tmp/acp-sdk-carol", args.passphrase,
                      handle="carol") as carol:
        alice.start_server()
        bob.start_server()
        carol.start_server()

        # 1) show the honest failure of the optional native group API
        try:
            alice.create_group("team", [bob.peer_id, carol.peer_id])
        except AcpError as e:
            print("native create_group -> AcpError(%s): %s"
                  % (e.code, e.detail))
        else:
            raise SystemExit("unexpected: acp_groups is installed?!")

        # 2) V1 fan-out "group chat": pair with each member, send to each
        got = {bob.peer_id: threading.Event(),
               carol.peer_id: threading.Event()}

        def on_msg(sender, text, msg_id):
            bob.on_message(lambda s, t, m: got[bob.peer_id].set()
                       if s == alice.peer_id and t == args.text else None)
        carol.on_message(lambda s, t, m: got[carol.peer_id].set()
                         if s == alice.peer_id and t == args.text else None)

        members = [pair(alice, bob), pair(alice, carol)]
        print("alice paired with %d members" % len(members))
        for pid in members:
            alice.send_message(pid, args.text)
        deadline = time.time() + 30
        assert all(ev.wait(max(0, deadline - time.time()))
                   for ev in got.values()), "a member never got the message"
        print("bob and carol both received %r" % args.text)
        print("OK: group-style fan-out chat works")
    return 0


if __name__ == "__main__":
    sys.exit(main())
