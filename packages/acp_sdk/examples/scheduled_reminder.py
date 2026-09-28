#!/usr/bin/env python3
"""scheduled_reminder.py — send a reminder message on a schedule.

Pairs two local agents, then uses ``AcpClient.schedule_every`` to send
a reminder every N seconds. The receiver prints each reminder live.

    python3 -m acp_sdk.examples.scheduled_reminder --interval 5 --count 3
"""
import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_sdk import AcpClient  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--home-a", default="/tmp/acp-sdk-alice")
    p.add_argument("--home-b", default="/tmp/acp-sdk-bob")
    p.add_argument("--passphrase", default="sdk-demo-pass")
    p.add_argument("--interval", type=float, default=2,
                   help="seconds between reminders")
    p.add_argument("--count", type=int, default=3,
                   help="how many reminders to send")
    p.add_argument("--text", default="stand up and stretch")
    args = p.parse_args(argv)

    code_box = {}
    arrived = threading.Event()
    got = []
    done = threading.Event()

    with AcpClient(args.home_a, args.passphrase, handle="alice") as alice, \
            AcpClient(args.home_b, args.passphrase, handle="bob") as bob:
        alice.start_server()
        bob_host, bob_port = bob.start_server()
        bob.on_pairing_request(
            lambda s: (code_box.setdefault("code", s.code),
                       s.accept(), arrived.set()))

        def on_msg(sender, text, msg_id):
            got.append(text)
            print("reminder %d/%d: %s" % (len(got), args.count, text))
            if len(got) >= args.count:
                done.set()

        bob.on_message(on_msg)

        peer_id = alice.pair_with(
            bob_host, bob_port,
            approve_callback=lambda: code_box["code"]
            if arrived.wait(30) else None)

        sent = []

        def reminder():
            mid = alice.send_message(peer_id, args.text)
            sent.append(mid)

        job = alice.schedule_every(args.interval, reminder)
        assert done.wait(30 + args.interval * args.count), \
            "reminders never arrived"
        job.cancel()
        assert len(sent) >= args.count, "scheduler sent too few reminders"
        print("OK: %d scheduled reminders delivered" % len(got))
    return 0


if __name__ == "__main__":
    sys.exit(main())
