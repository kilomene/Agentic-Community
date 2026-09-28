#!/usr/bin/env python3
"""file_transfer.py — pair two local agents and send a file end to end.

The receiver auto-accepts files (accept_files(True)); the sender's
``send_file`` blocks until the file is reassembled, SHA-256-verified,
and ACKed.

    python3 -m acp_sdk.examples.file_transfer --payload "some bytes"
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_sdk import AcpClient  # noqa: E402
from acp_sdk.examples._util import pair, retry  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--home-a", default="/tmp/acp-sdk-alice")
    p.add_argument("--home-b", default="/tmp/acp-sdk-bob")
    p.add_argument("--passphrase", default="sdk-demo-pass")
    p.add_argument("--payload", default="sdk file transfer payload 12345")
    args = p.parse_args(argv)

    src = os.path.join(args.home_a, "demo-payload.txt")
    os.makedirs(args.home_a, exist_ok=True)
    with open(src, "w") as f:
        f.write(args.payload)
    expect = hashlib.sha256(args.payload.encode()).hexdigest()

    def scenario():
        with AcpClient(args.home_a, args.passphrase,
                       handle="alice") as alice, \
                AcpClient(args.home_b, args.passphrase,
                          handle="bob") as bob:
            alice.start_server()
            bob.start_server()
            bob.accept_files(True)

            peer_id = pair(alice, bob)
            fid = alice.send_file(peer_id, src)
            print("sent: %s (transfer %s...)" % (src, fid[:8]))

            received = os.path.join(bob.connector.incoming_dir,
                                    "demo-payload.txt")
            assert os.path.isfile(received), "file never arrived"
            with open(received, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            assert digest == expect, "hash mismatch: %s" % digest
            print("bob received %s, sha256 ok" % received)
            print("OK: file transfer works")

    # Retries ride through the pre-existing V1 b62 envelope flake (see
    # acp_sdk/README.md "Known issues"); each attempt uses fresh
    # clients and fresh random envelopes.
    retry(scenario, attempts=3, label="file_transfer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
