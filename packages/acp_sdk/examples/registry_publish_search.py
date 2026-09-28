#!/usr/bin/env python3
"""registry_publish_search.py — publish to the directory, then resolve.

Starts a real local ``acp_api`` directory server in a background
thread, registers an agent handle, sets signed presence, and resolves
the handle back.

    python3 -m acp_sdk.examples.registry_publish_search --handle alice
"""
import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_sdk import AcpClient  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--home", default="/tmp/acp-sdk-alice")
    p.add_argument("--passphrase", default="sdk-demo-pass")
    p.add_argument("--handle", default="alice_demo")
    p.add_argument("--port", type=int, default=18080)
    args = p.parse_args(argv)

    from acp_api.server import run, graceful_shutdown

    db_path = os.path.join(tempfile.mkdtemp(prefix="acp-sdk-registry-"),
                           "registry.db")
    server, thread = run("127.0.0.1", args.port, db_path)
    try:
        with AcpClient(args.home, args.passphrase,
                       handle=args.handle) as client:
            api_url = "http://127.0.0.1:%d" % args.port
            reg = client.directory_register(api_url, args.handle)
            print("registered: %s" % reg)

            client.directory_set_presence("online")
            print("presence published: online")

            found = client.directory_search(args.handle)
            assert found["ipub"] == client.peer_id, \
                "resolved ipub does not match our peer id"
            assert found["handle"] == args.handle
            print("resolved '%s' -> ipub %s..."
                  % (found["handle"], found["ipub"][:12]))
            print("OK: registry publish + search works")
    finally:
        graceful_shutdown(server, thread)
    return 0


if __name__ == "__main__":
    sys.exit(main())
