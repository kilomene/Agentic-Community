#!/usr/bin/env python3
"""acp-office: run the read-only fleet office dashboard.

Usage:
    python3 apps/acp_office/__main__.py [--host 127.0.0.1] [--port 18081]
        [--token TOKEN] [--group-id ID]

Source DB paths default to ~/.acp (override with ACP_OFFICE_* env vars;
see apps/acp_office/server.py). The API token: --token, else generated
and printed once. Binds 127.0.0.1 by default — public exposure goes
through the cloudflared tunnel + Cloudflare Access (docs/OFFICE.md).
Stdlib only.
"""
import argparse
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_server():
    spec = importlib.util.spec_from_file_location(
        "acp_office_server", os.path.join(HERE, "server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    p = argparse.ArgumentParser(prog="acp-office",
                                description="Fleet office dashboard")
    p.add_argument("--host", default="127.0.0.1", help="listen host")
    p.add_argument("--port", type=int, default=18081, help="listen port")
    p.add_argument("--token", default=None,
                   help="API token (else generated and printed once)")
    p.add_argument("--group-id", default=None,
                   help="fleet group id (default: from fleet.json)")
    args = p.parse_args(argv)

    server_mod = _load_server()
    office = server_mod.Office(token=args.token, host=args.host,
                               port=args.port, group_id=args.group_id)
    port = office.start()
    try:
        if args.token:
            print("office token: (from --token / ACP_OFFICE_TOKEN)")
        else:
            print("office token: %s" % office.token)
        print("office at http://%s:%d/ (group=%s)"
              % (args.host, port, office.group_id))
        print("serving; Ctrl-C to stop.")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print()
    finally:
        office.stop()
        print("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
