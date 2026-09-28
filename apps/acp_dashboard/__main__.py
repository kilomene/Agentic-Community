#!/usr/bin/env python3
"""acp-dashboard: serve the ACP 1.0 web dashboard for a connector home.

Usage:
    python3 apps/acp_dashboard/__main__.py --home DIR [--port N]
        [--host 127.0.0.1] [--token TOKEN] [--lang en] [--passphrase ...]

Passphrase precedence: --passphrase > ACP_PASSPHRASE env > prompt.
The API token: --token, else a random one is generated and printed once.
Binds 127.0.0.1 by default. Stdlib only.
"""
import argparse
import getpass
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJ_ROOT, "packages"))

from acp_connector import Connector  # noqa: E402


def _load_server():
    spec = importlib.util.spec_from_file_location(
        "acp_dashboard_server", os.path.join(HERE, "server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    p = argparse.ArgumentParser(prog="acp-dashboard",
                                description="ACP 1.0 web dashboard")
    p.add_argument("--home", required=True, help="connector home directory")
    p.add_argument("--passphrase", default=None,
                   help="identity passphrase (else ACP_PASSPHRASE env, "
                        "else interactive prompt)")
    p.add_argument("--host", default="127.0.0.1", help="listen host")
    p.add_argument("--port", type=int, default=0, help="listen port")
    p.add_argument("--token", default=None,
                   help="API token (else a random one is generated)")
    p.add_argument("--lang", default="en", help="default UI locale")
    args = p.parse_args(argv)

    passphrase = args.passphrase or os.environ.get("ACP_PASSPHRASE")
    if not passphrase:
        passphrase = getpass.getpass("passphrase: ")

    home = os.path.abspath(args.home)
    if not os.path.exists(os.path.join(home, "connector.db")):
        print("ERROR NOT_FOUND: %s is not initialized "
              "(run: acp init --home %s --handle NAME first)" % (home, home))
        return 1

    server_mod = _load_server()
    conn = Connector(home, passphrase)
    dash = server_mod.Dashboard(conn, token=args.token, host=args.host,
                                port=args.port, lang=args.lang)
    port = dash.start()
    try:
        if args.token:
            print("dashboard token: (from --token)")
        else:
            print("dashboard token: %s" % dash.token)
        print("dashboard at http://%s:%d/  (lang=%s, handle=%s)"
              % (args.host, port, dash.default_lang, conn.handle))
        print("serving; Ctrl-C to stop.")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print()
    finally:
        dash.stop()
        conn.stop()
        print("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
