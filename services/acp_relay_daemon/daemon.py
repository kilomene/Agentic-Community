#!/usr/bin/env python3
"""acp-relay-daemon — keep this agent connected to the ACP relay.

Stdlib only. Run under a supervisor (systemd) or via the
``acp-relay-daemon`` control script (nohup + pid file).

Behavior:
  * loads the ACP identity from --home with the passphrase in
    --passphrase-file (0600)
  * connects to the wss:// relay and re-connects with backoff on drops
  * claims a 6-letter pairing code on every (re)connect (ttl 1h) and
    writes it to <state-dir>/pair-code.json so the owner can read it out
    for pairing:  {"code": "KX7Q2M", "claimed_at": ..., "expires_at": ...}
  * writes <state-dir>/relay-status.json on every state change:
    {"connected": bool, "url": ..., "since": ..., "peer_id": ...,
     "handle": ..., "code": ..., "code_expires_at": ...}
  * inbound envelopes are logged (kind/from); pairing requests are
    logged loudly — the owner confirms them with the `acp` CLI.
  * on SIGTERM/SIGINT the claimed code is released and the link closed.

The daemon never sends messages on its own and never auto-accepts
pairing: pairing is confirmed by the owner by protocol design.
"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time

LOG = logging.getLogger("acp-relay-daemon")

PAIR_CODE_TTL = 3600          # codes live 1h; refreshed before expiry
PAIR_CODE_REFRESH_AT = 600    # re-claim when <10 min of life remains
BACKOFFS = (5, 10, 20, 30, 60, 120, 300)  # reconnect backoff, seconds


def _repo_packages_on_path():
    """Make the acp_* packages importable from a repo checkout or an
    install prefix (lib/ next to this file's install location)."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "packages"),                       # not typical
        os.path.abspath(os.path.join(here, "..", "..", "packages")),
        os.path.join(os.path.dirname(here), "packages"),
    ]
    # install layout: <prefix>/lib/acp_relay_daemon/daemon.py ->
    #                 <prefix>/lib/{acp_proto,...}
    lib = os.path.dirname(here)
    candidates.append(lib)
    for c in candidates:
        if os.path.isdir(os.path.join(c, "acp_connector")):
            if c not in sys.path:
                sys.path.insert(0, c)
            return


def _load_connector(home, passphrase):
    _repo_packages_on_path()
    try:
        from acp_connector import Connector
    except ImportError:
        _repo_packages_on_path()
        from acp_connector import Connector  # noqa: F811
    return Connector(os.path.abspath(home), passphrase)


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


class Daemon:
    def __init__(self, args):
        self.args = args
        self.conn = None
        self.link = None
        self.code = None
        self.code_expires_at = 0
        self.connected_since = 0
        self._stop = threading.Event()
        self._code_lock = threading.Lock()

    # ------------------------------------------------------------ state

    def _status(self):
        now = int(time.time())
        with self._code_lock:
            code, exp = self.code, self.code_expires_at
        return {
            "connected": self.link is not None and not self.link.closed,
            "url": self.args.url,
            "since": self.connected_since or None,
            "peer_id": self.conn.peer_id if self.conn else None,
            "handle": self.conn.handle if self.conn else None,
            "code": code,
            "code_expires_at": exp or None,
            "now": now,
        }

    def _publish(self):
        st = self._status()
        try:
            _write_json(os.path.join(self.args.state_dir, "relay-status.json"),
                        st)
            if st["code"]:
                _write_json(
                    os.path.join(self.args.state_dir, "pair-code.json"),
                    {"code": st["code"],
                     "claimed_at": st["since"],
                     "expires_at": st["code_expires_at"]})
        except OSError as e:
            LOG.warning("state write failed: %s", e)

    # ---------------------------------------------------------- connect

    def _connect_once(self):
        """Connect and claim a pairing code. Raises on failure."""
        from acp_proto import AcpError
        # relay_connect opens the wss link AND spawns the Connector's own
        # reader thread — the daemon must not pump read_loop itself.
        link = self.conn.relay_connect(self.args.url)
        LOG.info("connected to relay %s as %s (%s)",
                 self.args.url, self.conn.handle,
                 self.conn.peer_id[:12] + "...")
        try:
            code = self.conn.relay_claim_code(ttl=PAIR_CODE_TTL)
        except AcpError as e:
            LOG.warning("pair-code claim failed (%s); continuing without one",
                        e)
            code = None
        with self._code_lock:
            self.code = code
            self.code_expires_at = int(time.time()) + PAIR_CODE_TTL if code else 0
        if code:
            LOG.info("pairing code claimed: %s (valid 1h, refreshed "
                     "automatically)", code)
        self.connected_since = int(time.time())
        self.link = link
        self._publish()
        return link

    def _register_callbacks(self):
        def _short(pid):
            return pid[:16] + "..." if len(pid) > 16 else pid

        def _on_msg(peer_pid, text):
            LOG.info("inbound message from %s: %.120s", _short(peer_pid),
                     text.replace("\n", " "))

        def _on_pair_req(peer_pid, session):
            LOG.warning("PAIRING REQUEST from %s (session %s) — confirm it "
                        "with the `acp` CLI (pair-requests / pair-accept); "
                        "the daemon never auto-accepts.",
                        _short(peer_pid), session)

        def _on_file(peer_pid, offer):
            LOG.info("inbound file offer from %s: %s", _short(peer_pid),
                     offer)
        try:
            self.conn.on_message(_on_msg)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.conn.on_pairing_request(_on_pair_req)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.conn.on_file_offer(_on_file)
        except Exception:  # noqa: BLE001
            pass

    def _serve_until_drop(self, link):
        """Block until the link drops (the Connector's reader thread owns
        the socket); refresh the pairing code in the background."""
        while not link.closed and not self._stop.is_set():
            self._refresh_code_if_needed()
            self._stop.wait(30)
        if link.closed:
            LOG.warning("relay link dropped")

    def _release_code(self):
        with self._code_lock:
            code, self.code = self.code, None
            self.code_expires_at = 0
        if code and self.link is not None and not self.link.closed:
            try:
                self.conn.relay_release_code(code)
                LOG.info("released pairing code %s", code)
            except Exception:  # noqa: BLE001 - best effort
                pass

    def _refresh_code_if_needed(self):
        """Re-claim the pairing code before it expires (relay-side TTL)."""
        with self._code_lock:
            code, exp = self.code, self.code_expires_at
        if not code:
            return
        if exp - time.time() > PAIR_CODE_REFRESH_AT:
            return
        if self.link is None or self.link.closed:
            return
        try:
            new_code = self.conn.relay_claim_code(ttl=PAIR_CODE_TTL)
        except Exception as e:  # noqa: BLE001
            LOG.warning("pair-code refresh failed: %s", e)
            return
        try:
            self.conn.relay_release_code(code)
        except Exception:  # noqa: BLE001
            pass
        with self._code_lock:
            self.code = new_code
            self.code_expires_at = int(time.time()) + PAIR_CODE_TTL
        LOG.info("pairing code refreshed: %s -> %s", code, new_code)
        self._publish()

    # -------------------------------------------------------------- run

    def run(self):
        with open(self.args.passphrase_file, "r", encoding="utf-8") as fh:
            passphrase = fh.read().strip()
        if not passphrase:
            raise SystemExit("passphrase file is empty: %s"
                             % self.args.passphrase_file)
        db = os.path.join(os.path.abspath(self.args.home), "connector.db")
        if not os.path.exists(db):
            raise SystemExit("home not initialized: %s (run `acp init` first)"
                             % self.args.home)
        self.conn = _load_connector(self.args.home, passphrase)
        LOG.info("identity loaded: %s (%s)", self.conn.handle,
                 self.conn.peer_id[:12] + "...")
        self._register_callbacks()

        backoff_idx = 0
        while not self._stop.is_set():
            try:
                link = self._connect_once()
            except Exception as e:  # noqa: BLE001
                wait = BACKOFFS[min(backoff_idx, len(BACKOFFS) - 1)]
                backoff_idx += 1
                LOG.warning("relay connect failed (%s); retry in %ds",
                            e, wait)
                self._stop.wait(wait)
                continue
            backoff_idx = 0
            # The Connector's reader thread owns the socket; supervise here.
            self._serve_until_drop(link)
            self._release_code()
            try:
                link.close()
            except Exception:  # noqa: BLE001
                pass
            self.link = None
            self.connected_since = 0
            self._publish()
            if not self._stop.is_set():
                LOG.warning("reconnecting to relay...")
        LOG.info("shutting down")
        try:
            self.conn.stop()
        except Exception:  # noqa: BLE001
            pass


def _handle_sigterm(daemon):
    def _h(signum, frame):  # noqa: ARG001
        daemon._stop.set()
    return _h


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--home", required=True, help="connector home directory")
    ap.add_argument("--passphrase-file", required=True,
                    help="file holding the identity passphrase (0600)")
    ap.add_argument("--url", required=True, help="relay wss:// URL")
    ap.add_argument("--state-dir", required=True,
                    help="directory for relay-status.json / pair-code.json")
    ap.add_argument("--pid-file", default=None, help="write PID here")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S")
    os.makedirs(args.state_dir, exist_ok=True)
    if args.pid_file:
        with open(args.pid_file, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))

    daemon = Daemon(args)
    signal.signal(signal.SIGTERM, _handle_sigterm(daemon))
    signal.signal(signal.SIGINT, _handle_sigterm(daemon))
    try:
        daemon.run()
    finally:
        if args.pid_file:
            # Only remove the pid file if it still points at us — a
            # replacement daemon may have written its own pid already.
            try:
                with open(args.pid_file, "r", encoding="utf-8") as fh:
                    if fh.read().strip() == str(os.getpid()):
                        os.unlink(args.pid_file)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
