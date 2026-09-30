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
  * the code is PERMANENT for life (owner's order): on every (re)connect
    the daemon re-claims the code recorded in pair-code.json instead of
    minting a fresh random one, so the owner's published code never
    changes across restarts, updates, drops, or races — no matter what.
    A failed claim is retried with the SAME code on the next cycle; the
    daemon never falls back to a fresh random claim.
  * writes <state-dir>/relay-status.json on every state change:
    {"connected": bool, "url": ..., "since": ..., "peer_id": ...,
     "handle": ..., "code": ..., "code_expires_at": ...}
  * inbound envelopes are logged (kind/from); pairing requests are
    auto-accepted — the pair_challenge is sent immediately, exactly like
    the `acp` CLI — and logged loudly with the 6-char confirm code. The
    owner reads the code to the other side; typing it there is the trust
    step that completes pairing.
  * on SIGTERM/SIGINT the claimed code is released and the link closed.

The daemon never sends chat messages on its own. Pairing challenges are
auto-sent on request (same posture as the `acp` CLI's REPL): the 6-char
confirm code, shown only on this side, remains the authentication step —
auto-accepting the challenge cannot complete pairing without it.
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
CODE_REFRESH_AHEAD = 600    # re-claim the same code when <10 min of life remain
PING_INTERVAL = 30          # WebSocket keepalive: idle middleboxes kill quiet links
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
        self.autopilot = None          # workstream D: opt-in auto-replies
        self._autopilot_groups = None  # lazily-created GroupChat for it
        self._fleet_groups = None      # lazily-created GroupChat for fleet

    # ------------------------------------------------------------ state

    def _active_pairings(self):
        """Number of pairing sessions currently mid-handshake.

        A session counts as active while it is neither done nor failed
        and has not expired. The auto-updater waits for this to reach
        zero before restarting the daemon, so an update never kills a
        live pairing.
        """
        try:
            mgr = self.conn.pairing
        except AttributeError:
            return 0
        n = 0
        for s in list(getattr(mgr, "_sessions", {}).values()):
            try:
                if s.state not in ("done", "failed") and not s.expired:
                    n += 1
            except Exception:  # noqa: BLE001
                continue
        return n

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
            "pairing_active": self._active_pairings(),
            "fleet": self._fleet_status(),
            "now": now,
        }

    def _fleet_status(self):
        try:
            cfg = self._fleet_cfg()
            members = None
            if cfg.get("group_id") and self.conn is not None:
                g = self._fleet_group_chat().get_group(cfg["group_id"])
                members = len(g["members"]) if g else None
            return {"auto_join": bool(cfg.get("auto_join")),
                    "group_id": cfg.get("group_id"),
                    "group_name": cfg.get("group_name"),
                    "members": members}
        except Exception:  # noqa: BLE001
            return {"auto_join": False, "group_id": None,
                    "group_name": None, "members": None}

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

    def _preferred_code(self):
        """The permanent pairing code, read from pair-code.json.

        The relay lets a client re-claim a specific code it held before;
        the daemon records every claimed code in pair-code.json, so the
        next boot asks for the same one back. Returns None when no code
        was ever recorded (first boot) or the record is unreadable.
        """
        try:
            with open(os.path.join(self.args.state_dir, "pair-code.json"),
                      encoding="utf-8") as fh:
                code = (json.load(fh) or {}).get("code")
        except (OSError, ValueError):
            return None
        if isinstance(code, str) and len(code) == 6 and code.isalnum():
            return code.upper()
        return None

    def _claim_code(self, preferred):
        """Claim a pairing code.

        Owner's order: ONE permanent pairing code per agent for life.
        When `preferred` is set, this claims THAT code and only that
        code — a failed claim is retried on the next refresh cycle, it
        is NEVER replaced by minting a fresh code. A fresh code is
        minted only when `preferred` is None (first boot: the code's
        birth, after which it is recorded as permanent).
        Returns the claimed code or None.
        """
        from acp_proto import AcpError
        if preferred:
            try:
                code = self.conn.relay_claim_code(code=preferred,
                                                 ttl=PAIR_CODE_TTL)
                LOG.info("pairing code re-claimed (permanent): %s", code)
                return code
            except AcpError as e:  # noqa: BLE001
                # Never rotate: keep the permanent code; the refresh
                # cycle retries this same claim (the usual cause is the
                # relay-side reconnect race, which clears on its own).
                LOG.warning("permanent pairing code %s claim failed (%s); "
                            "keeping it and retrying (never rotating)",
                            preferred, e)
                return None
        try:
            return self.conn.relay_claim_code(ttl=PAIR_CODE_TTL)
        except AcpError as e:  # noqa: BLE001
            LOG.warning("pair-code claim failed (%s); continuing without one",
                        e)
            return None

    def _connect_once(self):
        """Connect and claim a pairing code. Raises on failure."""
        # relay_connect opens the wss link AND spawns the Connector's own
        # reader thread — the daemon must not pump read_loop itself.
        link = self.conn.relay_connect(self.args.url)
        LOG.info("connected to relay %s as %s (%s)",
                 self.args.url, self.conn.handle,
                 self.conn.peer_id[:12] + "...")
        try:
            code = self._claim_code(self._preferred_code())
        except Exception as e:  # noqa: BLE001 - never break the connect
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

        def _on_msg(peer_pid, text, msg_id):
            LOG.info("inbound message from %s (id %s): %.120s",
                     _short(peer_pid), msg_id[:12],
                     text.replace("\n", " "))

        def _on_pair_req(session):
            # API is cb(session): session.peer_pid / peer_handle, and
            # session.code is the on-screen confirm code for the user.
            # Auto-send the challenge immediately (same as the `acp`
            # CLI): the human trust step is the 6-char confirm code,
            # typed on the OTHER side out-of-band. Waiting for a manual
            # accept here would deadlock headless pairing — the
            # initiator would sit in await_challenge forever with no
            # way to proceed, and the confirm code would be useless.
            try:
                session.accept()
            except Exception as e:  # noqa: BLE001 - AcpError on bad state
                LOG.error("could not auto-accept pairing request %s: %s",
                          session.session_id, e)
                return
            LOG.warning(
                "PAIRING REQUEST from %s (%s) -- challenge sent, confirm "
                "code: %s (session %s). Read the code to the user NOW; "
                "they type it on the other side to complete pairing.",
                _short(session.peer_pid), session.peer_handle or "?",
                session.code, session.session_id)
            self._record_pairing_request(session)

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
            # Fleet auto-join: newly paired peers land in the fleet group.
            self.conn.pairing.on_pairing_complete(self._fleet_auto_add)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.conn.on_file_offer(_on_file)
        except Exception:  # noqa: BLE001
            pass
        # Workstream D: autopilot — owner-opt-in autonomous agent-to-agent
        # replies (<home>/autopilot.json; absent file = everything off).
        # Wrapped so a broken autopilot module can NEVER break the
        # daemon's core loop; default behavior is unchanged when off.
        try:
            from autopilot import Autopilot
            self.autopilot = Autopilot(self.args.home, self.conn)
            self.conn.on_message(self.autopilot.handle_direct)
            try:
                from acp_connector.groups import GroupChat
                self._autopilot_groups = GroupChat(self.conn)
                self.autopilot.groups = self._autopilot_groups
                self._autopilot_groups.on_group_message(
                    self.autopilot.handle_group)
            except Exception as e:  # noqa: BLE001
                LOG.warning("autopilot: group replies unavailable: %s", e)
        except Exception as e:  # noqa: BLE001
            LOG.warning("autopilot disabled: %s", e)
            self.autopilot = None

    def _record_pairing_request(self, session):
        """Persist a pending inbound request (incl. confirm code) so the
        owner can read it even if the daemon restarts. Entries whose
        sessions are done/failed/expired (e.g. superseded by a newer
        request from the same peer) are pruned so a stale code is never
        read out."""
        try:
            path = os.path.join(self.args.state_dir, "pairing-requests.json")
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    pending = json.load(fh)
            except (OSError, ValueError):
                pending = []
            live = []
            for r in pending:
                if r.get("session_id") == session.session_id:
                    continue
                s = (self.conn.pairing.get_session(r.get("session_id"))
                     if self.conn is not None else None)
                if s is None or s.state in ("done", "failed") or s.expired:
                    continue
                live.append(r)
            pending = live
            pending.append({
                "session_id": session.session_id,
                "peer_pid": session.peer_pid,
                "peer_handle": session.peer_handle,
                "code": session.code,
                "received_at": int(time.time()),
            })
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(pending, fh, indent=2)
            os.replace(tmp, path)
        except Exception as e:  # noqa: BLE001 - never break pairing on this
            LOG.warning("could not record pairing request: %s", e)

    # ------------------------------------------------------ fleet auto-join
    # When enabled (state_dir/fleet.json -> {"auto_join": true}), every
    # peer that completes pairing with this daemon is automatically added
    # to the fleet group room, so a newly paired agent joins the fleet
    # with no manual step. Peers paired before this was enabled are NOT
    # grandfathered in.

    def _fleet_cfg_path(self):
        return os.path.join(self.args.state_dir, "fleet.json")

    def _fleet_cfg(self):
        cfg = {"auto_join": False, "group_name": "Phoenix Fleet",
               "group_id": None}
        try:
            with open(self._fleet_cfg_path(), "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                cfg.update({k: loaded[k] for k in cfg if k in loaded})
        except (OSError, ValueError):
            pass
        return cfg

    def _fleet_save(self, cfg):
        _write_json(self._fleet_cfg_path(), cfg)

    def _fleet_group_chat(self):
        if self._fleet_groups is None:
            from acp_connector.groups import GroupChat
            self._fleet_groups = GroupChat(self.conn)
        return self._fleet_groups

    def _fleet_ensure(self):
        """Return the fleet group_id, creating the group on first use."""
        cfg = self._fleet_cfg()
        groups = self._fleet_group_chat()
        gid = cfg.get("group_id")
        if gid:
            g = groups.get_group(gid)
            if g is not None and g.get("admin_id") == self.conn.peer_id:
                return gid
            LOG.warning("fleet group %s missing or not ours; recreating",
                        (gid or "")[:12])
        gid = groups.create_group(cfg.get("group_name") or "Phoenix Fleet",
                                  [])
        cfg["group_id"] = gid
        self._fleet_save(cfg)
        LOG.warning("fleet group created: %s (%s)", cfg.get("group_name"),
                    gid[:12])
        return gid

    def _fleet_auto_add(self, peer_pid, peer_handle, role):
        """PairingManager.on_pairing_complete callback: pull the newly
        paired peer into the fleet group when auto-join is enabled."""
        try:
            if not self._fleet_cfg().get("auto_join"):
                return
            gid = self._fleet_ensure()
            groups = self._fleet_group_chat()
            g = groups.get_group(gid) or {}
            if peer_pid in (g.get("members") or []):
                return
            groups.add_member(gid, peer_pid)
            LOG.warning("fleet auto-join: %s (%s) added to fleet group",
                        peer_handle or "?", peer_pid[:12])
        except Exception as e:  # noqa: BLE001 - never break pairing on this
            LOG.warning("fleet auto-join failed for %s: %s",
                        (peer_pid or "")[:12], e)

    def _outbox_dir(self):
        return os.path.join(self.args.state_dir, "outbox")

    def _drain_outbox(self):
        """Send queued outbound messages through THIS daemon's live relay
        link. Files are JSON: {"kind": "group_msg", "group_id": ..., "text":
        ...}. On success the file is removed; on failure it is retried next
        cycle up to 5 attempts, then moved to outbox/failed/.

        Why this exists: the relay allows exactly ONE socket per peer id —
        a duplicate registration closes the older socket. Any second process
        (e.g. the `acp` CLI) that connects with our identity steals the
        relay socket from the daemon, or gets its own socket killed by the
        daemon's reconnect, so sends from the CLI fail with "no open
        connection to peer" while reporting msg_sent ok. All outbound
        traffic must go through the daemon's single live connection. """
        d = self._outbox_dir()
        try:
            names = sorted(os.listdir(d))
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(d, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    req = json.load(fh)
            except (OSError, ValueError) as e:
                LOG.warning("outbox: dropping unreadable %s (%s)", name, e)
                self._outbox_fail(path, name)
                continue
            try:
                kind = req.get("kind")
                if kind == "group_msg":
                    self._fleet_group_chat().send_group_message(
                        req["group_id"], req["text"])
                else:
                    raise ValueError("unknown outbox kind %r" % (kind,))
            except Exception as e:  # noqa: BLE001 - retry next cycle
                attempts = int(req.get("attempts", 0)) + 1
                LOG.warning("outbox: send %s failed (attempt %d): %s",
                            name, attempts, e)
                if attempts >= 5:
                    self._outbox_fail(path, name)
                else:
                    req["attempts"] = attempts
                    try:
                        with open(path, "w", encoding="utf-8") as fh:
                            json.dump(req, fh)
                    except OSError:
                        pass
                continue
            try:
                os.remove(path)
            except OSError:
                pass
            LOG.info("outbox: sent %s", name)

    def _outbox_fail(self, path, name):
        failed = os.path.join(self._outbox_dir(), "failed")
        try:
            os.makedirs(failed, exist_ok=True)
            os.replace(path, os.path.join(failed, name))
        except OSError:
            pass

    def _serve_until_drop(self, link):
        """Block until the link drops (the Connector's reader thread owns
        the socket); refresh the pairing code in the background and send
        a WebSocket ping every cycle so idle middleboxes (Cloudflare
        edge, NAT, proxies) don't silently kill a quiet connection."""
        from acp_proto import AcpError  # local import: matches module style
        while not link.closed and not self._stop.is_set():
            self._refresh_code_if_needed()
            self._drain_outbox()
            try:
                link.send_ping()
            except AcpError:
                break  # send marks the link closed; reconnect takes over
            self._stop.wait(PING_INTERVAL)
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
        """Keep the permanent pairing code claimed on the relay.

        Re-claims the SAME code before its relay-side TTL expires. If the
        daemon currently holds no live claim (e.g. the connect-time claim
        failed), it keeps trying the recorded permanent code every cycle —
        never minting a fresh one. The owner's published code never
        changes, no matter what.
        """
        with self._code_lock:
            code, exp = self.code, self.code_expires_at
        if not code:
            code = self._preferred_code()
            if not code:
                return  # first boot with no recorded code yet
            exp = 0  # force an immediate (re-)claim attempt
        if exp - time.time() > PAIR_CODE_REFRESH_AT:
            return
        if self.link is None or self.link.closed:
            return
        new_code = self._claim_code(code)
        if not new_code:
            return
        with self._code_lock:
            self.code = new_code
            self.code_expires_at = int(time.time()) + PAIR_CODE_TTL
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
        if getattr(self.args, "fleet_auto_join", False):
            cfg = self._fleet_cfg()
            if not cfg.get("auto_join"):
                cfg["auto_join"] = True
                self._fleet_save(cfg)
            LOG.warning("fleet auto-join ENABLED")

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
    ap.add_argument("--fleet-auto-join", action="store_true",
                    help="newly paired peers are automatically added to the"
                    " fleet group room (persisted in state_dir/fleet.json)")
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
