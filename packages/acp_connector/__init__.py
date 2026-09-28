"""acp_connector: the core P2P agent runtime for ACP 1.0.

The Connector wires together identity, transport, pairing, messaging,
file transfer, permissions, family, projects, policy, presence,
revocation, audit, and the local bridge.

One receiver model: every accepted/dialed TCP connection gets a reader
thread; frames flow into _on_frame, which verifies (signature, replay
cache, freshness), routes by kind, E2E-decrypts where required, runs
permission checks, and dispatches to module handlers. Any AcpError on
the inbound path produces a signed plaintext ERROR envelope back to
the sender plus an audit event (except in reply to ERROR itself).
"""
import collections
import os
import threading
import time

from acp_proto import (
    AcpError, ALL_KINDS, E2E_KINDS, ERROR,
    PAIR_REQUEST, PAIR_CHALLENGE, PAIR_CONFIRM, PAIR_WELCOME,
    MSG, MSG_ACK,
    FILE_OFFER, FILE_ACCEPT, FILE_REJECT, FILE_CHUNK, FILE_DONE, FILE_ACK,
    PRESENCE, KEY_ROTATE, REVOKE_NOTICE,
    b62encode, make_envelope, make_e2e_envelope,
    verify_envelope, open_e2e_envelope, validate_payload,
)

from .store import Store
from .identity import Identity
from .audit import Audit
from .transport import TcpTransport
from .relay_link import RelayLink
from .policy import PolicyEngine
from .permissions import Permissions, PERMS
from .pairing import PairingManager
from .messaging import Messaging
from .files import FileTransfer
from .family import Family
from .projects import Projects
from .presence import Presence
from .revoke import Revoker
from .bridge import Bridge
from .scheduler import Scheduler

__all__ = ["Connector", "Bridge", "PERMS", "AcpError"]

_REPLAY_CACHE_SIZE = 10000
_SWEEP_INTERVAL = 30


class Connector:
    def __init__(self, home, passphrase, handle="default"):
        self.home = os.path.abspath(home)
        os.makedirs(self.home, exist_ok=True)
        self.incoming_dir = os.path.join(self.home, "incoming")
        os.makedirs(self.incoming_dir, exist_ok=True)
        self._passphrase = passphrase

        self.store = Store(os.path.join(self.home, "connector.db"))
        self.audit = Audit(self.home, self.store)
        self.identity = Identity(self.home, passphrase, handle)
        self.policy = PolicyEngine(self.store, self.audit)
        self.permissions = Permissions(self.store, self.audit)
        self.pairing = PairingManager(self)
        self.messaging = Messaging(self)
        self.files = FileTransfer(self)
        self.family = Family(self.store, self.permissions, self.audit,
                             self.peer_id)
        self.projects = Projects(self.store, self.permissions, self.audit,
                                 self.peer_id)
        self.presence = Presence(self)
        self.revoker = Revoker(self)
        self.bridge = Bridge(owner=self)
        self.transport = TcpTransport()
        # Scheduler: cron-like persisted tasks (actions are connector
        # operations or app-registered callbacks — never shell).
        self.scheduler = Scheduler(self)
        # Analytics: privacy-respecting local counters (opt-in reporting).
        from .analytics import Analytics
        self.analytics = Analytics(self)

        self._conns = {}  # pid -> Conn
        self._conns_lock = threading.Lock()
        self._relay_link = None  # RelayLink to a wss:// relay (shared)
        self._relay_queued = []  # [(to_pid, mailbox_id, ts)] FIFO notices
        self._relay_queued_lock = threading.Lock()
        self._ext_handlers = {}  # V2+ kind -> fn(conn, env, payload)
        self._replay = collections.OrderedDict()
        self._replay_lock = threading.Lock()
        self._prev_x_priv = None  # pre-rotation X25519 key (decrypt fallback)
        self._server_host = None
        self._server_port = None

        self._stopping = False
        self._sweeper = threading.Thread(target=self._sweep_loop,
                                         daemon=True, name="acp-sweeper")
        self._sweeper.start()
        # Re-arm persisted scheduled tasks (custom actions must be
        # re-registered by the app after construction).
        self.scheduler.start()
        self.audit.log("connector.started", result="ok",
                       details={"handle": self.handle,
                                "peer_id": self.peer_id})

    # ------------------------------------------------------------ properties
    @property
    def peer_id(self):
        return self.identity.peer_id

    @property
    def handle(self):
        return self.identity.handle

    # ------------------------------------------------------------- transport
    def start_server(self, host, port):
        """Start the TCP server. Returns the actual bound port."""
        actual = self.transport.start_server(host, port, self._on_accept)
        self._server_host, self._server_port = host, actual
        self.audit.log("server.started", result="ok",
                       details={"host": host, "port": actual})
        return actual

    def relay_connect(self, url):
        """Connect to a WebSocket ACP relay (e.g. wss://host/path).

        Holds one persistent outbound link; the relay routes envelopes
        by ``to`` pid, so agents behind NAT can reach each other. The
        link is shared: _get_conn falls back to it when no direct
        connection exists. Returns the RelayLink. Works with or without
        the TCP server running.
        """
        link = RelayLink(self)
        link.connect(url)
        self._relay_link = link
        self._spawn_reader(link)
        self.audit.log("relay.connected", result="ok",
                       details={"url": url})
        return link

    def _on_relay_queued(self, to_pid, mailbox_id):
        """The relay stored an envelope for to_pid in its mailbox.
        Called from the RelayLink reader thread; never raises."""
        try:
            with self._relay_queued_lock:
                self._relay_queued.append(
                    (to_pid, mailbox_id, int(time.time())))
        except Exception:
            pass

    def _pop_relay_queued(self, to_pid):
        """Pop the oldest queued notice for to_pid, or None."""
        with self._relay_queued_lock:
            for i, (pid, mbx_id, _ts) in enumerate(self._relay_queued):
                if pid == to_pid:
                    del self._relay_queued[i]
                    return mbx_id
        return None

    def stop(self):
        self._stopping = True
        self.audit.log("connector.stopped", result="ok", details={})
        try:
            self.scheduler.stop()
        except Exception:
            pass
        try:
            self.transport.stop()
        except Exception:
            pass
        link = self._relay_link
        self._relay_link = None
        if link is not None:
            try:
                link.close()
            except Exception:
                pass
        with self._conns_lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for c in conns:
            try:
                c.close()
            except Exception:
                pass
        if self._sweeper.is_alive():
            self._sweeper.join(timeout=5)
        try:
            self.store.close()
        except Exception:
            pass

    def _on_accept(self, conn):
        self._spawn_reader(conn)

    def _spawn_reader(self, conn):
        t = threading.Thread(target=self._reader_main, args=(conn,),
                             daemon=True, name="acp-reader")
        t.start()

    def _reader_main(self, conn):
        try:
            conn.read_loop(lambda env: self._on_frame(conn, env),
                           self._on_conn_error)
        finally:
            self._conn_closed(conn)

    def _on_conn_error(self, conn, err):
        self.audit.log("connection.error", result="failed",
                       details={"error": err.code, "detail": err.detail})

    def _conn_closed(self, conn):
        with self._conns_lock:
            for pid, c in list(self._conns.items()):
                if c is conn:
                    del self._conns[pid]
                    try:
                        self.store.set_connection(pid, "direct", None,
                                                  "closed")
                    except Exception:
                        pass

    def _bind_conn(self, pid, conn):
        with self._conns_lock:
            old = self._conns.get(pid)
            self._conns[pid] = conn
        # Never close the shared relay link here: other pids still route
        # through it. Rebinding one pid to a direct conn just replaces
        # that pid's entry.
        if old is not None and old is not conn \
                and old is not self._relay_link:
            try:
                old.close()
            except Exception:
                pass
        addr = None
        if conn.peer_addr:
            addr = f"{conn.peer_addr[0]}:{conn.peer_addr[1]}"
        self.store.set_connection(pid, "direct", addr, "open")

    def _drop_conn(self, pid):
        with self._conns_lock:
            conn = self._conns.pop(pid, None)
        # The relay link is shared across pids: dropping one pid must
        # not close it for everyone else.
        if conn is not None and conn is not self._relay_link:
            try:
                conn.close()
            except Exception:
                pass
        try:
            self.store.del_connection(pid)
        except Exception:
            pass

    def _get_conn(self, pid):
        with self._conns_lock:
            conn = self._conns.get(pid)
            if conn is not None and not conn.closed:
                return conn
            self._conns.pop(pid, None)
        info = self.store.get_connection(pid)
        if info and info["address"]:
            try:
                host, port_s = info["address"].rsplit(":", 1)
                conn = self.transport.connect(host, int(port_s))
            except (AcpError, ValueError, IndexError):
                conn = None
            if conn is not None:
                self._bind_conn(pid, conn)
                self._spawn_reader(conn)
                return conn
        # Relay fallback: one shared link routes by ``to`` pid, so no
        # per-pid binding is needed (and must NOT be created — the link
        # is shared). A closed link is skipped via its .closed flag.
        link = self._relay_link
        if link is not None and not link.closed:
            return link
        raise AcpError("INTERNAL", f"no open connection to peer"
                                   f" {pid[:16] if isinstance(pid, str) else pid}")

    # ------------------------------------------------------- send primitives
    def _send_plain(self, kind, to_pid, payload):
        env = make_envelope(kind, self.peer_id, to_pid, payload,
                            self.identity.ed_priv)
        self._get_conn(to_pid).send_env(env)

    def _send_e2e(self, kind, to_pid, payload):
        peer = self._require_peer(to_pid)
        env = make_e2e_envelope(
            kind, self.peer_id, to_pid, payload, self.identity.ed_priv,
            self.identity.x_priv, self.identity.x_pub,
            bytes.fromhex(peer["x_pub"]))
        self._get_conn(to_pid).send_env(env)

    def _send_e2e_untrusted(self, kind, to_pid, peer_x_pub, payload):
        """E2E send to a not-yet-trusted peer (pairing handshake).

        Skips the trust-store lookup; the caller supplies the peer's
        X25519 public key learned during the handshake.
        """
        env = make_e2e_envelope(
            kind, self.peer_id, to_pid, payload, self.identity.ed_priv,
            self.identity.x_priv, self.identity.x_pub, peer_x_pub)
        self._get_conn(to_pid).send_env(env)

    def _require_peer(self, pid):
        peer = self.store.get_peer(pid)
        if peer is None:
            raise AcpError("NOT_FOUND",
                           f"unknown peer {pid[:16] if isinstance(pid, str) else pid}")
        if peer["revoked"]:
            raise AcpError("POLICY_DENIED", "peer is revoked")
        if not peer["x_pub"]:
            raise AcpError("INTERNAL", "peer has no E2E key")
        return peer

    def _store_peer(self, pid, handle, ipub_hex, x_pub_hex):
        self.store.add_peer(pid, handle or "", ipub_hex, x_pub_hex)
        self.permissions.default_pairing_grants(pid)
        self.store.set_presence(pid, "unknown", int(time.time()))

    # -------------------------------------------------------- receive path
    def _get_pubkey(self, pid):
        peer = self.store.get_peer(pid)
        if peer is not None and not peer["revoked"] and peer["ed_pub"]:
            return bytes.fromhex(peer["ed_pub"])
        sess = self.pairing.find_by_peer(pid)
        if sess is not None and sess.peer_ipub:
            return bytes.fromhex(sess.peer_ipub)
        return None

    def _verify_bootstrap(self, env):
        """Verify pair_request/pair_challenge: the sender is not trusted
        yet, so the Ed25519 key comes from the payload's ``ipub`` and
        ``from`` must equal b62encode(ipub)."""
        payload = env.get("payload")
        if not isinstance(payload, dict):
            raise AcpError("BAD_ENVELOPE",
                           "bootstrap envelope needs a payload")
        validate_payload(env.get("kind"), payload)
        try:
            vkey = bytes.fromhex(payload.get("ipub") or "")
        except (ValueError, TypeError, AttributeError):
            raise AcpError("BAD_ENVELOPE", "ipub is not hex")
        if len(vkey) != 32:
            raise AcpError("BAD_ENVELOPE", "ipub wrong length")
        claimed = env.get("from")
        if b62encode(vkey) != claimed:
            raise AcpError("PAIRING_FAILED",
                           "sender id does not match payload ipub")
        verify_envelope(env, lambda pid: vkey if pid == claimed else None)

    def _check_replay(self, env):
        key = (env.get("from"), env.get("nonce"))
        with self._replay_lock:
            if key in self._replay:
                raise AcpError("REPLAY", "nonce already seen")
            self._replay[key] = True
            while len(self._replay) > _REPLAY_CACHE_SIZE:
                self._replay.popitem(last=False)

    def _open_e2e(self, env):
        try:
            return open_e2e_envelope(env, self._get_pubkey,
                                     self.identity.x_priv)
        except AcpError as e:
            if e.code == "DECRYPT_FAIL" and self._prev_x_priv is not None:
                return open_e2e_envelope(env, self._get_pubkey,
                                         self._prev_x_priv)
            raise

    def _on_frame(self, conn, env):
        kind = None
        try:
            if not isinstance(env, dict):
                raise AcpError("BAD_ENVELOPE", "envelope is not a dict")
            kind = env.get("kind")
            if kind not in ALL_KINDS:
                raise AcpError("UNKNOWN_KIND", str(kind))
            if kind in (PAIR_REQUEST, PAIR_CHALLENGE):
                self._verify_bootstrap(env)
            else:
                verify_envelope(env, self._get_pubkey)
            self._check_replay(env)
            # Rate-limit on the *verified* sender id. Checking before
            # signature verification would let an attacker burn another
            # identity's rate bucket with a spoofed ``from`` field.
            self.policy.check_rate(str(env.get("from") or "anon"))
            if kind in E2E_KINDS:
                payload = self._open_e2e(env)
                self._dispatch_e2e(conn, env, payload)
            elif kind == PAIR_REQUEST:
                self._bind_conn(env["from"], conn)
                self.pairing.handle_pair_request(conn, env)
            elif kind == PAIR_CHALLENGE:
                self.pairing.handle_challenge(conn, env)
            elif kind == ERROR:
                self._on_error_envelope(env)
            elif kind in (PRESENCE, KEY_ROTATE, REVOKE_NOTICE) or (
                    kind not in E2E_KINDS and kind in self._ext_handlers):
                # Signed plaintext kinds (PROTOCOL.md section 7), plus
                # V2+ extension plaintext kinds with a registered
                # handler: the signature was verified above; validate
                # the payload schema explicitly since verify_envelope
                # does not.
                validate_payload(kind, env.get("payload") or {})
                self._dispatch_plain(conn, env, env["payload"])
            else:
                raise AcpError("UNKNOWN_KIND", kind)
        except AcpError as e:
            actor = env.get("from") if isinstance(env, dict) else None
            self.audit.log("envelope.rejected", actor=actor or "unknown",
                           target=kind, result="denied",
                           details={"code": e.code, "detail": e.detail})
            if kind != ERROR and isinstance(env, dict):
                self._send_error_response(env, e, conn)
        except Exception as e:  # never let a bad frame kill the reader
            self.audit.log("envelope.exception", actor="unknown",
                           result="failed", details={"error": str(e)})

    def _dispatch_e2e(self, conn, env, payload):
        kind = env["kind"]
        if kind == PAIR_CONFIRM:
            self.pairing.handle_confirm(conn, env, payload)
        elif kind == PAIR_WELCOME:
            self.pairing.handle_welcome(conn, env, payload)
        elif kind == MSG:
            self.messaging.handle_msg(env, payload)
        elif kind == MSG_ACK:
            self.messaging.handle_ack(env, payload)
        elif kind == FILE_OFFER:
            self.files.handle_offer(env, payload)
        elif kind == FILE_ACCEPT:
            self.files.handle_accept(env, payload)
        elif kind == FILE_REJECT:
            self.files.handle_reject(env, payload)
        elif kind == FILE_CHUNK:
            self.files.handle_chunk(env, payload)
        elif kind == FILE_DONE:
            self.files.handle_done(env, payload)
        elif kind == FILE_ACK:
            self.files.handle_ack(env, payload)
        else:
            handler = self._ext_handlers.get(kind)
            if handler is None:
                raise AcpError("UNKNOWN_KIND", kind)
            handler(conn, env, payload)

    def _dispatch_plain(self, conn, env, payload):
        kind = env["kind"]
        if kind == PRESENCE:
            self.presence.handle_presence(env, payload)
        elif kind == KEY_ROTATE:
            self.presence.handle_key_rotate(env, payload)
        elif kind == REVOKE_NOTICE:
            self.revoker.handle_revoke_notice(env, payload)
        else:
            handler = self._ext_handlers.get(kind)
            if handler is None:
                raise AcpError("UNKNOWN_KIND", kind)
            handler(conn, env, payload)

    def _on_error_envelope(self, env):
        payload = env.get("payload") or {}
        self.audit.log("error.received", actor=env.get("from"),
                       result="ok",
                       details={"code": payload.get("code"),
                                "detail": payload.get("detail")})

    def _send_error_response(self, env, err, conn):
        try:
            to = env.get("from")
            if not to or not isinstance(to, str) or to == "*":
                return
            payload = {"code": err.code, "detail": err.detail or ""}
            envelope = make_envelope(ERROR, self.peer_id, to, payload,
                                     self.identity.ed_priv)
            conn.send_env(envelope)
        except Exception:
            pass

    def register_kind_handler(self, kind, fn):
        """Register a V2+ extension handler for a protocol kind.

        fn(conn, env, payload) is called for E2E kinds (payload already
        decrypted) after signature/replay checks. Use with
        acp_proto.register_kind().
        """
        self._ext_handlers[kind] = fn

    # ---------------------------------------------------------------- pairing
    def pair_initiate(self, host, port):
        return self.pairing.pair_initiate(host, port)

    def pair_initiate_relay(self, peer_pid):
        """Start pairing with a peer reachable via the relay (no dial)."""
        return self.pairing.pair_initiate_relay(peer_pid)

    def on_pairing_request(self, cb):
        self.pairing.on_pairing_request(cb)

    # --------------------------------------------------------------- messaging
    def send_message(self, peer_pid, text):
        return self.messaging.send_message(peer_pid, text)

    def on_message(self, cb):
        self.messaging.on_message(cb)

    # ------------------------------------------------------------------- files
    def send_file(self, peer_pid, path):
        return self.files.send_file(peer_pid, path)

    def on_file_offer(self, cb):
        self.files.on_file_offer(cb)

    # ------------------------------------------------------------------ family
    def family_add(self, name, relation="", notes="", visible_to=None):
        return self.family.add(name, relation, notes, visible_to)

    def family_list(self, for_peer=None):
        return self.family.list(for_peer=for_peer)

    def family_update(self, fam_id, for_peer=None, **fields):
        return self.family.update(fam_id, for_peer=for_peer, **fields)

    def family_delete(self, fam_id, for_peer=None):
        return self.family.delete(fam_id, for_peer=for_peer)

    # ---------------------------------------------------------------- projects
    def project_create(self, title, notes=""):
        return self.projects.create(title, notes)

    def task_add(self, project_id, title, assignee_pid=None, notes="",
                 for_peer=None):
        return self.projects.add_task(project_id, title, assignee_pid,
                                      notes, for_peer=for_peer)

    def task_update(self, task_id, status=None, notes=None, for_peer=None):
        return self.projects.update_task(task_id, status, notes,
                                          for_peer=for_peer)

    def project_get(self, project_id, for_peer=None):
        return self.projects.get(project_id, for_peer=for_peer)

    # -------------------------------------------------------------- permissions
    def grant_permission(self, agent_id, scope, **kw):
        return self.permissions.grant(agent_id, scope, **kw)

    def revoke_permission(self, agent_id, scope):
        return self.permissions.revoke(agent_id, scope)

    def check_permission(self, agent_id, scope):
        return self.permissions.check(agent_id, scope)

    def list_permissions(self, agent_id):
        return self.permissions.list(agent_id)

    # ------------------------------------------------------------------ policy
    def set_rate_limit(self, per_min):
        self.policy.set_rate_limit(per_min)

    def set_file_size_cap(self, max_bytes):
        self.policy.set_file_size_cap(max_bytes)

    def set_auto_accept_files(self, value):
        self.policy.set_auto_accept_files(value)

    # ---------------------------------------------------------------- presence
    def set_presence(self, state):
        self.presence.set_presence(state)

    def get_presence(self, peer_pid):
        return self.presence.get(peer_pid)

    def list_presence(self):
        return self.presence.list()

    # ------------------------------------------------------------------- keys
    def rotate_keys(self):
        """Rotate the X25519 E2E keypair and broadcast KEY_ROTATE.

        The Ed25519 identity key (and thus the peer id) does not change.
        Inbound envelopes encrypted to the previous X25519 key are still
        accepted via a one-generation decrypt fallback.
        """
        old_priv = self.identity.x_priv
        _, new_pub = self.identity.rotate_e2e()
        self.identity.save(self._passphrase)
        self._prev_x_priv = old_priv
        payload = {"ipub": self.identity.ed_pub.hex(),
                   "x_pub": new_pub.hex()}
        for peer in self.store.list_peers():
            try:
                self._send_plain(KEY_ROTATE, peer["agent_id"], payload)
            except AcpError as e:
                self.audit.log("key.rotate_failed",
                               actor=peer["agent_id"], result="failed",
                               details={"error": e.code})
        self.audit.log("key.rotated", result="ok", details={})

    def change_passphrase(self, new_passphrase):
        self.identity.change_passphrase(new_passphrase)
        self._passphrase = new_passphrase

    # ------------------------------------------------------------------ revoke
    def revoke_peer(self, pid, reason="revoked by local user"):
        self.revoker.revoke_peer(pid, reason)

    def list_peers(self, include_revoked=False):
        return self.store.list_peers(include_revoked=include_revoked)

    # ------------------------------------------------------------------- audit
    def audit_log(self, limit=200):
        return self.audit.tail(limit=limit)

    # --------------------------------------------------------------- metrics
    def _metric(self, name, nbytes=0):
        """Record an analytics counter if analytics is attached.

        Never raises: metrics must not break the data path.
        """
        try:
            a = self.analytics
        except AttributeError:
            return
        try:
            if name == "message_sent":
                a.message_sent(nbytes)
            elif name == "message_received":
                a.message_received(nbytes)
            elif name == "file_completed":
                a.file_completed()
            elif name == "pairing_completed":
                a.pairing_completed()
            elif name == "call_placed":
                a.call_placed()
        except Exception:
            pass

    # ------------------------------------------------------------------ bridge
    def _on_bridge_route(self, kind, payload, owner):
        """Per-connector policy passthrough for bridge fan-out."""
        self.policy.check_rate("bridge")
        self.audit.log("bridge.routed", actor="bridge", result="ok",
                       details={"kind": kind})
        return True

    # -------------------------------------------------------------- background
    def _sweep_loop(self):
        while not self._stopping:
            time.sleep(_SWEEP_INTERVAL)
            if self._stopping:
                break
            try:
                self.pairing.sweep()
            except Exception:
                pass
            try:
                self.analytics.heartbeat()
            except Exception:
                pass
