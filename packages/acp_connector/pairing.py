"""Pairing: the 4-message handshake.

  initiator: pair_request  -> (responder) pair_challenge ->
             pair_confirm (E2E) -> (responder) pair_welcome (E2E)

- pair_request / pair_challenge are signed plaintext (the peer is not
  trusted yet, so the signature is bootstrapped from the ``ipub`` in
  the payload: ``from`` must equal b62encode(ipub)).
- pair_confirm / pair_welcome are E2E-encrypted with the peer's X25519
  key learned during the handshake.
- The 6-char code is shown on the responder side (session.code); the
  initiator's user types it into session.confirm(). Only a sha256 hash
  of the code crosses the wire.
- Sessions expire after 10 minutes (lazy check + background sweep).

Deviation from docs/PROTOCOL.md section 6: that section describes the
backend-mediated flow (PAIR_HELLO/PAIR_CHALLENGE/PAIR_RESPONSE/PAIR_DONE
via the API server + relay). The implemented acp_proto kinds
(pair_request/pair_challenge/pair_confirm/pair_welcome) run the same
idea directly over TCP, which is what this connector build targets.
"""
import hashlib
import hmac
import os
import threading
import time

from acp_crypto import random_bytes
from acp_proto import (
    AcpError, make_envelope,
    PAIR_REQUEST, PAIR_CHALLENGE, PAIR_CONFIRM, PAIR_WELCOME,
)

# No ambiguous chars: no 0/O, no 1/I/L.
PAIR_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
SESSION_TTL = 600  # 10 minutes
MAX_CONFIRM_ATTEMPTS = 5


def new_code(n=6):
    return "".join(PAIR_CODE_ALPHABET[b % len(PAIR_CODE_ALPHABET)]
                   for b in random_bytes(n))


def code_hash(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _check_x_pub(value, what):
    """Validate a peer-supplied X25519 public key (64-char hex)."""
    try:
        raw = bytes.fromhex(value or "")
    except (ValueError, TypeError, AttributeError):
        raise AcpError("PAIRING_FAILED", f"{what} is not hex")
    if len(raw) != 32:
        raise AcpError("PAIRING_FAILED", f"{what} wrong length")
    return value


class PairingSession:
    """One side of one handshake. Returned to the user."""

    def __init__(self, mgr, session_id, role):
        self._mgr = mgr
        self.session_id = session_id
        self.role = role  # 'initiator' | 'responder'
        self.state = "await_challenge" if role == "initiator" else "await_accept"
        self.peer_pid = None
        self.peer_handle = None
        self.peer_x_pub = None  # hex
        self.peer_ipub = None   # hex
        self.code = None        # plaintext code; responder side only
        self.code_hash = None
        self.attempts = 0
        self.created_at = int(time.time())
        self.expires_at = self.created_at + SESSION_TTL
        self.conn = None

    @property
    def expired(self):
        return time.time() > self.expires_at

    # ------------------------------------------------------------- internal
    def _persist(self):
        self._mgr._c.store.save_pairing_session(
            self.session_id, self.role, self.peer_pid, self.code_hash,
            self.expires_at, self.state, self.created_at)

    def _ensure_live(self):
        if self.state == "failed" or self.expired:
            self._fail("expired" if self.expired else "failed")
            raise AcpError("PAIRING_FAILED", "pairing session expired")

    def _fail(self, reason):
        self.state = "failed"
        try:
            self._persist()
        except Exception:
            pass
        self._mgr._c.audit.log("pairing.failed", actor=self.peer_pid,
                               result="failed",
                               details={"session": self.session_id,
                                        "reason": reason})

    # ------------------------------------------------------- responder side
    def accept(self):
        """Responder: approve the request, send pair_challenge."""
        if self.role != "responder":
            raise AcpError("PAIRING_FAILED", "accept() is responder-only")
        if self.state != "await_accept":
            raise AcpError("PAIRING_FAILED",
                           f"cannot accept in state {self.state}")
        self._ensure_live()
        c = self._mgr._c
        payload = {
            "code_hash": self.code_hash,
            "x_pub": c.identity.x_pub.hex(),
            "ipub": c.identity.ed_pub.hex(),
            "handle": c.handle,
            "expires": self.expires_at,
        }
        c._send_plain(PAIR_CHALLENGE, self.peer_pid, payload)
        self.state = "await_confirm"
        self._persist()
        c.audit.log("pairing.challenged", actor=self.peer_pid, result="ok",
                    details={"session": self.session_id})

    # ------------------------------------------------------- initiator side
    def confirm(self, code):
        """Initiator: submit the code shown on the responder's screen."""
        if self.role != "initiator":
            raise AcpError("PAIRING_FAILED", "confirm() is initiator-only")
        if self.state != "await_code":
            raise AcpError("PAIRING_FAILED",
                           f"cannot confirm in state {self.state}")
        self._ensure_live()
        self.attempts += 1
        typed = str(code).strip().upper()
        if self.attempts > MAX_CONFIRM_ATTEMPTS:
            self._fail("too many code attempts")
            raise AcpError("PAIRING_FAILED", "too many code attempts")
        if not hmac.compare_digest(code_hash(typed), self.code_hash or ""):
            raise AcpError("PAIRING_FAILED", "pair code mismatch")
        c = self._mgr._c
        payload = {
            "x_pub": c.identity.x_pub.hex(),
            "ipub": c.identity.ed_pub.hex(),
            "handle": c.handle,
            "code": typed,
        }
        # The responder is not in the trust store yet: send with the
        # X25519 key learned from its pair_challenge.
        c._send_e2e_untrusted(PAIR_CONFIRM, self.peer_pid,
                              bytes.fromhex(self.peer_x_pub), payload)
        self.state = "await_welcome"
        self._persist()
        c.audit.log("pairing.confirmed", actor=self.peer_pid, result="ok",
                    details={"session": self.session_id})


class PairingManager:
    def __init__(self, connector):
        self._c = connector
        self._lock = threading.Lock()
        self._sessions = {}  # session_id -> PairingSession (in-memory)
        self._request_cbs = []

    # ------------------------------------------------------------------ API
    def on_pairing_request(self, cb):
        """cb(session): fired when a pair_request arrives. Read
        session.code and show it to the user; call session.accept()."""
        self._request_cbs.append(cb)

    def pair_initiate(self, host, port):
        """Connect and send pair_request. Returns the initiator session."""
        c = self._c
        conn = c.transport.connect(host, port)
        session = self._new_session("initiator")
        session.conn = conn
        c._spawn_reader(conn)
        c.store.set_connection("pending:" + session.session_id, "direct",
                               f"{host}:{port}", "connecting")
        payload = {
            "handle": c.handle,
            "x_pub": c.identity.x_pub.hex(),
            "ipub": c.identity.ed_pub.hex(),
        }
        env = make_envelope(PAIR_REQUEST, c.peer_id, "*", payload,
                            c.identity.ed_priv)
        conn.send_env(env)
        c.audit.log("pairing.initiated", target=f"{host}:{port}",
                    result="ok", details={"session": session.session_id})
        return session

    def pair_initiate_relay(self, peer_pid):
        """Start pairing with a peer reachable via the relay (no dial).

        The pair_request goes out through the shared relay link
        (Connector._get_conn falls back to it); no per-pid binding is
        created here. The challenge handler binds the peer to the link
        when the response arrives. Returns the initiator session.
        """
        c = self._c
        link = c._relay_link
        if link is None or link.closed:
            raise AcpError("INTERNAL",
                           "no relay link — relay_connect(url) first")
        session = self._new_session("initiator")
        session.peer_pid = peer_pid
        session.conn = link
        payload = {
            "handle": c.handle,
            "x_pub": c.identity.x_pub.hex(),
            "ipub": c.identity.ed_pub.hex(),
        }
        c._send_plain(PAIR_REQUEST, peer_pid, payload)
        c.audit.log("pairing.initiated", target="relay", result="ok",
                    details={"session": session.session_id,
                             "peer": peer_pid[:16]
                             if isinstance(peer_pid, str) else peer_pid,
                             "via": "relay"})
        return session

    def get_session(self, session_id):
        with self._lock:
            return self._sessions.get(session_id)

    def find_by_peer(self, peer_pid):
        """In-memory session for a peer (any non-failed state)."""
        with self._lock:
            best = None
            for s in self._sessions.values():
                if s.peer_pid == peer_pid and s.state != "failed":
                    if best is None or s.created_at > best.created_at:
                        best = s
            return best

    def sweep(self):
        """Fail expired sessions. Called periodically by the connector."""
        now = time.time()
        for s in list(self._sessions.values()):
            if s.state not in ("done", "failed") and s.expires_at < now:
                s._fail("expired")
                # Never close the shared relay link here: it belongs to
                # the Connector and serves all pids.
                if s.conn is not None and s.conn is not self._c._relay_link:
                    try:
                        s.conn.close()
                    except Exception:
                        pass

    # ------------------------------------------------------- inbound events
    def handle_pair_request(self, conn, env):
        """Responder: a new pair_request arrived (signature bootstrapped)."""
        c = self._c
        payload = env["payload"]
        peer_pid = env["from"]
        with self._lock:
            for s in list(self._sessions.values()):
                if (s.peer_pid == peer_pid and s.role == "responder"
                        and s.state != "done"):
                    s.state = "failed"
                    s._persist()
        session = self._new_session(
            "responder", peer_pid=peer_pid,
            peer_handle=payload.get("handle", ""),
            peer_x_pub=_check_x_pub(payload.get("x_pub"), "x_pub"),
            peer_ipub=payload.get("ipub"))
        session.conn = conn
        session.code = new_code()
        session.code_hash = code_hash(session.code)
        session._persist()
        c.audit.log("pairing.requested", actor=peer_pid, result="ok",
                    details={"session": session.session_id,
                             "handle": session.peer_handle})
        for cb in list(self._request_cbs):
            try:
                cb(session)
            except Exception as e:
                c.audit.log("pairing.callback_error", actor=peer_pid,
                            result="failed", details={"error": str(e)})
        return session

    def handle_challenge(self, conn, env):
        """Initiator: pair_challenge arrived."""
        c = self._c
        payload = env["payload"]
        session = self._find_initiator_session(env["from"])
        if session is None:
            raise AcpError("PAIRING_FAILED",
                           "challenge for unknown pairing session")
        if session.state != "await_challenge":
            raise AcpError("PAIRING_FAILED",
                           f"unexpected challenge in state {session.state}")
        session._ensure_live()
        session.peer_pid = env["from"]
        session.peer_handle = payload.get("handle", "")
        session.peer_x_pub = _check_x_pub(payload.get("x_pub"), "x_pub")
        session.peer_ipub = payload.get("ipub")
        session.code_hash = payload.get("code_hash")
        session.conn = conn
        session.state = "await_code"
        session._persist()
        c._bind_conn(env["from"], conn)
        c.audit.log("pairing.challenge_received", actor=env["from"],
                    result="ok", details={"session": session.session_id})

    def handle_confirm(self, conn, env, payload):
        """Responder: pair_confirm (E2E) arrived."""
        c = self._c
        peer_pid = env["from"]
        session = self._find_session(peer_pid, "responder", "await_confirm")
        if session is None:
            raise AcpError("PAIRING_FAILED",
                           "confirm for unknown pairing session")
        session._ensure_live()
        if (payload.get("ipub") != session.peer_ipub
                or payload.get("x_pub") != session.peer_x_pub):
            session._fail("identity keys changed mid-handshake")
            raise AcpError("PAIRING_FAILED",
                           "identity keys changed mid-handshake")
        if not hmac.compare_digest(str(payload.get("code", "")),
                                   session.code or ""):
            session._fail("code mismatch")
            raise AcpError("PAIRING_FAILED", "pair code mismatch")
        c._store_peer(peer_pid, session.peer_handle, session.peer_ipub,
                      session.peer_x_pub)
        c._bind_conn(peer_pid, conn)
        c._send_e2e(PAIR_WELCOME, peer_pid, {"handle": c.handle})
        session.state = "done"
        session._persist()
        c.audit.log("pairing.completed", actor=peer_pid, result="ok",
                    details={"session": session.session_id,
                             "role": "responder"})
        c._metric("pairing_completed")

    def handle_welcome(self, conn, env, payload):
        """Initiator: pair_welcome (E2E) arrived."""
        c = self._c
        peer_pid = env["from"]
        session = self._find_session(peer_pid, "initiator", "await_welcome")
        if session is None:
            raise AcpError("PAIRING_FAILED",
                           "welcome for unknown pairing session")
        c._store_peer(peer_pid, session.peer_handle, session.peer_ipub,
                      session.peer_x_pub)
        c._bind_conn(peer_pid, conn)
        session.state = "done"
        session._persist()
        c.audit.log("pairing.completed", actor=peer_pid, result="ok",
                    details={"session": session.session_id,
                             "role": "initiator"})
        c._metric("pairing_completed")

    # -------------------------------------------------------------- internal
    def _new_session(self, role, **kw):
        session_id = os.urandom(16).hex()
        s = PairingSession(self, session_id, role)
        for k, v in kw.items():
            setattr(s, k, v)
        with self._lock:
            self._sessions[session_id] = s
        s._persist()
        return s

    def _find_session(self, peer_pid, role, state):
        with self._lock:
            for s in self._sessions.values():
                if (s.peer_pid == peer_pid and s.role == role
                        and s.state == state and not s.expired):
                    return s
        return None

    def _find_initiator_session(self, peer_pid):
        with self._lock:
            best = None
            for s in self._sessions.values():
                if (s.role == "initiator" and s.state == "await_challenge"
                        and not s.expired
                        and s.peer_pid in (None, peer_pid)):
                    if best is None or s.created_at > best.created_at:
                        best = s
            return best
