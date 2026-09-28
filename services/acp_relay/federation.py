"""Relay federation for acp_relay: relay-to-relay peering over TCP.

Two (or more) relays link to each other so a frame addressed to a pid
that is not locally connected can be forwarded to the relay where that
pid IS connected. Trust is explicit: every relay holds an Ed25519
identity keypair (generated once, stored in the relay data dir) and a
local allowlist file (trusted_relays.json). A link is only established
when BOTH sides verify the peer's signature AND find the peer's relay
id in their own allowlist — there is no open federation.

Link handshake (length-prefixed JSON frames, same framing as relay.py):
  dialer -> listener: {"relay_link": {"relay_id","ts","sig"}}
  listener -> dialer: {"relay_link_accept": {"relay_id","ts","sig"}}
  sig = Ed25519_sign(relay_priv, canonical({"relay_id","ts"})).

After linking each side announces the pids attached to it:
  {"relay_announce": {"pid","relay_id","ts","sig"}}
  sig = Ed25519_sign(sender_relay_priv,
                     canonical({"pid","relay_id","ts"})).
relay_id is the ORIGIN relay (where the pid is locally attached);
announces are re-signed at every hop, so a relay can advertise pids it
reaches transitively. Withdrawals use {"relay_withdraw": {...}} with
the same shape. Routing table: pid -> (link, origin_relay_id, ts).

Data frames cross links wrapped OUTSIDE the signed envelope so the
original bytes — and therefore the sender's signature — are untouched:
  {"fed_forward": {"hops": int, "frame": b62(raw_envelope_bytes)}}
"hops" counts relay-to-relay traversals; MAX_FED_HOPS = 3, anything at
or above is dropped (loop backstop). The receiving relay verifies the
envelope's signature itself (the pid IS the Ed25519 verify key) as
defense-in-depth, then delivers locally, forwards onward (hops+1), or
mailboxes it if the pid is unreachable.

Security properties (also see docs/FEDERATION.md):
  * frames keep their original sender signatures end-to-end; a
    malicious (but allowlisted) relay can drop or blackhole traffic
    but cannot forge a sender's signature or read E2E ("box") content;
  * untrusted relays cannot link at all (allowlist is fail-closed);
  * tampered hop counters are dropped, not forwarded.

Keepalive: {"fed_ping":{"ts"}} / {"fed_pong":{"ts"}}; links that stop
answering are closed and their routes withdrawn. Local pids are
re-announced periodically so withdrawals caused by flapping links
self-heal.
"""
import json
import os
import socket
import struct
import threading
import time

from acp_crypto import (ed25519_sign, ed25519_verify,
                        generate_ed25519_keypair)
from acp_proto import b62encode, b62decode, canonical

MAX_FRAME = 4 * 1024 * 1024
LINK_FRESHNESS_S = 300      # relay_link / relay_link_accept ts window
ANNOUNCE_FRESHNESS_S = 600  # announce / withdraw ts window
MAX_FED_HOPS = 3            # fed_forward hops at/above this are dropped


class FederationError(Exception):
    pass


# ---------------------------------------------------------------- framing
# (mirrors relay.py framing; duplicated here so this module has no
# import cycle with relay.py)

def _recvall(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def _read_frame(sock):
    hdr = _recvall(sock, 4)
    (ln,) = struct.unpack(">I", hdr)
    if ln > MAX_FRAME:
        raise ValueError("frame too large")
    return _recvall(sock, ln)


def _write_frame(sock, raw):
    sock.sendall(struct.pack(">I", len(raw)) + raw)


# ------------------------------------------------------------- identities

def vkey_from_pid(pid):
    """Recover the 32-byte Ed25519 verify key from a pid (a pid IS the
    b62-encoded verify key; b62 drops leading zero bytes, restored
    here). Raises ValueError on garbage."""
    raw = b62decode(pid)
    if len(raw) > 32:
        raise ValueError("pid too long")
    return raw.rjust(32, b"\x00")


def verify_forwarded_frame(obj):
    """Structural + signature check for an envelope received over a
    relay link. Freshness/kind are intentionally NOT checked here: the
    frame may legitimately come from a mailbox (old ts), and kind
    validity is the recipient's call. Returns the envelope dict.
    Raises ValueError."""
    if not isinstance(obj, dict):
        raise ValueError("frame is not a dict")
    for f in ("from", "to", "kind", "ts", "nonce", "sig"):
        if f not in obj:
            raise ValueError("missing %s" % f)
    if not isinstance(obj["from"], str) or not isinstance(obj["to"], str):
        raise ValueError("bad from/to")
    if ("payload" in obj) == ("box" in obj):
        raise ValueError("need exactly one of payload/box")
    vkey = vkey_from_pid(obj["from"])
    try:
        sig = b62decode(obj["sig"])
    except (ValueError, KeyError, TypeError):
        raise ValueError("bad sig encoding")
    unsigned = {k: v for k, v in obj.items() if k != "sig"}
    if not ed25519_verify(vkey, canonical(unsigned), sig):
        raise ValueError("bad envelope signature")
    return obj


def load_or_create_identity(data_dir):
    """Load (or generate) the relay's Ed25519 identity keypair.

    Stored at <data_dir>/relay_identity.key as JSON with mode 0600.
    Returns (priv, pub, relay_id) where relay_id = b62(pub).
    """
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, "relay_identity.key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        priv = bytes.fromhex(doc["ed_priv"])
        if len(priv) != 32:
            raise FederationError("relay_identity.key is corrupt")
    else:
        priv, _ = generate_ed25519_keypair()
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            from acp_crypto import ed25519_publickey
            json.dump({"ed_priv": priv.hex(),
                       "ed_pub": ed25519_publickey(priv).hex()}, f)
        os.replace(tmp, path)
    from acp_crypto import ed25519_publickey
    pub = ed25519_publickey(priv)
    return priv, pub, b62encode(pub)


def read_allowlist(path):
    """Read trusted_relays.json -> set of relay ids.

    Format: {"relays": [{"relay_id": "<b62>", "note": "..."}, ...]}.
    Missing or corrupt file -> empty set (fail-closed: no links).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        entries = doc.get("relays", [])
        out = set()
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("relay_id"), str):
                out.add(e["relay_id"])
        return out
    except (OSError, ValueError, AttributeError):
        return set()


def allowlist_add(path, relay_id, note=""):
    """Append a relay id to the allowlist file (creates it if needed)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        doc = {"relays": []}
    relays = doc.setdefault("relays", [])
    if not any(isinstance(e, dict) and e.get("relay_id") == relay_id
               for e in relays):
        relays.append({"relay_id": relay_id, "note": note})
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


# ------------------------------------------------------------------ link

class _Link:
    """One relay-to-relay TCP connection."""

    def __init__(self, sock, relay_id, manager):
        self.sock = sock
        self.relay_id = relay_id
        self._mgr = manager
        self._send_lock = threading.Lock()
        self.last_pong = time.time()
        self.last_ping_sent = 0.0
        self.alive = True
        self._reader = None

    def send_obj(self, obj):
        with self._send_lock:
            if not self.alive:
                raise OSError("link closed")
            _write_frame(self.sock, canonical(obj))

    def start_reader(self):
        t = threading.Thread(target=self._read_loop, daemon=True,
                             name="fed-link-reader")
        t.start()
        self._reader = t

    def _read_loop(self):
        try:
            while self.alive:
                try:
                    raw = _read_frame(self.sock)
                except (ConnectionError, ValueError, OSError,
                        socket.timeout):
                    break
                try:
                    obj = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                try:
                    self._mgr.handle_link_frame(self, obj)
                except Exception:
                    continue
        finally:
            self._mgr.link_closed(self)

    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------- manager

class FederationManager:
    def __init__(self, server, config):
        self._server = server
        cfg = dict(config or {})
        data_dir = cfg.get("data_dir")
        if not data_dir:
            raise ValueError("federation requires data_dir")
        self._data_dir = str(data_dir)
        self._priv, self._pub, self.relay_id = load_or_create_identity(
            self._data_dir)
        self._allowlist_path = (cfg.get("trusted_relays_path") or
                                os.path.join(self._data_dir,
                                             "trusted_relays.json"))
        self._ping_interval = float(cfg.get("fed_ping_interval_s", 30))
        self._pong_timeout = float(cfg.get("fed_pong_timeout_s", 90))
        self._announce_interval = float(cfg.get("fed_announce_interval_s",
                                               300))
        self._route_ttl = float(cfg.get("fed_route_ttl_s",
                                        2 * self._announce_interval))
        self._links = {}   # relay_id -> _Link
        self._routes = {}  # pid -> {"link","origin","ts"}
        self._lock = threading.RLock()
        self._running = False
        self._sweeper = None
        self._last_reannounce = 0.0

    # ------------------------------------------------------------ lifecycle
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._sweeper = threading.Thread(target=self._sweep_loop,
                                             daemon=True,
                                             name="fed-sweeper")
            self._sweeper.start()

    def stop(self):
        with self._lock:
            self._running = False
            links = list(self._links.values())
        for lk in links:
            lk.close()
        if self._sweeper is not None:
            self._sweeper.join(timeout=5)
            self._sweeper = None

    def _sweep_loop(self):
        while True:
            with self._lock:
                if not self._running:
                    break
            time.sleep(min(self._ping_interval, 5))
            with self._lock:
                if not self._running:
                    break
            try:
                self._tick()
            except Exception:
                pass

    def _tick(self):
        now = time.time()
        with self._lock:
            links = list(self._links.values())
        for lk in links:
            if not lk.alive:
                self.link_closed(lk)
                continue
            if now - lk.last_ping_sent >= self._ping_interval:
                try:
                    lk.send_obj({"fed_ping": {"ts": int(now)}})
                except OSError:
                    self.link_closed(lk)
                    continue
                lk.last_ping_sent = now
            if now - lk.last_pong > self._pong_timeout:
                self._server.audit("fed.link_timeout",
                                   {"relay_id": lk.relay_id})
                self.link_closed(lk)
        with self._lock:
            stale = [pid for pid, r in self._routes.items()
                     if now - r["ts"] > self._route_ttl]
            for pid in stale:
                del self._routes[pid]
        if stale:
            self._server.audit("fed.routes_expired",
                               {"count": len(stale)})
        if now - self._last_reannounce >= self._announce_interval:
            self._last_reannounce = now
            for pid in self._server.local_pids():
                self.announce_local(pid)

    # ------------------------------------------------------------- linking
    def _verify_link_message(self, msg, what):
        """Validate a relay_link / relay_link_accept body. Returns the
        peer relay id. Raises FederationError (caller closes)."""
        if not isinstance(msg, dict):
            raise FederationError("%s is not a dict" % what)
        rid = msg.get("relay_id")
        ts = msg.get("ts")
        sig = msg.get("sig")
        if not isinstance(rid, str) or not rid:
            raise FederationError("%s: bad relay_id" % what)
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise FederationError("%s: bad ts" % what)
        if abs(int(time.time()) - ts) > LINK_FRESHNESS_S:
            raise FederationError("%s: stale ts" % what)
        if rid == self.relay_id:
            raise FederationError("%s: self link refused" % what)
        if rid not in read_allowlist(self._allowlist_path):
            raise FederationError("%s: relay not in allowlist" % what)
        try:
            vkey = vkey_from_pid(rid)
            sigb = b62decode(sig)
        except (ValueError, KeyError, TypeError):
            raise FederationError("%s: bad sig encoding" % what)
        if not ed25519_verify(vkey, canonical({"relay_id": rid, "ts": ts}),
                              sigb):
            raise FederationError("%s: bad signature" % what)
        return rid

    def _signed(self, body):
        body = dict(body)
        body["sig"] = b62encode(ed25519_sign(self._priv, canonical(
            {k: v for k, v in body.items() if k != "sig"})))
        return body

    def _add_link(self, sock, peer_id):
        with self._lock:
            old = self._links.get(peer_id)
            link = _Link(sock, peer_id, self)
            self._links[peer_id] = link
        if old is not None and old is not link:
            old.close()
        return link

    def dial(self, host, port, timeout=10):
        """Initiate a federation link. Returns the peer relay id.

        Raises FederationError if the peer refuses, is untrusted, or
        the handshake fails (socket is closed on failure).
        """
        with self._lock:
            if not self._running:
                raise FederationError("federation not started")
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ts = int(time.time())
            body = self._signed({"relay_id": self.relay_id, "ts": ts})
            _write_frame(sock, canonical({"relay_link": body}))
            sock.settimeout(timeout)
            try:
                raw = _read_frame(sock)
            finally:
                sock.settimeout(None)
            obj = json.loads(raw.decode("utf-8"))
            acc = obj.get("relay_link_accept")
            peer_id = self._verify_link_message(acc, "relay_link_accept")
            link = self._add_link(sock, peer_id)
            link.start_reader()
            self._announce_all_to(link)
            self._server.audit("fed.link_up",
                               {"relay_id": peer_id, "direction": "out"})
            return peer_id
        except Exception as e:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
            if isinstance(e, FederationError):
                raise
            raise FederationError("link handshake failed: %s" % e)

    def accept_link(self, sock, first):
        """Accept-side of the handshake (called by the relay handler on
        the first frame). Returns the _Link. Raises FederationError."""
        lk = first.get("relay_link")
        peer_id = self._verify_link_message(lk, "relay_link")
        ts = int(time.time())
        body = self._signed({"relay_id": self.relay_id, "ts": ts})
        _write_frame(sock, canonical({"relay_link_accept": body}))
        link = self._add_link(sock, peer_id)
        self._announce_all_to(link)
        self._server.audit("fed.link_up",
                           {"relay_id": peer_id, "direction": "in"})
        return link

    def link_closed(self, link):
        with self._lock:
            if self._links.get(link.relay_id) is not link:
                return
            del self._links[link.relay_id]
            affected = [(pid, r["origin"]) for pid, r in
                        self._routes.items() if r["link"] is link]
            for pid, _ in affected:
                del self._routes[pid]
        link.close()
        self._server.audit("fed.link_down", {"relay_id": link.relay_id,
                                             "routes_lost": len(affected)})
        for pid, origin in affected:
            if self._server.lookup(pid) is None:
                self._propagate_withdraw(pid, origin)

    def links(self):
        with self._lock:
            return dict(self._links)

    # -------------------------------------------------------------- routes
    def route_for(self, pid):
        with self._lock:
            r = self._routes.get(pid)
            if r is None:
                return None
            if not r["link"].alive:
                return None
            if time.time() - r["ts"] > self._route_ttl:
                del self._routes[pid]
                return None
            return r["link"]

    def _announce_all_to(self, link):
        for pid in self._server.local_pids():
            self._send_announce(link, pid)

    def _send_announce(self, link, pid):
        body = self._signed({"pid": pid, "relay_id": self.relay_id,
                             "ts": int(time.time())})
        try:
            link.send_obj({"relay_announce": body})
        except OSError:
            self.link_closed(link)

    def announce_local(self, pid):
        """A pid just hello'd here: tell every linked relay."""
        with self._lock:
            links = list(self._links.values())
        for lk in links:
            self._send_announce(lk, pid)

    def withdraw_local(self, pid):
        """A pid just disconnected: tell every linked relay."""
        body = self._signed({"pid": pid, "relay_id": self.relay_id,
                             "ts": int(time.time())})
        with self._lock:
            links = list(self._links.values())
        for lk in links:
            try:
                lk.send_obj({"relay_withdraw": body})
            except OSError:
                self.link_closed(lk)

    def _propagate_withdraw(self, pid, origin):
        body = self._signed({"pid": pid, "relay_id": origin,
                             "ts": int(time.time())})
        with self._lock:
            links = list(self._links.values())
        for lk in links:
            try:
                lk.send_obj({"relay_withdraw": body})
            except OSError:
                self.link_closed(lk)

    def _verify_relay_msg(self, link, msg, what):
        """Verify an announce/withdraw body against the LINK peer's key
        (the immediate sender vouches for it). Returns (pid, origin,
        ts). Raises ValueError."""
        if not isinstance(msg, dict):
            raise ValueError("%s not a dict" % what)
        pid, origin, ts = msg.get("pid"), msg.get("relay_id"), msg.get("ts")
        sig = msg.get("sig")
        if not isinstance(pid, str) or not pid:
            raise ValueError("bad pid")
        if not isinstance(origin, str) or not origin:
            raise ValueError("bad relay_id")
        if not isinstance(ts, int) or isinstance(ts, bool):
            raise ValueError("bad ts")
        if abs(int(time.time()) - ts) > ANNOUNCE_FRESHNESS_S:
            raise ValueError("stale ts")
        vkey = vkey_from_pid(link.relay_id)
        sigb = b62decode(sig)
        if not ed25519_verify(
                vkey, canonical({"pid": pid, "relay_id": origin,
                                 "ts": ts}), sigb):
            raise ValueError("bad signature")
        return pid, origin, ts

    def _on_announce(self, link, ann):
        try:
            pid, origin, ts = self._verify_relay_msg(link, ann,
                                                     "relay_announce")
        except (ValueError, KeyError, TypeError) as e:
            self._server.audit("fed.announce_rejected",
                               {"from": link.relay_id, "error": str(e)})
            return
        if self._server.lookup(pid) is not None:
            return  # local attachment wins; ignore remote claim
        with self._lock:
            cur = self._routes.get(pid)
            if cur is not None and ts <= cur["ts"]:
                return
            self._routes[pid] = {"link": link, "origin": origin, "ts": ts}
            others = [lk for lk in self._links.values() if lk is not link]
        self._server.audit("fed.route",
                           {"pid": pid[:16], "via": link.relay_id[:16],
                            "origin": origin[:16]})
        if origin != self.relay_id:
            # Transitive propagation: re-sign with our own key, keep the
            # origin relay id so withdrawals can be matched. Our own
            # echoes (origin == us) are never re-propagated.
            for lk in others:
                self._send_transitive(lk, pid, origin)
        self._forward_mailbox_for(pid, link)

    def _send_transitive(self, link, pid, origin):
        body = self._signed({"pid": pid, "relay_id": origin,
                             "ts": int(time.time())})
        try:
            link.send_obj({"relay_announce": body})
        except OSError:
            self.link_closed(link)

    def _on_withdraw(self, link, wd):
        try:
            pid, origin, ts = self._verify_relay_msg(link, wd,
                                                     "relay_withdraw")
        except (ValueError, KeyError, TypeError) as e:
            self._server.audit("fed.withdraw_rejected",
                               {"from": link.relay_id, "error": str(e)})
            return
        _ = ts
        with self._lock:
            cur = self._routes.get(pid)
            if cur is None or cur["origin"] != origin:
                return
            del self._routes[pid]
            others = [lk for lk in self._links.values() if lk is not link]
        self._server.audit("fed.route_withdrawn",
                           {"pid": pid[:16], "origin": origin[:16]})
        for lk in others:
            body = self._signed({"pid": pid, "relay_id": origin,
                                 "ts": int(time.time())})
            try:
                lk.send_obj({"relay_withdraw": body})
            except OSError:
                self.link_closed(lk)

    def _forward_mailbox_for(self, pid, link):
        """A pid we have queued mail for just became reachable via a
        federated link: forward the frames (custody transfer) and drop
        the local copies. Only when the pid is not locally attached."""
        mb = self._server.mailbox
        if mb is None:
            return
        if self._server.lookup(pid) is not None:
            return
        rows = mb.pending(pid)
        if not rows:
            return
        sent = []
        try:
            for r in rows:
                if not self.forward_frame(link, r["frame"], hops=0):
                    break
                sent.append(r["id"])
        finally:
            if sent:
                mb.delete_ids(sent)
        self._server.audit("fed.mailbox_forwarded",
                           {"pid": pid[:16], "frames": len(sent),
                            "via": link.relay_id[:16]})

    # ---------------------------------------------------------- link frames
    def handle_link_frame(self, link, obj):
        if not isinstance(obj, dict):
            return
        if "fed_ping" in obj:
            p = obj["fed_ping"]
            if isinstance(p, dict) and isinstance(p.get("ts"), int):
                try:
                    link.send_obj({"fed_pong": {"ts": p["ts"]}})
                except OSError:
                    self.link_closed(link)
            return
        if "fed_pong" in obj:
            link.last_pong = time.time()
            return
        if "relay_announce" in obj:
            self._on_announce(link, obj["relay_announce"])
            return
        if "relay_withdraw" in obj:
            self._on_withdraw(link, obj["relay_withdraw"])
            return
        if "fed_forward" in obj:
            self._on_fed_forward(link, obj["fed_forward"])
            return

    def forward_frame(self, link, raw: bytes, hops: int) -> bool:
        """Wrap raw envelope bytes with a hop counter and send. The
        envelope bytes are untouched (signatures stay verifiable)."""
        try:
            link.send_obj({"fed_forward": {"hops": int(hops),
                                           "frame": b62encode(raw)}})
            return True
        except (OSError, ValueError):
            self.link_closed(link)
            return False

    def _on_fed_forward(self, link, ff):
        try:
            if not isinstance(ff, dict):
                raise ValueError("fed_forward not a dict")
            hops = ff.get("hops")
            if not isinstance(hops, int) or isinstance(hops, bool):
                raise ValueError("hops not an int")
            if hops < 0 or hops >= MAX_FED_HOPS:
                self._server.audit(
                    "fed.forward_dropped",
                    {"reason": "hop_limit", "hops": hops,
                     "from": link.relay_id})
                return
            raw = b62decode(ff.get("frame") or "")
            env = verify_forwarded_frame(
                json.loads(raw.decode("utf-8")))
            target = env["to"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
            self._server.audit("fed.forward_rejected",
                               {"from": link.relay_id,
                                "error": "%s: %s" % (type(e).__name__, e)})
            return
        # Local delivery (drain gate applied inside).
        if self._server.deliver_to_local(target, raw):
            return
        # Transit: never bounce straight back over the incoming link.
        with self._lock:
            r = self._routes.get(target)
            nxt = (r["link"] if r is not None and r["link"] is not link
                   and r["link"].alive else None)
        if nxt is not None:
            self.forward_frame(nxt, raw, hops + 1)
            return
        # Terminal: hold it in our own mailbox (signature already
        # verified above); the recipient's relay will get it on
        # (re)connect via announce-triggered forwarding.
        mb = self._server.mailbox
        if mb is not None:
            mid = mb.store(target, env.get("from") or "",
                           env.get("kind") or "", raw)
            self._server.audit("fed.mailboxed",
                               {"to": target[:16], "mailbox_id": mid})
        else:
            self._server.audit("fed.dropped_no_route",
                               {"to": target[:16]})
