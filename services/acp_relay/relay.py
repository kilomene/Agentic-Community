"""acp_relay — TCP relay for connectors behind NAT (stdlib only).

Relay visibility (matches docs/SECURITY.md honest disclosure):
  The relay routes ACP *envelopes*. To forward a frame it reads only the
  envelope's routing metadata — "from", "to", "kind", "ts", "nonce" — and
  forwards the raw frame bytes to the connected client registered under
  the "to" pid. The relay holds NO E2E keys and NEVER sees plaintext:
  E2E payloads ("box" ciphertext) stay opaque. A compromised relay learns
  who talks to whom, when, and how much — never message text, file bytes,
  or permission reasons.

Handshake:
  Client connects and sends one length-prefixed JSON frame:
    {"hello": {"pid": b62, "ts": int, "sig": b62}}
  where pid = b62(connector Ed25519 public key) and
  sig = Ed25519_sign(identity_priv, canonical({"pid": pid, "ts": ts})).
  The relay verifies sig against pid (the pid IS the verify key) and
  requires |now - ts| <= 300 s. Anything else -> connection closed.

  A relay-to-relay federation link instead starts with:
    {"relay_link": {"relay_id": b62, "ts": int, "sig": b62}}
  (see federation.py). The first frame decides which path a connection
  takes; federation must be enabled in the relay config.

After the handshake each frame is either:
  * an ACP envelope frame (4-byte big-endian length + JSON): the relay
    reads "to" and forwards the raw bytes to that pid's socket. If the
    target is offline, the relay replies to the sender with a
    length-prefixed CONTROL frame (not an ACP envelope):
      {"relayed": false, "to": <pid>, "error": "offline"}
    With the mailbox enabled (config), the frame is instead stored for
    later delivery and the sender gets:
      {"relayed": false, "to": <pid>, "error": "offline",
       "queued": true, "mailbox_id": <int>}
  * a control frame {"ping": ts} -> replies {"pong": ts}.
  * a control frame {"mailbox_ack": {"ids": [...]}} -> deletes the
    acknowledged queued frames for this pid, replies
    {"mailbox_ack": {"acked": <int>}}.

Mailbox drain: on hello/reconnect, queued frames for the pid are sent
in FIFO order BEFORE any new traffic (a drain gate in deliver_to_local
holds concurrent dispatches until the drain finishes), preceded by a
{"mailbox_delivery": {"ids": [...]}} control frame. Frames stay
"inflight" until acked; unacked frames are retried on the next
reconnect.

Threading: one thread per client (socketserver.ThreadingMixIn);
pid -> socket map is lock-protected; dead clients are removed on
disconnect. A duplicate pid registration closes the older socket.

Config (dict, all optional):
  data_dir                  directory for mailbox.db, relay identity,
                            trusted_relays.json, relay_audit.log
                            (required when mailbox/federation enabled)
  mailbox_enabled           bool, default False (V1 behavior preserved)
  mailbox_max_per_recipient int, default 1000
  mailbox_max_bytes_per_recipient int, default 25 MiB
  mailbox_ttl_s             int, default 7 days
  federation_enabled        bool, default False
  trusted_relays_path       default <data_dir>/trusted_relays.json
  federation_links          list of {"host","port","relay_id"(opt),"note"}
                            auto-dialed on start, retried until linked
                            (see docs/FEDERATION.md)
  fed_dial_retry_s          seconds between link redials, default 15
  fed_ping_interval_s       default 30
  fed_pong_timeout_s        default 90
  fed_announce_interval_s   default 300
  fed_route_ttl_s           default 2 * announce interval
"""
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "packages"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from acp_crypto import ed25519_publickey, ed25519_sign, ed25519_verify
from acp_proto import (AcpError, b62encode, b62decode, canonical,
                       verify_envelope)
from mailbox import Mailbox
from federation import FederationManager, vkey_from_pid

MAX_FRAME = 4 * 1024 * 1024          # protocol §4: 4 MiB frame cap
FRESHNESS_S = 300                    # handshake + envelope timestamp window
HELLO_TIMEOUT_S = 15                 # seconds to complete the handshake


# -- framing ----------------------------------------------------------

def _recvall(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def read_frame(sock):
    """Read one length-prefixed frame. Raises on close / oversize."""
    hdr = _recvall(sock, 4)
    (ln,) = struct.unpack(">I", hdr)
    if ln > MAX_FRAME:
        raise ValueError("frame exceeds %d bytes" % MAX_FRAME)
    return _recvall(sock, ln)


def write_frame(sock, raw):
    sock.sendall(struct.pack(">I", len(raw)) + raw)


# -- handshake --------------------------------------------------------

def verify_hello(hello, now=None):
    """Validate a hello frame object. Returns the pid string.

    Raises ValueError on any problem; the caller must close the
    connection (no error is sent back).
    """
    now = int(time.time()) if now is None else now
    if not isinstance(hello, dict):
        raise ValueError("hello frame is not a JSON object")
    h = hello.get("hello")
    if not isinstance(h, dict):
        raise ValueError("missing hello object")
    pid = h.get("pid")
    ts = h.get("ts")
    sig_s = h.get("sig")
    if not isinstance(pid, str) or not pid:
        raise ValueError("bad pid")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise ValueError("bad ts")
    if abs(now - ts) > FRESHNESS_S:
        raise ValueError("stale ts")
    if not isinstance(sig_s, str) or not sig_s:
        raise ValueError("bad sig")
    try:
        vkey = b62decode(pid)
        sig = b62decode(sig_s)
    except (ValueError, KeyError):
        raise ValueError("bad base62 in pid/sig")
    if len(vkey) > 32 or len(sig) > 64:
        raise ValueError("pid/sig too long")
    vkey = vkey.rjust(32, b"\x00")
    sig = sig.rjust(64, b"\x00")
    if not ed25519_verify(vkey, canonical({"pid": pid, "ts": ts}), sig):
        raise ValueError("bad hello signature")
    return pid


def _looks_like_envelope(obj):
    """Structural check: is this plausibly an ACP envelope frame (as
    opposed to a control frame)? Never raises."""
    return (isinstance(obj, dict)
            and isinstance(obj.get("kind"), str)
            and isinstance(obj.get("from"), str)
            and isinstance(obj.get("to"), str)
            and isinstance(obj.get("ts"), int)
            and not isinstance(obj.get("ts"), bool)
            and isinstance(obj.get("nonce"), str)
            and isinstance(obj.get("sig"), str)
            and ("payload" in obj) != ("box" in obj))


# -- server -----------------------------------------------------------

class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.pid = None
        self.request.settimeout(HELLO_TIMEOUT_S)
        try:
            raw = read_frame(self.request)
            first = json.loads(raw.decode("utf-8"))
        except Exception:
            return  # unreadable first frame: close silently
        # -- federation link path -----------------------------------
        if (isinstance(first, dict) and "relay_link" in first
                and self.server.federation is not None):
            try:
                link = self.server.federation.accept_link(self.request,
                                                          first)
            except Exception:
                return  # refused: close silently
            try:
                self.request.settimeout(None)
                while True:
                    try:
                        raw = read_frame(self.request)
                    except (ConnectionError, ValueError, socket.timeout,
                            OSError):
                        break
                    try:
                        obj = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    self.server.federation.handle_link_frame(link, obj)
            finally:
                self.server.federation.link_closed(link)
            return
        # -- client path --------------------------------------------
        try:
            pid = verify_hello(first)
        except Exception:
            return  # handshake failed: close silently
        self.pid = pid
        self.server.register(pid, self.request)
        if self.server.federation is not None:
            self.server.federation.announce_local(pid)
        drain_ev = self.server.begin_drain(pid)
        try:
            self.drain_mailbox(pid)
            # A frame for this pid may have been stored while our first
            # drain was running (dispatch raced our hello verification);
            # sweep once more so it is delivered on this connection
            # instead of sitting queued until the next reconnect. The
            # second sweep skips the inflight reset so already-sent rows
            # are never delivered twice.
            self.drain_mailbox(pid, _reset=False)
        finally:
            self.server.end_drain(pid, drain_ev)
        try:
            self.request.settimeout(None)
            while True:
                try:
                    raw = read_frame(self.request)
                except (ConnectionError, ValueError, socket.timeout,
                        OSError):
                    break
                self.dispatch(raw)
        finally:
            self.server.unregister(pid, self.request)

    def drain_mailbox(self, pid, _reset=True):
        """Send queued frames FIFO, before any new traffic. Frames stay
        inflight until the client acks them.

        _reset=False skips the inflight reset: only genuinely new
        ('queued') rows are picked up, so a second sweep never
        re-sends rows the first sweep already delivered.
        """
        mb = self.server.mailbox
        if mb is None:
            return 0
        if _reset:
            mb.reset_inflight(pid)
        rows = mb.pending(pid)
        if not rows:
            return 0
        ids = [r["id"] for r in rows]
        mb.mark_inflight(ids)
        try:
            self.send_control({"mailbox_delivery": {"ids": ids}})
            for r in rows:
                self.server.send_to(self.request, r["frame"])
        except OSError:
            # Socket died mid-drain; frames stay inflight and are
            # retried on the next reconnect.
            return 0
        self.server.audit("mailbox.drained",
                          {"pid": pid[:16], "frames": len(rows)})
        return len(rows)

    def dispatch(self, raw):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_control({"relayed": False, "error": "bad_frame"})
            return
        if not isinstance(obj, dict):
            self.send_control({"relayed": False, "error": "bad_frame"})
            return
        if "ping" in obj:
            self.send_control({"pong": obj["ping"]})
            return
        if "mailbox_ack" in obj:
            self.handle_mailbox_ack(obj)
            return
        if "to" in obj and isinstance(obj["to"], str):
            target = obj["to"]
            if self.server.deliver_to_local(target, raw):
                return
            fed = self.server.federation
            if fed is not None:
                link = fed.route_for(target)
                if link is not None and fed.forward_frame(link, raw,
                                                          hops=0):
                    return
                # No route or the link died: fall through to mailbox /
                # offline reply below.
            if self.server.mailbox is not None:
                self.store_offline(target, raw, obj)
            else:
                self.send_control({"relayed": False, "to": target,
                                   "error": "offline"})
            return
        self.send_control({"relayed": False, "error": "bad_frame"})

    def store_offline(self, target, raw, obj):
        """Mailbox store path for an offline target. The frame must be a
        well-formed envelope from the hello'd pid with a valid
        signature; anything else is refused and never stored."""
        if not _looks_like_envelope(obj):
            self.send_control({"relayed": False, "to": target,
                               "error": "bad_frame"})
            return
        if obj.get("from") != self.pid:
            self.send_control({"relayed": False, "to": target,
                               "error": "spoofed_sender"})
            return
        try:
            vkey = vkey_from_pid(self.pid)
            verify_envelope(obj, lambda p: vkey if p == self.pid else None)
        except (AcpError, ValueError, KeyError):
            self.send_control({"relayed": False, "to": target,
                               "error": "bad_sig"})
            return
        mb = self.server.mailbox
        mid = mb.store(target, self.pid, obj.get("kind") or "", raw)
        if mid is None:
            self.send_control({"relayed": False, "to": target,
                               "error": "mailbox_full"})
            return
        self.server.audit("mailbox.stored",
                          {"to": target[:16], "from": self.pid[:16],
                           "kind": obj.get("kind"), "mailbox_id": mid})
        self.send_control({"relayed": False, "to": target,
                           "error": "offline", "queued": True,
                           "mailbox_id": mid})

    def handle_mailbox_ack(self, obj):
        mb = self.server.mailbox
        if mb is None or self.pid is None:
            return
        ack = obj.get("mailbox_ack")
        ids = ack.get("ids") if isinstance(ack, dict) else None
        if not isinstance(ids, list):
            return
        try:
            ids = [int(i) for i in ids]
        except (ValueError, TypeError):
            return
        n = mb.ack(self.pid, ids)
        self.server.audit("mailbox.acked",
                          {"pid": self.pid[:16], "acked": n})
        self.send_control({"mailbox_ack": {"acked": n}})

    def send_control(self, obj):
        try:
            write_frame(self.request, canonical(obj))
        except OSError:
            pass


class RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, config=None):
        super().__init__(server_address, RelayHandler)
        cfg = dict(config or {})
        self.config = cfg
        self.data_dir = cfg.get("data_dir")
        self._peers = {}          # pid (str) -> socket
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._drain_events = {}   # pid -> threading.Event (drain in flight)
        if cfg.get("mailbox_enabled", False):
            if not self.data_dir:
                raise ValueError("mailbox_enabled requires data_dir")
            self.mailbox = Mailbox(
                os.path.join(self.data_dir, "mailbox.db"),
                max_per_recipient=cfg.get("mailbox_max_per_recipient",
                                          1000),
                max_bytes_per_recipient=cfg.get(
                    "mailbox_max_bytes_per_recipient", 25 * 1024 * 1024),
                default_ttl_s=cfg.get("mailbox_ttl_s", 7 * 86400))
        else:
            self.mailbox = None
        if cfg.get("federation_enabled", False):
            if not self.data_dir:
                raise ValueError("federation_enabled requires data_dir")
            self.federation = FederationManager(self, cfg)
        else:
            self.federation = None

    # ------------------------------------------------------------ peers
    def register(self, pid, sock):
        with self._lock:
            old = self._peers.get(pid)
            if old is not None and old is not sock:
                try:
                    old.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    old.close()
                except OSError:
                    pass
            self._peers[pid] = sock

    def unregister(self, pid, sock):
        with self._lock:
            if self._peers.get(pid) is sock:
                del self._peers[pid]
            else:
                return
        if self.federation is not None:
            self.federation.withdraw_local(pid)

    def lookup(self, pid):
        with self._lock:
            return self._peers.get(pid)

    def local_pids(self):
        with self._lock:
            return list(self._peers.keys())

    def peer_count(self):
        with self._lock:
            return len(self._peers)

    def send_to(self, sock, raw):
        with self._send_lock:
            write_frame(sock, raw)

    # ------------------------------------------------- delivery + drain
    def begin_drain(self, pid):
        ev = threading.Event()
        with self._lock:
            self._drain_events[pid] = ev
        return ev

    def end_drain(self, pid, ev):
        with self._lock:
            if self._drain_events.get(pid) is ev:
                del self._drain_events[pid]
        ev.set()

    def deliver_to_local(self, target, raw):
        """Send to a locally connected pid, honouring the drain gate so
        mailbox redelivery always precedes new traffic. Returns True on
        delivery, False if the pid is not (or no longer) local."""
        with self._lock:
            peer = self._peers.get(target)
            ev = self._drain_events.get(target)
        if peer is None:
            return False
        if ev is not None:
            ev.wait(timeout=30)
            with self._lock:
                peer = self._peers.get(target)
            if peer is None:
                return False
        try:
            self.send_to(peer, raw)
        except OSError:
            return False
        return True

    # ------------------------------------------------------------- audit
    def audit(self, event, details=None):
        """Best-effort JSONL audit to <data_dir>/relay_audit.log."""
        if not self.data_dir:
            return
        try:
            line = canonical({"ts": int(time.time()), "event": event,
                              "details": details or {}}) + b"\n"
            with open(os.path.join(self.data_dir, "relay_audit.log"),
                      "ab") as f:
                f.write(line)
        except OSError:
            pass


# -- client (tests / scripting) ---------------------------------------

class RelayClient:
    """Minimal relay client: hello handshake + raw frame send/recv."""

    def __init__(self, sock, pid):
        self.sock = sock
        self.pid = pid

    @classmethod
    def connect(cls, host, port, sign_priv, ts=None, timeout=10):
        """Connect and complete the hello handshake.

        sign_priv: 32-byte Ed25519 identity private key.
        Returns (RelayClient, pid).
        """
        sock = socket.create_connection((host, port), timeout=timeout)
        pid = b62encode(ed25519_publickey(sign_priv))
        ts = int(time.time()) if ts is None else ts
        sig = b62encode(ed25519_sign(sign_priv,
                                     canonical({"pid": pid, "ts": ts})))
        hello = canonical({"hello": {"pid": pid, "ts": ts, "sig": sig}})
        write_frame(sock, hello)
        return cls(sock, pid), pid

    def send_frame(self, raw: bytes):
        write_frame(self.sock, raw)

    def send_json(self, obj):
        self.send_frame(canonical(obj))

    def recv_frame(self, timeout=10) -> bytes:
        self.sock.settimeout(timeout)
        try:
            return read_frame(self.sock)
        finally:
            self.sock.settimeout(None)

    def recv_json(self, timeout=10):
        return json.loads(self.recv_frame(timeout).decode("utf-8"))

    def drain_mailbox(self, timeout=10):
        """Read one mailbox_delivery control + its frames.

        Returns (ids, [raw frames]). Sends nothing; the caller decides
        what to ack.
        """
        notice = self.recv_json(timeout=timeout)
        ids = notice.get("mailbox_delivery", {}).get("ids")
        if not isinstance(ids, list):
            raise ValueError("expected mailbox_delivery, got %r"
                             % (notice,))
        frames = [self.recv_frame(timeout=timeout) for _ in ids]
        return ids, frames

    def ack_mailbox(self, ids, timeout=10):
        """Send a mailbox_ack control frame; returns the acked count."""
        self.send_json({"mailbox_ack": {"ids": list(ids)}})
        resp = self.recv_json(timeout=timeout)
        return resp.get("mailbox_ack", {}).get("acked", 0)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# -- lifecycle --------------------------------------------------------

def run(host="127.0.0.1", port=9090, config=None):
    """Start the relay in a background thread. Returns (server, thread).

    config: optional dict (see module docstring). With no config the
    relay behaves exactly like V1 (no mailbox, no federation).
    """
    server = RelayServer((host, port), config)
    if server.federation is not None:
        server.federation.start()
    thread = threading.Thread(target=server.serve_forever,
                              name="acp-relay", daemon=True)
    thread.start()
    return server, thread


def graceful_shutdown(server, thread, timeout=5):
    if server.federation is not None:
        try:
            server.federation.stop()
        except Exception:
            pass
    if server.mailbox is not None:
        try:
            server.mailbox.close()
        except Exception:
            pass
    server.shutdown()
    server.server_close()
    thread.join(timeout)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="acp_relay TCP relay")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9090)
    p.add_argument("--data-dir", default=None)
    p.add_argument("--mailbox", action="store_true",
                   help="enable the offline message mailbox")
    p.add_argument("--federation", action="store_true",
                   help="enable relay-to-relay federation")
    args = p.parse_args(argv)
    config = None
    if args.mailbox or args.federation or args.data_dir:
        if not args.data_dir:
            p.error("--data-dir is required with --mailbox/--federation")
        config = {"data_dir": args.data_dir,
                  "mailbox_enabled": args.mailbox,
                  "federation_enabled": args.federation}
    server, thread = run(args.host, args.port, config)
    print("acp_relay listening on %s:%d" % (args.host, args.port), flush=True)
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        graceful_shutdown(server, thread)
        print("acp_relay stopped", flush=True)


if __name__ == "__main__":
    main()
