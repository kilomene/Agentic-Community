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

After the handshake each frame is either:
  * an ACP envelope frame (4-byte big-endian length + JSON): the relay
    reads "to" and forwards the raw bytes to that pid's socket. If the
    target is offline, the relay replies to the sender with a
    length-prefixed CONTROL frame (not an ACP envelope):
      {"relayed": false, "to": <pid>, "error": "offline"}
  * a control frame {"ping": ts} -> replies {"pong": ts}.

Threading: one thread per client (socketserver.ThreadingMixIn);
pid -> socket map is lock-protected; dead clients are removed on
disconnect. A duplicate pid registration closes the older socket.
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

from acp_crypto import ed25519_publickey, ed25519_sign, ed25519_verify
from acp_proto import b62encode, b62decode, canonical

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


# -- server -----------------------------------------------------------

class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(HELLO_TIMEOUT_S)
        try:
            raw = read_frame(self.request)
            hello = json.loads(raw.decode("utf-8"))
            pid = verify_hello(hello)
        except Exception:
            return  # handshake failed: close silently
        self.server.register(pid, self.request)
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

    def dispatch(self, raw):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_control({"relayed": False, "error": "bad_frame"})
            return
        if isinstance(obj, dict) and "ping" in obj:
            self.send_control({"pong": obj["ping"]})
            return
        if isinstance(obj, dict) and "to" in obj and isinstance(obj["to"], str):
            target = obj["to"]
            peer = self.server.lookup(target)
            if peer is None:
                self.send_control({"relayed": False, "to": target,
                                   "error": "offline"})
                return
            try:
                self.server.send_to(peer, raw)
            except OSError:
                self.send_control({"relayed": False, "to": target,
                                   "error": "offline"})
            return
        self.send_control({"relayed": False, "error": "bad_frame"})

    def send_control(self, obj):
        try:
            write_frame(self.request, canonical(obj))
        except OSError:
            pass


class RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address):
        super().__init__(server_address, RelayHandler)
        self._peers = {}          # pid (str) -> socket
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()

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

    def lookup(self, pid):
        with self._lock:
            return self._peers.get(pid)

    def peer_count(self):
        with self._lock:
            return len(self._peers)

    def send_to(self, sock, raw):
        with self._send_lock:
            write_frame(sock, raw)


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

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# -- lifecycle --------------------------------------------------------

def run(host="127.0.0.1", port=9090):
    """Start the relay in a background thread. Returns (server, thread)."""
    server = RelayServer((host, port))
    thread = threading.Thread(target=server.serve_forever,
                              name="acp-relay", daemon=True)
    thread.start()
    return server, thread


def graceful_shutdown(server, thread, timeout=5):
    server.shutdown()
    server.server_close()
    thread.join(timeout)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="acp_relay TCP relay")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9090)
    args = p.parse_args(argv)
    server, thread = run(args.host, args.port)
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
