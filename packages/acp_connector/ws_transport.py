"""WebSocket (RFC 6455) client transport for ACP 1.0 — stdlib only.

Wire convention (must match the Cloudflare Worker relay): each WebSocket
binary message carries exactly one ACP frame: 4-byte big-endian length +
JSON bytes. Control frames are length-prefixed JSON without envelope
shape.

Client-to-server frames are always masked (RFC 6455 §5.3); server
frames are expected unmasked, but a masked server frame is still
unmasked correctly rather than crashing.

Interface mirrors transport.Conn: ``send_env(env)``, ``send_raw(bytes)``,
``read_loop(on_envelope, on_error=None)`` (never raises), ``close()``,
``.closed``, ``.peer_addr``.
"""
import base64
import hashlib
import os
import socket
import ssl
import struct
import threading

from acp_proto import AcpError, frame_envelope, parse_frames

MAX_FRAME = 4 * 1024 * 1024  # protocol §4: 4 MiB frame cap
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _PeerClosed(Exception):
    """Internal: the peer closed the connection (EOF / socket error)."""


# ---------------------------------------------------------------- URL parsing

def _parse_wss_url(url):
    """Parse wss://host[:port][/path]. Returns (host, port, path)."""
    if not isinstance(url, str) or not url.startswith("wss://"):
        raise AcpError("INTERNAL", "relay url must start with wss://")
    rest = url[len("wss://"):]
    if "/" in rest:
        authority, path = rest.split("/", 1)
        path = "/" + path
    else:
        authority, path = rest, "/"
    if not authority or "@" in authority:
        raise AcpError("INTERNAL", "bad wss url: %r" % url)
    # host[:port], with minimal [ipv6] support
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise AcpError("INTERNAL", "bad wss url: %r" % url)
        host = authority[1:end]
        tail = authority[end + 1:]
        port = int(tail[1:]) if tail.startswith(":") else 443
    elif authority.count(":") == 1:
        host, port_s = authority.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            raise AcpError("INTERNAL", "bad wss url port: %r" % url)
    else:
        host, port = authority, 443
    if not host or not (0 < port < 65536):
        raise AcpError("INTERNAL", "bad wss url: %r" % url)
    return host, port, path


# ---------------------------------------------------------------- handshake

def _read_until(sock, marker, limit, timeout_note="handshake"):
    """Read until marker appears. Returns (head, leftover)."""
    buf = b""
    while marker not in buf:
        if len(buf) > limit:
            raise AcpError("INTERNAL",
                           "%s response too large" % timeout_note)
        try:
            chunk = sock.recv(4096)
        except (OSError, ssl.SSLError) as e:
            raise AcpError("INTERNAL",
                           "%s read failed: %s" % (timeout_note, e))
        if not chunk:
            raise AcpError("INTERNAL",
                           "server closed during %s" % timeout_note)
        buf += chunk
    head, _, rest = buf.partition(marker)
    return head, rest


def _parse_http_response(head):
    """Parse an HTTP response head. Returns (status:int, headers:dict)."""
    try:
        text = head.decode("latin-1")
    except UnicodeDecodeError:
        raise AcpError("INTERNAL", "bad handshake response encoding")
    lines = text.split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise AcpError("INTERNAL", "bad handshake response line")
    try:
        status = int(parts[1])
    except ValueError:
        raise AcpError("INTERNAL", "bad handshake status")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def _ws_handshake(sock, host, port, path, timeout=10):
    """Run the client opening handshake on a connected socket.

    Returns leftover bytes read past the response head (normally empty).
    Raises AcpError on any failure. Exposed for testing over socketpair.
    """
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    host_hdr = host if port == 443 else "%s:%d" % (host, port)
    request = (
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n" % (path, host_hdr, key)
    )
    try:
        sock.sendall(request.encode("latin-1"))
    except (OSError, ssl.SSLError) as e:
        raise AcpError("INTERNAL", "handshake send failed: %s" % e)
    head, rest = _read_until(sock, b"\r\n\r\n", 16384)
    status, headers = _parse_http_response(head)
    if status != 101:
        raise AcpError("INTERNAL",
                       "websocket upgrade rejected: HTTP %d" % status)
    expected = base64.b64encode(
        hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
    ).decode("ascii")
    accept = headers.get("sec-websocket-accept")
    if accept != expected:
        raise AcpError("INTERNAL",
                       "bad Sec-WebSocket-Accept in handshake")
    return rest


def _proxy_for_wss(host):
    """Return (proxy_host, proxy_port, proxy_auth_header) for wss egress,
    or None when no proxy applies. Honors https_proxy/HTTPS_PROXY and
    no_proxy/NO_PROXY. Only http:// proxies (HTTP CONNECT) are supported.
    """
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if not proxy:
        return None
    no_proxy = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    hl = host.lower()
    for entry in no_proxy.split(","):
        e = entry.strip().lower().lstrip(".")
        if not e:
            continue
        if e == "*" or hl == e or hl.endswith("." + e):
            return None
    # minimal proxy-URL parse: scheme://[user:pass@]host[:port]
    rest = proxy
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        if scheme.lower() not in ("http",):
            return None
    if "@" in rest:
        userinfo, rest = rest.rsplit("@", 1)
    else:
        userinfo = None
    if ":" in rest and not rest.startswith("["):
        phost, port_s = rest.rsplit(":", 1)
        try:
            pport = int(port_s)
        except ValueError:
            return None
    else:
        phost, pport = rest, 8080
    if not phost:
        return None
    auth = None
    if userinfo:
        auth = "Basic " + base64.b64encode(
            userinfo.encode("utf-8")).decode("ascii")
    return (phost, pport, auth)


def _read_head_exact(sock, timeout):
    """Read an HTTP response head byte-by-byte (no over-read past
    the header terminator). Returns (status, headers)."""
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            raise AcpError("INTERNAL", "proxy closed during CONNECT")
        buf += chunk
        if len(buf) > 16384:
            raise AcpError("INTERNAL", "proxy response head too large")
    return _parse_http_response(buf)


def _connect_wss_socket(host, port, timeout):
    """TCP-connect for a wss target, via HTTP CONNECT proxy when the
    environment routes egress through one. Returns a plain TCP socket
    ready for the TLS handshake."""
    via = _proxy_for_wss(host)
    if via is None:
        return socket.create_connection((host, port), timeout=timeout)
    phost, pport, auth = via
    sock = socket.create_connection((phost, pport), timeout=timeout)
    try:
        req = ("CONNECT %s:%d HTTP/1.1\r\n"
               "Host: %s:%d\r\n" % (host, port, host, port))
        if auth:
            req += "Proxy-Authorization: %s\r\n" % auth
        req += "\r\n"
        sock.sendall(req.encode("latin-1"))
        status, _headers = _read_head_exact(sock, timeout)
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
    if status != 200:
        try:
            sock.close()
        except OSError:
            pass
        raise AcpError("INTERNAL",
                       "proxy CONNECT %s:%d rejected: HTTP %d"
                       % (host, port, status))
    return sock


def wss_connect(url, timeout=10):
    """Connect to a wss:// URL and complete the WS handshake.

    TLS uses the default context: SNI + certificate verification ON.
    Egress proxies are honored: when https_proxy/HTTPS_PROXY is set (and
    the host is not in no_proxy), the TCP connection goes through an
    HTTP CONNECT tunnel first. Returns a WsConn. Raises AcpError on any
    failure.
    """
    host, port, path = _parse_wss_url(url)
    sock = None
    try:
        raw = _connect_wss_socket(host, port, timeout)
        raw.settimeout(timeout)
        ctx = ssl.create_default_context()
        try:
            sock = ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            try:
                raw.close()
            except OSError:
                pass
            raise
        rest = _ws_handshake(sock, host, port, path, timeout=timeout)
        sock.settimeout(None)
        conn = WsConn(sock, initial=rest)
        sock = None  # ownership transferred to the WsConn
        return conn
    except AcpError:
        raise
    except (OSError, ssl.SSLError) as e:
        raise AcpError("INTERNAL", "wss connect %s:%d failed: %s"
                       % (host, port, e))
    finally:
        if sock is not None:
            try:
                sock.close()
            except (OSError, ssl.SSLError):
                pass


# ---------------------------------------------------------------- framing

def _encode_frame(opcode, payload):
    """Encode one client->server frame: FIN set, masked (RFC 6455 §5.3)."""
    payload = bytes(payload)
    ln = len(payload)
    mask = os.urandom(4)
    if ln < 126:
        hdr = struct.pack(">BB", 0x80 | opcode, 0x80 | ln)
    elif ln < 65536:
        hdr = struct.pack(">BBH", 0x80 | opcode, 0x80 | 126, ln)
    else:
        hdr = struct.pack(">BBQ", 0x80 | opcode, 0x80 | 127, ln)
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return hdr + mask + masked


class WsConn:
    """One WebSocket client connection. Thread-safe sends."""

    def __init__(self, sock, initial=b""):
        self._sock = sock
        self._send_lock = threading.Lock()
        self._closed = False
        self._buf = bytearray(initial)
        self.peer_addr = None

    @property
    def closed(self):
        return self._closed

    # ------------------------------------------------------------------ send
    def _send_frame_bytes(self, data):
        with self._send_lock:
            if self._closed:
                raise AcpError("INTERNAL", "connection closed")
            try:
                self._sock.sendall(data)
            except (OSError, ssl.SSLError) as e:
                self._closed = True
                raise AcpError("INTERNAL", "send failed: %s" % e)

    def send_env(self, env):
        """Serialize and send one envelope as a single masked binary
        frame. Raises AcpError on failure (marks closed on transport
        failure)."""
        self.send_raw(frame_envelope(env))  # may raise AcpError (oversize)

    def send_raw(self, frame_bytes):
        """Send already-framed bytes (4-byte BE length + JSON) as one
        masked binary frame. Raises AcpError on failure."""
        raw = bytes(frame_bytes)
        if len(raw) > MAX_FRAME + 4:
            raise AcpError("BAD_ENVELOPE", "frame too large")
        self._send_frame_bytes(_encode_frame(0x2, raw))

    def _send_pong(self, payload):
        # Control frames carry at most 125 bytes (RFC 6455 §5.5).
        try:
            self._send_frame_bytes(_encode_frame(0xA, bytes(payload)[:125]))
        except AcpError:
            pass  # best effort; the read loop will notice a dead socket

    def send_ping(self, payload=b""):
        """Send a WebSocket ping frame (keepalive). The peer's runtime
        answers with a pong automatically. Raises AcpError on failure
        and marks the connection closed, like any other send."""
        payload = bytes(payload or b"")
        if len(payload) > 125:  # control frames carry at most 125 bytes
            raise AcpError("BAD_ENVELOPE", "ping payload too large")
        self._send_frame_bytes(_encode_frame(0x9, payload))

    # ------------------------------------------------------------------ read
    def _read_exactly(self, n):
        while len(self._buf) < n:
            try:
                chunk = self._sock.recv(65536)
            except (OSError, ssl.SSLError):
                raise _PeerClosed()
            if not chunk:
                raise _PeerClosed()
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _read_frame(self):
        """Read one WS frame. Returns (opcode, payload bytes)."""
        hdr = self._read_exactly(2)
        b1, b2 = hdr[0], hdr[1]
        if b1 & 0x70:
            raise AcpError("BAD_ENVELOPE", "ws rsv bits set")
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        ln = b2 & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._read_exactly(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self._read_exactly(8), "big")
            if ln >> 63:
                raise AcpError("BAD_ENVELOPE", "bad ws 64-bit length")
        if ln > MAX_FRAME:
            raise AcpError("OVERSIZED", "ws frame declares %d bytes" % ln)
        mask = self._read_exactly(4) if masked else None
        payload = self._read_exactly(ln)
        if mask is not None:
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        if not fin:
            raise AcpError("BAD_ENVELOPE",
                           "fragmented ws frames not supported")
        return opcode, payload

    def read_loop(self, on_envelope, on_error=None):
        """Block reading WS binary frames until close/error. Never raises.

        Ping (0x9) is answered automatically; pong (0xA) ignored; close
        (0x8) ends the loop. Each binary (0x2) payload must be exactly
        one ACP frame (4-byte BE length + JSON).
        """
        try:
            while not self._closed:
                try:
                    opcode, payload = self._read_frame()
                except _PeerClosed:
                    break
                if opcode == 0x8:  # close
                    break
                elif opcode == 0x9:  # ping
                    self._send_pong(payload)
                elif opcode == 0xA:  # pong
                    continue
                elif opcode == 0x2:  # binary: one ACP frame
                    try:
                        envs, rest = parse_frames(payload)
                    except AcpError as e:
                        raise AcpError("BAD_ENVELOPE",
                                       "frame parse failed: %s" % e.detail)
                    if rest:
                        raise AcpError("BAD_ENVELOPE",
                                       "trailing bytes after frame")
                    for env in envs:
                        on_envelope(env)
                else:
                    raise AcpError("BAD_ENVELOPE",
                                   "unexpected ws opcode %#x" % opcode)
        except AcpError as e:
            if on_error is not None:
                try:
                    on_error(self, e)
                except Exception:
                    pass
        finally:
            self.close()

    # ----------------------------------------------------------------- close
    def close(self):
        try:
            with self._send_lock:
                if not self._closed:
                    try:
                        self._sock.sendall(_encode_frame(0x8, b""))
                    except (OSError, ssl.SSLError):
                        pass
        finally:
            self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except (OSError, ssl.SSLError):
            pass
        try:
            self._sock.close()
        except (OSError, ssl.SSLError):
            pass
