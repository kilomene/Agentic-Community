"""Tests for acp_connector.ws_transport (stdlib-only wss:// client).

Run: python3 -m pytest packages/acp_connector/tests/test_ws_transport.py -q
"""
import base64
import hashlib
import os
import socket
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from acp_proto import AcpError, frame_envelope, parse_frames  # noqa: E402
from acp_connector.ws_transport import (  # noqa: E402
    MAX_FRAME, WsConn, _encode_frame, _parse_wss_url, _proxy_for_wss,
    _ws_handshake, wss_connect,
)

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ------------------------------------------------------- stub-server helpers

def _recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "peer closed"
        buf += chunk
    return buf


def _srv_read_frame(sock):
    """Read one client->server frame; returns ((fin, opcode), payload)."""
    hdr = _recvall(sock, 2)
    b1, b2 = hdr[0], hdr[1]
    assert b2 & 0x80, "client frames must be masked"
    ln = b2 & 0x7F
    if ln == 126:
        ln = int.from_bytes(_recvall(sock, 2), "big")
    elif ln == 127:
        ln = int.from_bytes(_recvall(sock, 8), "big")
    mask = _recvall(sock, 4)
    payload = _recvall(sock, ln)
    return (bool(b1 & 0x80), b1 & 0x0F), \
        bytes(b ^ mask[i & 3] for i, b in enumerate(payload))


def _srv_send_frame(sock, opcode, payload, mask=False):
    """Send one server->server frame (unmasked unless mask=True)."""
    payload = bytes(payload)
    ln = len(payload)
    mbit = 0x80 if mask else 0
    if ln < 126:
        hdr = struct.pack(">BB", 0x80 | opcode, mbit | ln)
    elif ln < 65536:
        hdr = struct.pack(">BBH", 0x80 | opcode, mbit | 126, ln)
    else:
        hdr = struct.pack(">BBQ", 0x80 | opcode, mbit | 127, ln)
    if mask:
        m = os.urandom(4)
        payload = bytes(b ^ m[i & 3] for i, b in enumerate(payload))
        sock.sendall(hdr + m + payload)
    else:
        sock.sendall(hdr + payload)


def _srv_handshake(sock, accept="good", status=101):
    """Read the client handshake; reply. accept: 'good'|'bad'."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        assert chunk, "client closed during handshake"
        buf += chunk
    lines = buf.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    assert lines[0].startswith("GET /acp HTTP/1.1"), lines[0]
    hdrs = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    assert hdrs.get("upgrade") == "websocket"
    assert hdrs.get("connection") == "Upgrade"
    assert hdrs.get("sec-websocket-version") == "13"
    key = hdrs["sec-websocket-key"]
    if status != 101:
        sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        return
    good = base64.b64encode(
        hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()).decode()
    sock.sendall((
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n"
        % (good if accept == "good" else "bogus")) .encode("latin-1"))


def _env(nonce="n1"):
    return {"kind": "msg", "from": "a", "to": "b", "ts": 1,
            "nonce": nonce, "sig": "s", "payload": {"text": "hi"}}


# ------------------------------------------------------------------- tests

def test_url_parsing():
    assert _parse_wss_url("wss://example.com") == ("example.com", 443, "/")
    assert _parse_wss_url("wss://example.com/acp") == \
        ("example.com", 443, "/acp")
    assert _parse_wss_url("wss://example.com:8443/acp/x") == \
        ("example.com", 8443, "/acp/x")
    for bad in ("http://example.com/", "ws://example.com/",
                "wss://", "wss://user@example.com/", "not a url"):
        with pytest.raises(AcpError):
            _parse_wss_url(bad)


def test_wss_connect_rejects_non_wss_without_network():
    with pytest.raises(AcpError):
        wss_connect("http://example.com/")
    with pytest.raises(AcpError):
        wss_connect("ws://example.com/")


def test_handshake_ok():
    a, b = socket.socketpair()
    t = threading.Thread(target=_srv_handshake, args=(b,),
                         kwargs={"accept": "good"})
    t.start()
    rest = _ws_handshake(a, "example.com", 443, "/acp", timeout=5)
    t.join(timeout=5)
    assert not t.is_alive()
    assert rest == b""
    a.close()
    b.close()


def test_handshake_bad_accept_rejected():
    a, b = socket.socketpair()
    t = threading.Thread(target=_srv_handshake, args=(b,),
                         kwargs={"accept": "bad"})
    t.start()
    with pytest.raises(AcpError):
        _ws_handshake(a, "example.com", 443, "/acp", timeout=5)
    t.join(timeout=5)
    a.close()
    b.close()


def test_handshake_non_101_rejected():
    a, b = socket.socketpair()
    t = threading.Thread(target=_srv_handshake, args=(b,),
                         kwargs={"status": 403})
    t.start()
    with pytest.raises(AcpError):
        _ws_handshake(a, "example.com", 443, "/acp", timeout=5)
    t.join(timeout=5)
    a.close()
    b.close()


def test_send_env_roundtrip_masked():
    a, b = socket.socketpair()
    conn = WsConn(a)
    try:
        env = _env()
        conn.send_env(env)
        (fin, opcode), payload = _srv_read_frame(b)
        assert fin and opcode == 0x2
        envs, rest = parse_frames(payload)
        assert rest == b"" and envs == [env]
    finally:
        conn.close()
        b.close()


def test_send_raw_extended_lengths():
    a, b = socket.socketpair()
    conn = WsConn(a)
    try:
        for n in (200, 70000):  # 16-bit and 64-bit length paths
            raw = struct.pack(">I", n) + os.urandom(n)
            conn.send_raw(raw)
            (fin, opcode), payload = _srv_read_frame(b)
            assert fin and opcode == 0x2
            assert payload == raw
    finally:
        conn.close()
        b.close()


def test_send_raw_oversize_rejected():
    a, b = socket.socketpair()
    conn = WsConn(a)
    try:
        with pytest.raises(AcpError):
            conn.send_raw(b"x" * (MAX_FRAME + 5))
    finally:
        conn.close()
        b.close()


def test_send_ping_emits_valid_ping_frame():
    a, b = socket.socketpair()
    conn = WsConn(a)
    try:
        conn.send_ping(b"hb")
        (fin, opcode), payload = _srv_read_frame(b)
        assert fin and opcode == 0x9, "must be a FIN ping frame"
        assert payload == b"hb"
        # oversize payloads are rejected (control frames <= 125 bytes)
        with pytest.raises(AcpError):
            conn.send_ping(b"x" * 126)
    finally:
        conn.close()
        b.close()


def test_ping_pong_and_close():
    a, b = socket.socketpair()
    conn = WsConn(a)
    received = []

    def server():
        _srv_send_frame(b, 0x2, frame_envelope(_env()))
        _srv_send_frame(b, 0x9, b"pingdata")
        (fin, opcode), payload = _srv_read_frame(b)
        assert opcode == 0xA and payload == b"pingdata", \
            "client must auto-reply pong with the ping payload"
        _srv_send_frame(b, 0x8, b"")

    t = threading.Thread(target=server)
    t.start()
    rt = threading.Thread(target=lambda: conn.read_loop(received.append))
    rt.start()
    t.join(timeout=10)
    rt.join(timeout=10)
    assert not t.is_alive() and not rt.is_alive(), "threads hung"
    assert received == [_env()]
    b.close()


def test_masked_server_frame_still_unmasked():
    # Servers should not mask, but a masked server frame must not crash us.
    a, b = socket.socketpair()
    conn = WsConn(a)
    received = []
    env = _env(nonce="n2")
    _srv_send_frame(b, 0x2, frame_envelope(env), mask=True)
    _srv_send_frame(b, 0x8, b"")
    rt = threading.Thread(target=lambda: conn.read_loop(received.append))
    rt.start()
    rt.join(timeout=10)
    assert not rt.is_alive()
    assert received == [env]
    b.close()


def test_close_frame_ends_loop_cleanly():
    a, b = socket.socketpair()
    conn = WsConn(a)
    errors = []
    _srv_send_frame(b, 0x8, b"")
    rt = threading.Thread(
        target=lambda: conn.read_loop(lambda e: None,
                                      lambda c, e: errors.append(e)))
    rt.start()
    rt.join(timeout=10)
    assert not rt.is_alive()
    assert errors == []
    assert conn.closed
    b.close()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


# ------------------------------------------------------- proxy config tests

def _clear_proxy_env(monkeypatch):
    for var in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY",
                "no_proxy", "NO_PROXY"):
        monkeypatch.delenv(var, raising=False)


def test_proxy_for_wss_none_without_env(monkeypatch):
    _clear_proxy_env(monkeypatch)
    assert _proxy_for_wss("example.com") is None


def test_proxy_for_wss_parsing(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("https_proxy", "http://proxy:3128")
    assert _proxy_for_wss("example.com") == ("proxy", 3128, None)
    monkeypatch.setenv("https_proxy", "http://proxy")
    assert _proxy_for_wss("example.com") == ("proxy", 8080, None)
    monkeypatch.setenv("https_proxy", "http://user:pass@proxy:8080")
    host, port, auth = _proxy_for_wss("example.com")
    assert (host, port) == ("proxy", 8080)
    assert auth == "Basic " + base64.b64encode(b"user:pass").decode("ascii")
    # only http:// CONNECT proxies are supported
    monkeypatch.setenv("https_proxy", "socks5://proxy:1080")
    assert _proxy_for_wss("example.com") is None
    # uppercase variant is honored
    monkeypatch.delenv("https_proxy")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy2:3128")
    assert _proxy_for_wss("example.com") == ("proxy2", 3128, None)


def test_proxy_for_wss_no_proxy(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("https_proxy", "http://proxy:3128")
    monkeypatch.setenv("no_proxy", "example.com, .other.org")
    assert _proxy_for_wss("example.com") is None
    assert _proxy_for_wss("sub.other.org") is None
    assert _proxy_for_wss("other.org") is None
    assert _proxy_for_wss("elsewhere.net") == ("proxy", 3128, None)
    monkeypatch.setenv("no_proxy", "*")
    assert _proxy_for_wss("elsewhere.net") is None
