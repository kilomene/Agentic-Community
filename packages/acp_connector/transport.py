"""TCP transport for ACP 1.0.

Length-prefixed frames (4-byte big-endian + JSON) via
acp_proto.frame_envelope / parse_frames. Handles partial reads by
accumulating a buffer and parsing whole frames only.

PROTOCOL.md section 4: max frame size is 4 MiB; a larger declared frame
drops the connection with ERROR(OVERSIZED).
"""
import socket
import threading

from acp_proto import AcpError, frame_envelope, parse_frames

MAX_FRAME = 4 * 1024 * 1024


class Conn:
    """One TCP connection (either direction). Thread-safe sends."""

    def __init__(self, sock):
        self._sock = sock
        self._send_lock = threading.Lock()
        self._closed = False
        try:
            self.peer_addr = sock.getpeername()
        except OSError:
            self.peer_addr = None

    @property
    def closed(self):
        return self._closed

    def send_env(self, env):
        """Serialize and send one envelope. Raises on transport failure."""
        frame = frame_envelope(env)  # may raise AcpError (oversize)
        with self._send_lock:
            if self._closed:
                raise AcpError("INTERNAL", "connection closed")
            try:
                self._sock.sendall(frame)
            except OSError as e:
                self._closed = True
                raise AcpError("INTERNAL", f"send failed: {e}")

    def read_loop(self, on_envelope, on_error=None):
        """Block reading frames until EOF/error. Never raises."""
        buf = b""
        try:
            while not self._closed:
                try:
                    chunk = self._sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 4:
                    declared = int.from_bytes(buf[:4], "big")
                    if declared > MAX_FRAME:
                        raise AcpError("OVERSIZED",
                                       f"frame declares {declared} bytes")
                if len(buf) > MAX_FRAME + 1024 * 1024:
                    raise AcpError("OVERSIZED",
                                   "no complete frame within size budget")
                try:
                    envs, buf = parse_frames(buf)
                except AcpError as e:
                    raise AcpError("BAD_ENVELOPE",
                                   f"frame parse failed: {e.detail}")
                for env in envs:
                    on_envelope(env)
        except AcpError as e:
            if on_error is not None:
                try:
                    on_error(self, e)
                except Exception:
                    pass
        finally:
            self.close()

    def close(self):
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


class TcpTransport:
    """Listening server + outbound dialer."""

    def __init__(self):
        self._server_sock = None
        self._accept_thread = None
        self._running = False
        self._lock = threading.Lock()

    def start_server(self, host, port, on_accept):
        """Listen; spawn accept thread. Returns the actual bound port."""
        with self._lock:
            if self._running:
                raise AcpError("INTERNAL", "server already running")
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(32)
            actual = srv.getsockname()[1]
            self._server_sock = srv
            self._running = True

            def _accept():
                while self._running:
                    try:
                        client, _ = srv.accept()
                    except OSError:
                        break
                    try:
                        on_accept(Conn(client))
                    except Exception:
                        try:
                            client.close()
                        except OSError:
                            pass

            t = threading.Thread(target=_accept, daemon=True,
                                 name="acp-accept")
            t.start()
            self._accept_thread = t
            return actual

    def connect(self, host, port, timeout=10):
        """Dial out; returns a Conn. Raises AcpError on failure."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            raise AcpError("INTERNAL", f"connect {host}:{port} failed: {e}")
        # create_connection leaves the connect timeout on the socket;
        # the data path must not time out on idle.
        sock.settimeout(None)
        return Conn(sock)

    def stop(self):
        with self._lock:
            self._running = False
            if self._server_sock is not None:
                try:
                    self._server_sock.close()
                except OSError:
                    pass
                self._server_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
            self._accept_thread = None
