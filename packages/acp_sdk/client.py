"""AcpClient: the SDK's main entry point.

One object, one identity: it owns the connector (local agent runtime)
and a small scheduler, talks to a directory when asked, and cleans up
after itself. All network operations run on the connector's reader
threads; callbacks registered via ``on_message`` are invoked from
those threads, so keep them short and thread-safe.
"""
import sys
import threading
import time

from acp_connector import Connector
from acp_proto import AcpError, b62encode

from . import schedule as _schedule


class AcpClient:
    """High-level ACP agent.

    ``AcpClient(home, passphrase, handle=None)`` — ``home`` is the agent
    data directory (created if needed); ``passphrase`` protects the
    identity keys at rest; ``handle`` names a new identity (ignored when
    the home is already initialized).

    Use as a context manager (``with AcpClient(...) as c:``) or call
    ``close()`` explicitly.
    """

    def __init__(self, home, passphrase, handle=None):
        self._connector = _make_connector(home, passphrase, handle)
        self._server = None  # (host, port) once start_server() is called
        self._directory_url = None
        self._directory_api_key = None
        self._scheduler = _schedule.Scheduler()
        self._closed = False
        self._close_lock = threading.Lock()

    # ------------------------------------------------------------- identity
    @property
    def peer_id(self):
        """This agent's peer id (b62-encoded Ed25519 public key)."""
        return self._connector.peer_id

    @property
    def handle(self):
        return self._connector.handle

    @property
    def connector(self):
        """The underlying :class:`acp_connector.Connector` (escape hatch
        for power users; prefer the SDK methods)."""
        return self._connector

    # ------------------------------------------------------------- lifecycle
    def start_server(self, host="127.0.0.1", port=0):
        """Start the TCP listener. Returns the bound ``(host, port)``."""
        actual = self._connector.start_server(host, port)
        self._server = (host, actual)
        return self._server

    @property
    def server_address(self):
        """``(host, port)`` of the listener, or None before
        ``start_server()``."""
        return self._server

    def close(self):
        """Stop the scheduler, the connector and all connections.
        Idempotent."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._scheduler.stop()
        except Exception:
            pass
        try:
            self._connector.stop()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    # ---------------------------------------------------------------- pairing
    def pair_with(self, host, port, approve_callback, timeout=120):
        """Pair with a remote agent at ``(host, port)``.

        This agent is the pairing *initiator*. ``approve_callback``
        is called with no arguments and must return the 6-character
        code shown on the responder side::

            client.pair_with("127.0.0.1", 9000,
                             approve_callback=lambda: input("code: "))

        Returns the peer id of the newly paired agent. Raises
        ``AcpError(PAIRING_FAILED)`` on bad/expired codes.

        The ``approve_callback`` is the human trust step: it is called
        with no arguments once the responder's challenge has arrived,
        and must return the 6-character code shown on the responder's
        side (``lambda: input("code: ")`` for interactive use). In
        automated tests the callback can return a code captured from
        the responder's ``on_pairing_request`` handler.
        """
        session = self._connector.pair_initiate(host, port)
        deadline = time.time() + timeout
        while session.state == "await_challenge" and time.time() < deadline:
            time.sleep(0.1)
        if session.state == "await_challenge":
            raise AcpError("PAIRING_FAILED",
                           "no pair_challenge received within timeout")
        if session.state != "await_code":
            raise AcpError("PAIRING_FAILED",
                           "pairing session left state await_code: %s"
                           % session.state)
        code = approve_callback()
        session.confirm(code)
        deadline = time.time() + timeout
        while session.state not in ("done", "failed") \
                and time.time() < deadline:
            time.sleep(0.1)
        if session.state != "done":
            raise AcpError("PAIRING_FAILED",
                           "pair_welcome not received within timeout")
        return session.peer_pid

    def on_pairing_request(self, cb):
        """Register ``cb(session)`` for inbound pairing requests. See the
        connector's ``PairingSession``: read ``session.code`` to show the
        code, call ``session.accept()`` to approve."""
        self._connector.on_pairing_request(cb)

    def peers(self):
        """List paired peers: ``[{'agent_id', 'handle', 'revoked', ...}]``."""
        return self._connector.list_peers()

    # --------------------------------------------------------------- messages
    def send_message(self, peer_id, text):
        """Send an E2E-encrypted message; blocks until the peer ACKs.
        Returns the message id."""
        return self._connector.send_message(peer_id, text)

    def on_message(self, cb):
        """Register ``cb(sender_pid, text, msg_id)`` for inbound messages."""
        self._connector.on_message(cb)

    def inbox(self, limit=50):
        """Recent messages, newest first, as store rows."""
        return self._connector.store.list_messages(limit=limit)

    # ------------------------------------------------------------------ files
    def send_file(self, peer_id, path):
        """Send a file (E2E chunked transfer). Returns the transfer id."""
        return self._connector.send_file(peer_id, path)

    def on_file_offer(self, cb):
        """Register ``cb(sender_pid, name, size, sha256) -> bool``."""
        self._connector.on_file_offer(cb)

    def accept_files(self, value=True):
        """Set the auto-accept policy for inbound files."""
        self._connector.set_auto_accept_files(value)

    # ----------------------------------------------------------------- groups
    def create_group(self, name, members):
        """Create a group chat. Optional: requires the ``acp_groups``
        module, which is not part of V1. Raises a clear AcpError when it
        is missing."""
        groups = _optional("acp_groups",
                           "group support (create_group) is not installed; "
                           "this is an optional V2+ module")
        return groups.create_group(self._connector, name, members)

    def send_group_message(self, gid, text):
        """Send a message to a group. Optional: requires ``acp_groups``."""
        groups = _optional("acp_groups",
                           "group support (send_group_message) is not "
                           "installed; this is an optional V2+ module")
        return groups.send_group_message(self._connector, gid, text)

    # ------------------------------------------------------------------ voice
    def place_call(self, peer_id, source, sink):
        """Place a voice call. Optional: requires the ``acp_voice``
        module, which is not part of V1. Raises a clear AcpError when it
        is missing."""
        voice = _optional("acp_voice",
                          "voice support (place_call) is not installed; "
                          "this is an optional V2+ module")
        return voice.place_call(self._connector, peer_id, source, sink)

    # --------------------------------------------------------------- schedule
    def schedule_every(self, interval_seconds, fn, *args, **kwargs):
        """Run ``fn(*args, **kwargs)`` every ``interval_seconds`` seconds
        on a background thread. Returns a handle; call ``handle.cancel()``
        to stop. The scheduler is stopped by ``close()``."""
        return self._scheduler.every(interval_seconds, fn, *args, **kwargs)

    def schedule_at(self, when, fn, *args, **kwargs):
        """Run ``fn(*args, **kwargs)`` once at unix timestamp ``when``.
        Returns a handle; ``handle.cancel()`` stops it if pending."""
        return self._scheduler.at(when, fn, *args, **kwargs)

    # --------------------------------------------------------------- directory
    def directory_register(self, api_url, handle=None, api_key=None):
        """Register this agent's handle with the directory at ``api_url``
        and remember the URL (and optional API key) for later
        ``directory_search`` / ``directory_set_presence`` calls.
        Returns the server's response dict.

        ``api_key`` is an operator-issued directory API key; it is only
        needed for key-gated routes such as presence publish.
        """
        from acp_api.client import DirectoryClient
        client = DirectoryClient(api_url.rstrip("/"), api_key=api_key)
        body = client.register(handle or self.handle, self.peer_id,
                               _b62(self._connector.identity.x_pub))
        self._directory_url = api_url.rstrip("/")
        self._directory_api_key = api_key
        return body

    def directory_search(self, handle):
        """Resolve ``handle`` via the remembered directory URL. Raises
        ``AcpError(INTERNAL)`` when no directory is configured."""
        if not self._directory_url:
            raise AcpError("INTERNAL",
                           "no directory configured — call "
                           "directory_register(api_url) first")
        from acp_api.client import DirectoryClient
        return DirectoryClient(self._directory_url,
                               api_key=self._directory_api_key).resolve(handle)

    def directory_set_presence(self, state, handle=None):
        """Publish signed presence to the remembered directory. Needs an
        API key with the ``presence:write`` scope — pass it to
        ``directory_register(api_url, api_key=...)`` first."""
        if not self._directory_url:
            raise AcpError("INTERNAL",
                           "no directory configured — call "
                           "directory_register(api_url) first")
        from acp_api.client import DirectoryClient
        return DirectoryClient(self._directory_url,
                               api_key=self._directory_api_key).set_presence(
            handle or self.handle, state,
            self._connector.identity.ed_priv)

    # --------------------------------------------------------------- misc passthroughs
    def set_presence(self, state):
        self._connector.set_presence(state)

    def get_presence(self, peer_id):
        return self._connector.get_presence(peer_id)

    def grant_permission(self, peer_id, scope):
        return self._connector.grant_permission(peer_id, scope)

    def revoke_peer(self, peer_id, reason="revoked via SDK"):
        return self._connector.revoke_peer(peer_id, reason)

    def audit_log(self, limit=200):
        return self._connector.audit_log(limit=limit)

    def rotate_keys(self):
        self._connector.rotate_keys()


def _make_connector(home, passphrase, handle):
    if handle is None:
        return Connector(home, passphrase)
    return Connector(home, passphrase, handle)


def _b62(raw: bytes) -> str:
    return b62encode(raw)


def _optional(module_name, message):
    try:
        __import__(module_name)
    except ImportError:
        raise AcpError("INTERNAL", message) from None
    return sys.modules[module_name]
