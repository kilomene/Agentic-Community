"""acp_sdk: the high-level developer SDK for the ACP 1.0 agent network.

This package wraps :class:`acp_connector.Connector` and
:class:`acp_api.client.DirectoryClient` behind one friendly
``AcpClient`` object:

    from acp_sdk import AcpClient

    with AcpClient("~/.acp-alice", "correct-horse") as alice:
        alice.pair_with("127.0.0.1", 9000, approve_callback=lambda code: code)
        alice.send_message(peer_id, "hello world")

Stdlib only. The package works by adding the repo's ``packages`` and
``services`` directories to ``sys.path``; it does not need to be
installed with pip. Set ``PYTHONPATH`` when running outside the repo:

    export PYTHONPATH=/path/to/Agentic-Community/packages:/path/to/Agentic-Community/services

Optional features (groups, voice calls) are imported lazily so the
SDK is fully usable even when those modules are not installed:
calling a missing optional method raises :class:`AcpError` with a
clear message instead of an ``ImportError`` traceback.
"""

import os
import sys

# ---------------------------------------------------------------- path setup
# Make the sibling packages (acp_crypto, acp_proto, acp_connector) and the
# services tree (acp_api client) importable without an install step. This
# is a no-op when they are already importable (e.g. via PYTHONPATH).
_here = os.path.dirname(os.path.abspath(__file__))
_proj_root = os.path.dirname(os.path.dirname(_here))
for _p in (os.path.join(_proj_root, "packages"),
           os.path.join(_proj_root, "services")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from acp_connector import Connector, AcpError  # noqa: E402
from acp_proto import b62encode  # noqa: E402

__all__ = [
    "AcpClient",
    "AcpError",
    "pair",
    "register_in_directory",
    "search_directory",
]


def pair(home, passphrase, host, port, approve_callback, handle=None,
         timeout=120):
    """Pair a fresh agent home with a remote agent in one call.

    ``approve_callback`` receives the 6-character pairing code shown on
    the responder side and must return it verbatim (``lambda:
    input("code: ")`` for interactive use, or a function returning a
    code captured from the responder's ``on_pairing_request`` handler
    in tests). Returns the created :class:`AcpClient` (still open — use
    it as a context manager or call ``close()``).
    """
    client = AcpClient(home, passphrase, handle=handle)
    try:
        client.start_server()
        client.pair_with(host, port, approve_callback, timeout=timeout)
        return client
    except Exception:
        client.close()
        raise


def register_in_directory(client, api_url, handle):
    """Register ``client``'s identity with the directory and return the
    server's response dict. Remembers ``api_url`` on the client for
    later ``search_directory`` calls."""
    return client.directory_register(api_url, handle)


def search_directory(client, handle):
    """Resolve ``handle`` to ``{'handle', 'ipub', 'x_pub'}``. The client
    must have called ``directory_register`` (or been given an API URL)
    first."""
    return client.directory_search(handle)


from .client import AcpClient  # noqa: E402  (re-exported above via __all__)
