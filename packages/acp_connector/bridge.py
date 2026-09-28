"""Local bridge: fan-out across connectors in one process.

A named registry of Connector instances. send_via(name, peer_pid, text)
sends a message through the named connector. route(kind, payload)
delivers a local event to every registered connector (except an
optional exclusion); each connector applies its own policy/audit in
_on_bridge_route before accepting it.

This is the in-process bridge for co-located agents; cross-machine
bridging goes through the normal ACP transport.
"""
import threading


class Bridge:
    def __init__(self, owner=None):
        self._owner = owner
        self._lock = threading.Lock()
        self._registry = {}  # name -> Connector

    def register(self, name, connector):
        with self._lock:
            self._registry[name] = connector

    def unregister(self, name):
        with self._lock:
            self._registry.pop(name, None)

    def names(self):
        with self._lock:
            return sorted(self._registry)

    def send_via(self, name, peer_pid, text):
        """Send a direct message through the named connector."""
        with self._lock:
            target = self._registry.get(name)
        if target is None:
            from acp_proto import AcpError
            raise AcpError("NOT_FOUND", f"no bridge connector {name!r}")
        return target.send_message(peer_pid, text)

    def route(self, kind, payload, exclude=None):
        """Fan a local event out to every registered connector.

        Returns {name: accepted_bool}. Each connector's own policy
        decides acceptance (per-connector policy passthrough).
        """
        with self._lock:
            targets = [(n, c) for n, c in self._registry.items()
                       if n != exclude]
        results = {}
        for name, connector in targets:
            try:
                results[name] = bool(
                    connector._on_bridge_route(kind, payload, self._owner))
            except Exception:
                results[name] = False
        return results
