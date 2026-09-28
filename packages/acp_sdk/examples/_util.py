"""Shared helpers for the acp_sdk examples (not part of the SDK API)."""
import threading


def pair(initiator, responder, timeout=120):
    """Pair initiator -> responder via the SDK. Returns the responder's
    peer id. The responder auto-accepts; the initiator's
    approve_callback echoes the code the responder showed (same
    process, so this is just plumbing — a real deployment shows the
    code to a human)."""
    code_box = {}
    arrived = threading.Event()
    responder.on_pairing_request(
        lambda s: (code_box.setdefault("code", s.code),
                   s.accept(), arrived.set()))
    host, port = responder.server_address
    peer_id = initiator.pair_with(
        host, port,
        approve_callback=lambda: _wait_code(code_box, arrived),
        timeout=timeout)
    assert peer_id == responder.peer_id, "paired with the wrong peer"
    return peer_id


def _wait_code(code_box, arrived):
    assert arrived.wait(30), "responder never sent a pairing code"
    return code_box["code"]


def retry(fn, attempts=3, label="operation"):
    """Run fn(); on exception, retry with fresh state up to
    ``attempts`` times, then re-raise the last error.

    This exists because of a pre-existing V1 bug (see
    acp_sdk/README.md "Known issues"): acp_proto's plain b62
    encode/decode drops leading zero bytes, so ~0.8% of E2E envelopes
    fail decrypt/verify at random. Retrying with fresh random
    envelopes rides through it; it is not a substitute for the real
    V1 fix.
    """
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - bounded retry, then raise
            last = e
            print("%s attempt %d/%d failed: %s"
                  % (label, i + 1, attempts, e))
    raise last
