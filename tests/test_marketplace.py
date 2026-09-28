"""Marketplace tests: real publish/sign/verify/install, real offer/escrow
protocol over ACP between paired connectors, plus attack tests.

Run: python3 -m pytest tests/test_marketplace.py -q
"""
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_connector import Connector, AcpError
from acp_proto import make_envelope
from acp_marketplace import Marketplace, MARKET_OFFER, MARKET_OFFER_ACCEPT, \
    MARKET_ESCROW_RELEASE
from acp_marketplace.manifest import (build_manifest, sign_manifest,
                                      verify_manifest, _check_path)
from acp_marketplace.payments import NullAdapter, PaymentAdapter
from acp_crypto import generate_ed25519_keypair

def case(name):
    def deco(fn):
        fn._name = name
        return fn
    return deco


def expect_acp_error(fn, code):
    try:
        fn()
    except AcpError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e.detail}"
        return e
    raise AssertionError(f"expected AcpError({code}), no error raised")


def audit_details(entry):
    """audit_log() returns details as a JSON string; parse it."""
    d = entry["details"]
    if isinstance(d, str):
        try:
            return json.loads(d)
        except ValueError:
            return {}
    return d or {}


def wait_for_audit(conn, action, code=None, timeout=15):
    """Wait until an audit entry (action[, details.code]) appears."""
    def check():
        for e in conn.audit_log(limit=100):
            if e["action"] != action:
                continue
            if code is None or audit_details(e).get("code") == code:
                return True
        return False
    return wait_until(check, timeout=timeout,
                      what=f"audit {action} {code}")


def make_pkg_dir():
    d = tempfile.mkdtemp(prefix="mkt-pkg-")
    with open(os.path.join(d, "main.py"), "w") as f:
        f.write("print('hello from capability')\n")
    with open(os.path.join(d, "util.py"), "w") as f:
        f.write("X = 42\n")
    return d


def pair(a, b, timeout=45):
    """Pair connector a -> b, return when both sides trust each other."""
    port_b = b._server_port
    for attempt in (1, 2):
        sessions = []
        ev = threading.Event()
        b.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
        s1 = a.pair_initiate("127.0.0.1", port_b)
        if ev.wait(timeout):
            break
        if attempt == 2:
            raise AssertionError("no pairing request arrived")
    s2 = sessions[0]
    assert s2.code and len(s2.code) == 6, f"bad code: {s2.code!r}"
    s2.accept()
    wait_until(lambda: s1.state == "await_code", what="await_code",
               timeout=timeout)
    s1.confirm(s2.code)
    wait_until(lambda: b.store.get_peer(a.peer_id) is not None,
               what="b trusts a", timeout=timeout)
    wait_until(lambda: a.store.get_peer(b.peer_id) is not None,
               what="a trusts b", timeout=timeout)


def wait_until(fn, timeout=45, interval=0.2, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(interval)
    raise AssertionError(f"timeout waiting for {what}")


# Module-level state, initialized by setup() at RUN time (never at
# import/collection time: pytest imports every test module before
# running any of them, and pairing three connectors at collection
# starves under that load).
c1 = c2 = c3 = m1 = m2 = m3 = None
PKG = None
SVC_LISTING = None


def setup():
    global c1, c2, c3, m1, m2, m3, PKG, SVC_LISTING
    if c1 is not None:
        return
    home1 = tempfile.mkdtemp(prefix="mkt-c1-")
    home2 = tempfile.mkdtemp(prefix="mkt-c2-")
    home3 = tempfile.mkdtemp(prefix="mkt-c3-")
    c1 = Connector(home1, "mkt-pass-one", handle="seller")
    c2 = Connector(home2, "mkt-pass-two", handle="buyer")
    c3 = Connector(home3, "mkt-pass-three", handle="arbiter")
    c1.start_server("127.0.0.1", 0)
    c2.start_server("127.0.0.1", 0)
    c3.start_server("127.0.0.1", 0)
    print(f"paired setup: c1={c1.peer_id[:12]} c2={c2.peer_id[:12]}"
          f" c3={c3.peer_id[:12]}", flush=True)
    pair(c1, c2)
    pair(c1, c3)
    pair(c2, c3)
    print("all paired", flush=True)
    m1 = Marketplace(c1)
    m2 = Marketplace(c2)
    m3 = Marketplace(c3)
    PKG = make_pkg_dir()
    SVC_LISTING = t_services()


def teardown():
    for c in (c1, c2, c3):
        try:
            c.stop()
        except Exception:
            pass


# ---------------------------------------------------------------- packages
@case("publish signs manifest; get_package returns it")
def t_publish():
    man = m1.publish_package(PKG, "summarizer", "1.0.0",
                             "Summarizes long text",
                             ["summarize", "nlp"], "main.py")
    assert man["sig"], "manifest not signed"
    assert man["publisher_id"] == c1.peer_id
    assert len(man["files"]) == 2
    got = m1.get_package("summarizer")
    assert got["sig"] == man["sig"]
    # served over the wire too
    resp = m2.request_listings(c1.peer_id, query="summar")
    names = [l["name"] for l in resp["listings"] if l["type"] == "package"]
    assert "summarizer" in names, resp["listings"]
    json.dumps(resp)  # listings are JSON-serializable


@case("install verifies sig + sha256, quarantines, never executes")
def t_install():
    receipt = m2.install_package("summarizer", from_peer=c1.peer_id,
                                 approve=True)
    assert os.path.isdir(receipt["installed"])
    assert receipt["files"] == 2
    with open(os.path.join(receipt["installed"], "main.py")) as f:
        assert "hello from capability" in f.read()
    # quarantine dir is cleaned up
    assert not os.path.exists(os.path.join(
        m2.quarantine_dir, "summarizer-1.0.0"))
    # audit event recorded
    evs = c2.audit_log(limit=50)
    assert any(e["action"] == "marketplace.package.installed"
               for e in evs), "no install audit event"
    # manifest.json rides along
    assert os.path.isfile(os.path.join(receipt["installed"],
                                       "manifest.json"))


@case("install without explicit approval is POLICY_DENIED")
def t_install_policy():
    m2.set_install_policy("manual")
    expect_acp_error(
        lambda: m2.install_package("summarizer", from_peer=c1.peer_id),
        "POLICY_DENIED")


@case("tampered package file -> install refused (sha256 mismatch)")
def t_tamper_file():
    man = m1.publish_package(PKG, "tamperme", "1.0.0", "t", ["t"], "main.py")
    pkgdir = os.path.join(m1.packages_dir, "tamperme-1.0.0")
    with open(os.path.join(pkgdir, "main.py"), "wb") as f:
        f.write(b"print('EVIL')\n")
    expect_acp_error(
        lambda: m2.install_package("tamperme", from_peer=c1.peer_id,
                                   approve=True),
        "FILE_HASH_MISMATCH")


@case("forged publisher sig -> install refused")
def t_forged_sig():
    man = m1.publish_package(PKG, "forgeme", "1.0.0", "f", ["f"], "main.py")
    bad = dict(man)
    bad["description"] = "forged description"
    # keep the original sig -> signature no longer matches
    m2.store.add_package("forgeme", "1.0.0", json.dumps(bad),
                         c1.peer_id)
    expect_acp_error(
        lambda: m2.install_package("forgeme", approve=True),
        "INVALID_SIG")


@case("path traversal in package file paths -> refused")
def t_path_traversal():
    unsigned = build_manifest(PKG, "trav", "1.0.0", "t", ["t"], "main.py",
                              c1.peer_id)
    unsigned["files"].append({"path": "../../evil.sh",
                              "sha256": "0" * 64})
    evil = sign_manifest(unsigned, c1.identity.ed_priv)
    # verify_manifest rejects it outright
    expect_acp_error(lambda: verify_manifest(evil, c1._get_pubkey),
                     "FILE_REJECTED")
    # and the low-level checker agrees on every hostile shape
    for hostile in ["../../evil", "/abs/path", "a\x00b", "..\\win"]:
        try:
            _check_path(hostile)
        except AcpError as e:
            assert e.code == "FILE_REJECTED", e.code
        else:
            raise AssertionError(f"{hostile!r} not rejected")


@case("service listings publish, sign, and serve over market_list")
def t_services():
    listing = m1.publish_service("Nightly data scrape",
                                 "I scrape public datasets nightly",
                                 ["scrape", "datasets"],
                                 price_model="negotiable",
                                 terms="delivery within 24h")
    assert listing["sig"]
    m1.verify_service_sig(listing)
    resp = m2.request_listings(c1.peer_id, capability="scrape")
    svcs = [l for l in resp["listings"] if l["type"] == "service"]
    assert any(s["listing_id"] == listing["listing_id"] for s in svcs), resp
    found = m1.search_services("scrape")
    assert found and found[0]["listing_id"] == listing["listing_id"], \
        "local search found nothing"
    return listing


# ------------------------------------------------------------ transactions
def full_offer_flow():
    """offer -> accept -> escrow_hold; returns (offer_id, hold_id)."""
    offer_id = m2.make_offer(c1.peer_id, SVC_LISTING["listing_id"],
                             {"price_cents": 500, "currency": "USD"})
    wait_until(lambda: m1.get_offer(offer_id) is not None,
               what="seller sees offer")
    assert m1.get_offer(offer_id)["state"] == "offered"
    m1.accept_offer(offer_id)
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "accepted",
               what="buyer sees accept")
    hold_id = m2.escrow_hold(offer_id, 500, "USD", adapter_name="null")
    wait_until(lambda: m1.get_offer(offer_id)["state"] == "escrow_held",
               what="seller sees escrow_held")
    return offer_id, hold_id


@case("offer -> accept -> escrow_hold -> release (happy path)")
def t_happy_path():
    offer_id, hold_id = full_offer_flow()
    assert m2.get_offer(offer_id)["state"] == "escrow_held"
    st = m2.get_adapter("null").get_status(hold_id)
    assert st["state"] == "held" and st["amount_cents"] == 500
    m1.escrow_release(offer_id)  # seller releases after delivery
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "released",
               what="buyer sees released")
    assert m2.get_offer(offer_id)["state"] == "released"
    st = m1.get_adapter("null").get_status(hold_id)
    assert st["state"] == "released"


@case("escrow double-release -> second fails ALREADY_SETTLED")
def t_double_release():
    offer_id, hold_id = full_offer_flow()
    m1.escrow_release(offer_id)
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "released",
               what="released")
    # local second release fails loudly...
    expect_acp_error(lambda: m1.escrow_release(offer_id),
                     "ALREADY_SETTLED")
    # ...and the adapter itself refuses to double-apply
    expect_acp_error(
        lambda: m1.get_adapter("null").release_hold(hold_id),
        "ALREADY_SETTLED")
    # adapter state unchanged
    st = m1.get_adapter("null").get_status(hold_id)
    assert st["state"] == "released"
    # duplicate release arriving over the wire is dropped, not applied
    m1._c._send_e2e(MARKET_ESCROW_RELEASE, c2.peer_id,
                     {"offer_id": offer_id, "hold_id": hold_id,
                      "adapter": "null", "amount_cents": 500,
                      "currency": "USD"})
    time.sleep(1.0)
    assert m2.get_offer(offer_id)["state"] == "released"


@case("escrow cancel path settles to cancelled")
def t_cancel():
    offer_id, hold_id = full_offer_flow()
    m2.escrow_cancel(offer_id, reason="buyer changed mind")
    wait_until(lambda: m1.get_offer(offer_id)["state"] == "cancelled",
               what="seller sees cancelled")
    st = m2.get_adapter("null").get_status(hold_id)
    assert st["state"] == "cancelled"
    expect_acp_error(lambda: m2.escrow_cancel(offer_id, reason="x"),
                     "ALREADY_SETTLED")


@case("decline path settles to declined")
def t_decline():
    offer_id = m2.make_offer(c1.peer_id, SVC_LISTING["listing_id"],
                             {"price_cents": 1, "currency": "USD"})
    wait_until(lambda: m1.get_offer(offer_id) is not None,
               what="seller sees offer")
    m1.decline_offer(offer_id, reason="too cheap")
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "declined",
               what="buyer sees declined")


@case("dispute: open from escrow_held, arbiter resolves to refund")
def t_dispute():
    offer_id, hold_id = full_offer_flow()
    m2.open_dispute(offer_id, claim="deliverable did not match terms")
    wait_until(lambda: m1.get_offer(offer_id)["state"] == "disputed",
               what="seller sees disputed")
    # third-party arbiter resolves for both parties
    m3.resolve_dispute(offer_id, "refund",
                       peers=[c1.peer_id, c2.peer_id])
    wait_until(lambda: m1.get_offer(offer_id)["state"] == "cancelled",
               what="seller sees refund")
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "cancelled",
               what="buyer sees refund")
    st = m2.get_adapter("null").get_status(hold_id)
    assert st["state"] == "cancelled"


@case("forged market_offer signature -> rejected, never recorded")
def t_forged_offer():
    evil_priv, _evil_pub = generate_ed25519_keypair()
    payload = {"offer_id": "f" * 32, "listing_id": SVC_LISTING["listing_id"],
               "terms": {"price_cents": 1}, "ts": int(time.time())}
    # signed by an unknown key but claiming to be c1 -> INVALID_SIG
    env = make_envelope(MARKET_OFFER, c1.peer_id, c2.peer_id, payload,
                        evil_priv)
    c1._get_conn(c2.peer_id).send_env(env)
    wait_for_audit(c2, "envelope.rejected", code="INVALID_SIG")
    assert m2.get_offer("f" * 32) is None, "forged offer was recorded!"


@case("release by non-party -> rejected (POLICY_DENIED)")
def t_nonparty_release():
    offer_id, _hold = full_offer_flow()
    # c3 (arbiter) is not a party to this offer: hand-craft a release
    # from the non-party over the wire.
    from acp_proto import make_e2e_envelope
    peer = c3.store.get_peer(c2.peer_id)
    env = make_e2e_envelope(
        MARKET_ESCROW_RELEASE, c3.peer_id, c2.peer_id,
        {"offer_id": offer_id, "hold_id": "x" * 32, "adapter": "null",
         "amount_cents": 500, "currency": "USD"},
        c3.identity.ed_priv, c3.identity.x_priv, c3.identity.x_pub,
        bytes.fromhex(peer["x_pub"]))
    c3._get_conn(c2.peer_id).send_env(env)
    wait_for_audit(c2, "envelope.rejected", code="POLICY_DENIED")
    # offer untouched: still escrow_held
    assert m2.get_offer(offer_id)["state"] == "escrow_held", \
        m2.get_offer(offer_id)["state"]


@case("replayed market_offer_accept -> dropped, no state change")
def t_replay_accept():
    offer_id = m2.make_offer(c1.peer_id, SVC_LISTING["listing_id"],
                             {"price_cents": 9, "currency": "USD"})
    wait_until(lambda: m1.get_offer(offer_id) is not None,
               what="seller sees offer")
    m1.accept_offer(offer_id)
    wait_until(lambda: m2.get_offer(offer_id)["state"] == "accepted",
               what="buyer sees accept")
    # fresh-nonce replay of the accept (connector replay cache only
    # catches identical nonces)
    c1._send_e2e(MARKET_OFFER_ACCEPT, c2.peer_id, {"offer_id": offer_id})
    wait_for_audit(c2, "marketplace.offer.accept_replay")
    assert m2.get_offer(offer_id)["state"] == "accepted"


@case("NullAdapter: idempotent create, honest no-money bookkeeping")
def t_null_adapter():
    ad = NullAdapter(m2.store)
    assert isinstance(ad, PaymentAdapter)
    h1 = ad.create_hold("offer-abc", 100, "USD")
    h2 = ad.create_hold("offer-abc", 100, "USD")
    assert h1 == h2, "create_hold not idempotent"
    assert ad.get_status(h1)["state"] == "held"
    ad.release_hold(h1)
    expect_acp_error(lambda: ad.release_hold(h1), "ALREADY_SETTLED")
    expect_acp_error(lambda: ad.cancel_hold(h1), "ALREADY_SETTLED")
    # docstrings say the honest part out loud
    assert "moves no money" in (NullAdapter.create_hold.__doc__ or "").lower()
    assert "no money" in (NullAdapter.__doc__ or "").lower()


@case("discovery hooks are JSON-serializable")
def t_discovery_json():
    pkgs = m2.search_packages("summarizer")
    assert pkgs
    json.dumps(pkgs)
    man = m2.get_package("summarizer")
    json.dumps(man)
    receipt = m1.install_package("summarizer", approve=True)
    json.dumps(receipt)


@case("unknown publisher -> install refused")
def t_unknown_publisher():
    priv, pub = generate_ed25519_keypair()
    unsigned = build_manifest(PKG, "stranger", "1.0.0", "s", ["s"],
                              "main.py", "no-such-peer-id")
    man = sign_manifest(unsigned, priv)
    m2.store.add_package("stranger", "1.0.0", json.dumps(man),
                         "no-such-peer-id")
    expect_acp_error(lambda: m2.install_package("stranger", approve=True),
                     "UNKNOWN_SENDER")


def main():
    setup()
    cases = [t_publish, t_install, t_install_policy, t_tamper_file,
             t_forged_sig, t_path_traversal, t_happy_path,
             t_double_release, t_cancel, t_decline, t_dispute,
             t_forged_offer, t_nonparty_release, t_replay_accept,
             t_null_adapter, t_discovery_json, t_unknown_publisher]
    failed = 0
    try:
        for fn in cases:
            try:
                fn()
                print(f"PASS {fn._name}", flush=True)
            except Exception as e:
                failed += 1
                print(f"FAIL {fn._name}: {type(e).__name__}: {e}",
                      flush=True)
        print(f"{len(cases) - failed}/{len(cases)} marketplace cases passed",
              flush=True)
    finally:
        teardown()
    return failed


def test_marketplace_suite():
    """Pytest entry point: the whole marketplace suite as one test."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
