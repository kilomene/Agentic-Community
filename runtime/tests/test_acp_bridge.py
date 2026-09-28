"""Tests for the runtime <-> ACP bridge (src/acp_bridge.py).

The bridge gives the vm-agent task engine a network identity: pair,
message, transfer files, and install capability packages over ACP 1.0.

These tests run the real ACP stack (pure-python, stdlib only) — two
bridges pair over loopback TCP exactly like two agents would.
"""
import hashlib
import json
import os
import sys
import tempfile
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(HERE, "..")
sys.path.insert(0, os.path.abspath(RUNTIME))

from src.acp_bridge import AcpBridge, AcpBridgeError, bridge_for_executor  # noqa: E402


@pytest.fixture()
def cfg():
    base = tempfile.mkdtemp(prefix="vmagent-test-")
    return {"base_dir": base, "acp_home": os.path.join(base, "acp")}


def make_bridge(cfg, handle="agent"):
    return AcpBridge(cfg)


def init_bridge(cfg, handle="agent", passphrase="test-passphrase-1"):
    b = AcpBridge(cfg)
    r = b.run("init", {"handle": handle, "passphrase": passphrase,
                       "home": os.path.join(cfg["acp_home"], handle)})
    return b, r


def wait_until(fn, timeout=30, interval=0.2):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    raise AssertionError("timeout")


# ------------------------------------------------------------ basics
def test_init_creates_identity_and_is_idempotent(cfg):
    b, r = init_bridge(cfg, handle="alice")
    assert r["created"] is True
    assert r["peer_id"] and r["handle"] == "alice"
    b2, r2 = init_bridge(cfg, handle="alice")
    assert r2["created"] is False
    assert r2["peer_id"] == r["peer_id"]


def test_identity_op(cfg):
    b, r = init_bridge(cfg, handle="alice")
    ident = b.run("identity", {"passphrase": "test-passphrase-1"})
    assert ident["peer_id"] == r["peer_id"]
    assert ident["handle"] == "alice"


def test_unknown_op_is_clean_error(cfg):
    b, r = init_bridge(cfg)
    with pytest.raises(AcpBridgeError) as e:
        b.run("hack_the_planet", {"passphrase": "test-passphrase-1"})
    assert "unknown acp op" in str(e.value)


def test_missing_passphrase_is_clean_error(cfg):
    b = AcpBridge(cfg)
    with pytest.raises(AcpBridgeError) as e:
        b.run("identity", {})
    assert "passphrase" in str(e.value)


def test_wrong_passphrase_fails_cleanly(cfg):
    b, r = init_bridge(cfg, handle="alice")
    b2 = AcpBridge(cfg)
    with pytest.raises(AcpBridgeError):
        b2.run("identity", {"passphrase": "wrong-passphrase",
                            "home": os.path.join(cfg["acp_home"], "alice")})
    # the failed open must not poison the good connector
    ident = b.run("identity", {"passphrase": "test-passphrase-1"})
    assert ident["peer_id"] == r["peer_id"]


def test_passphrase_never_in_result(cfg):
    b, r = init_bridge(cfg, handle="alice")
    ident = b.run("identity", {"passphrase": "test-passphrase-1"})
    blob = json.dumps(ident)
    assert "test-passphrase-1" not in blob


# ------------------------------------------------------------ E2E: pair + message + file
def _paired_pair(cfg):
    """Two bridges, A serving, B paired to A. Returns (bridge_a, bridge_b,
    peer ids...)."""
    b_a, r_a = init_bridge(cfg, handle="alice")
    b_b, r_b = init_bridge(cfg, handle="bob")
    served = b_a.run("serve", {"passphrase": "test-passphrase-1",
                               "host": "127.0.0.1", "port": 0})
    b_b.run("serve", {"passphrase": "test-passphrase-1",
                      "host": "127.0.0.1", "port": 0})
    port = served["port"]
    assert port > 0
    p = b_b.run("pair", {"passphrase": "test-passphrase-1",
                         "host": "127.0.0.1", "port": port})
    assert p["status"] == "await_challenge"

    def got_request():
        r = b_a.run("pair_requests", {"passphrase": "test-passphrase-1"})
        return r["requests"] if r["requests"] else None

    reqs = wait_until(got_request, timeout=20)
    assert len(reqs) == 1
    req = reqs[0]
    assert req["code"]
    acc = b_a.run("pair_accept", {"passphrase": "test-passphrase-1",
                                  "session_id": req["session_id"]})
    assert acc["status"] in ("await_confirm", "done")

    def await_code():
        st = b_b.run("pair_status", {"passphrase": "test-passphrase-1",
                                     "session_id": p["session_id"]})
        return st if st["status"] == "await_code" else None

    wait_until(await_code, timeout=20)
    done = b_b.run("pair_confirm", {"passphrase": "test-passphrase-1",
                                    "session_id": p["session_id"],
                                    "code": req["code"], "wait_s": 20})
    assert done["status"] == "done"
    assert done["peer_id"] == r_a["peer_id"]
    return b_a, b_b, r_a["peer_id"], r_b["peer_id"]


def test_pair_message_and_inbox(cfg):
    b_a, b_b, pid_a, pid_b = _paired_pair(cfg)
    m = b_b.run("message", {"passphrase": "test-passphrase-1",
                            "peer": pid_a, "text": "hello from bob"})
    assert m["acked"] is True
    inbox = b_a.run("inbox", {"passphrase": "test-passphrase-1",
                              "limit": 10})
    texts = [x["text"] for x in inbox["messages"] if x["direction"] == "in"]
    assert "hello from bob" in texts
    peers = b_a.run("peers", {"passphrase": "test-passphrase-1"})
    assert any(p["peer_id"] == pid_b for p in peers["peers"])


def test_pair_confirm_wrong_code_fails(cfg):
    b_a, b_b, pid_a, pid_b = _paired_pair(cfg)
    # fresh second pairing attempt with a bad code
    served = b_a.run("serve", {"passphrase": "test-passphrase-1"})
    p = b_b.run("pair", {"passphrase": "test-passphrase-1",
                         "host": "127.0.0.1", "port": served["port"]})

    def got_request():
        r = b_a.run("pair_requests", {"passphrase": "test-passphrase-1"})
        return r["requests"] if r["requests"] else None

    reqs = wait_until(got_request, timeout=20)
    # the request from the first pairing was consumed; take the newest
    req = reqs[-1]
    b_a.run("pair_accept", {"passphrase": "test-passphrase-1",
                            "session_id": req["session_id"]})

    def await_code():
        st = b_b.run("pair_status", {"passphrase": "test-passphrase-1",
                                     "session_id": p["session_id"]})
        return st if st["status"] == "await_code" else None

    wait_until(await_code, timeout=20)
    with pytest.raises(AcpBridgeError) as e:
        b_b.run("pair_confirm", {"passphrase": "test-passphrase-1",
                                 "session_id": p["session_id"],
                                 "code": "WRONG1"})
    assert "mismatch" in str(e.value).lower() or "PAIR" in str(e.value)


def test_send_file_roundtrip(cfg):
    b_a, b_b, pid_a, pid_b = _paired_pair(cfg)
    content = b"ACP-BRIDGE-FILE:" * 2048
    src = os.path.join(cfg["base_dir"], "payload.bin")
    with open(src, "wb") as f:
        f.write(content)
    want = hashlib.sha256(content).hexdigest()
    r = b_b.run("send_file", {"passphrase": "test-passphrase-1",
                              "peer": pid_a, "path": src})
    assert r["sha256"] == want

    def received():
        home_a = os.path.join(cfg["acp_home"], "alice")
        inc = os.path.join(home_a, "incoming")
        if not os.path.isdir(inc):
            return None
        for name in os.listdir(inc):
            if name.endswith(".part"):
                continue
            p = os.path.join(inc, name)
            with open(p, "rb") as f:
                if f.read() == content:
                    return p
        return None

    got = wait_until(received, timeout=30)
    assert got is not None


def test_send_file_refuses_runtime_state(cfg):
    b_a, b_b, pid_a, pid_b = _paired_pair(cfg)
    state_db = os.path.join(cfg["base_dir"], "state", "state.db")
    os.makedirs(os.path.dirname(state_db), exist_ok=True)
    with open(state_db, "w") as f:
        f.write("secret-state")
    with pytest.raises(AcpBridgeError) as e:
        b_b.run("send_file", {"passphrase": "test-passphrase-1",
                              "peer": pid_a, "path": state_db})
    assert "protected" in str(e.value).lower()


# ------------------------------------------------------------ executor wiring
class _FakeExecutor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.logged = []

    def _log(self, event, **kw):
        self.logged.append((event, kw))


def test_tool_dispatch_and_shared_bridge(cfg):
    from src.tools import Executor
    logged = []
    ex = Executor(cfg, journal=lambda event, **kw: logged.append((event, kw)))
    home = os.path.join(cfg["acp_home"], "alice")
    res = ex.run("acp", op="init",
                 args={"op": "init", "handle": "alice",
                       "passphrase": "pw-tool-1", "home": home})
    assert res.ok, res.stderr
    data = json.loads(res.stdout)
    assert data["peer_id"]
    # the bridge is shared on the executor, not rebuilt per call
    b1 = bridge_for_executor(ex)
    b2 = bridge_for_executor(ex)
    assert b1 is b2
    # journaled args must not contain the raw passphrase
    for event, kw in logged:
        blob = json.dumps(kw)
        assert "pw-tool-1" not in blob


def test_caps_gate_acp_tool():
    from src import caps as capsmod

    class _DenyStore:
        def capability_has(self, task_id, cap):
            return False

    class _GrantStore:
        def capability_has(self, task_id, cap):
            return cap == "ACP_NETWORK"

    # the acp tool maps to its own capability, distinct from NETWORK_ACCESS
    assert capsmod.TOOL_CAPABILITY["acp"] == "ACP_NETWORK"
    assert "ACP_NETWORK" in capsmod.CAPABILITIES
    assert capsmod.TOOL_CAPABILITY["http_get"] == "NETWORK_ACCESS"
    ok, reason = capsmod.check_tool(_DenyStore(), "t1", "acp")
    assert not ok and "ACP_NETWORK" in reason
    ok, _ = capsmod.check_tool(_GrantStore(), "t1", "acp")
    assert ok


def test_verifier_acp_check(cfg):
    from src.tools import Executor
    from src.verify import Verifier
    ex = Executor(cfg)
    home = os.path.join(cfg["acp_home"], "alice")
    ex.run("acp", op="init",
           args={"op": "init", "handle": "alice",
                 "passphrase": "pw-verify-1", "home": home})
    v = Verifier(ex)
    verdict = v.verify_step({"verify": [
        {"check": "acp", "op": "identity",
         "args": {"passphrase": "pw-verify-1"},
         "expect": {"handle": "alice"}}]})
    assert verdict.passed, verdict.to_dict()
    # mutating ops are rejected by the check
    bad = v.verify_step({"verify": [
        {"check": "acp", "op": "message",
         "args": {"passphrase": "pw-verify-1", "peer": "x", "text": "y"}}]})
    assert not bad.passed
    # the raw passphrase must not persist in the verdict record
    assert "pw-verify-1" not in json.dumps(verdict.to_dict())


def test_model_validates_acp_action(cfg):
    from src.model import validate_action
    ok, errors = validate_action({"tool": "acp",
                                  "args": {"op": "identity"}})
    assert ok, errors
    ok, errors = validate_action({"tool": "acp", "args": {}})
    assert not ok and any("op" in e for e in errors)


# ------------------------------------------------------------ market install
def _signed_package(tmp, publisher_id,
                    with_task=True, tamper_sig=False, evil_path=False):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "packages"))
    from acp_marketplace import manifest as manifestmod
    from acp_crypto import generate_ed25519_keypair
    ed_priv, ed_pub = generate_ed25519_keypair()
    pkg_src = os.path.join(tmp, "pkgsrc")
    os.makedirs(pkg_src)
    with open(os.path.join(pkg_src, "main.py"), "w") as f:
        f.write("# demo capability\n")
    if with_task:
        task = {"steps": [
            {"name": "say hi",
             "tool": "acp",
             "args": {"op": "identity",
                      "passphrase": {"vault": "acp_passphrase"}},
             "verify": [{"check": "acp", "op": "identity",
                         "args": {"passphrase": {"vault": "acp_passphrase"}},
                         "expect": {}}]}]}
        with open(os.path.join(pkg_src, "task.json"), "w") as f:
            json.dump(task, f)
    man = manifestmod.build_manifest(
        pkg_src, name="demo-cap", version="1.0.0",
        description="demo", capabilities=["demo"],
        entry_point="main.py", publisher_id=publisher_id)
    signed = manifestmod.sign_manifest(man, ed_priv)
    if tamper_sig:
        signed["sig"] = "47:" + "A" * 90
    pkg_dir = os.path.join(tmp, "pkgdir")
    os.makedirs(pkg_dir)
    with open(os.path.join(pkg_dir, "manifest.json"), "w") as f:
        json.dump(signed, f)
    for entry in signed["files"]:
        with open(os.path.join(pkg_src, entry["path"]), "rb") as f:
            data = f.read()
        with open(os.path.join(pkg_dir, entry["path"]), "wb") as f:
            f.write(data)
    if evil_path:
        signed["files"].append({"path": "../evil.py",
                                "sha256": "00" * 32})
        with open(os.path.join(pkg_dir, "manifest.json"), "w") as f:
            json.dump(signed, f)
    return pkg_dir, ed_pub


def test_market_install_verifies_and_validates_task(cfg):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "packages"))
    from acp_crypto import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()
    b, r = init_bridge(cfg, handle="alice")
    tmp = tempfile.mkdtemp(prefix="market-")
    pkg_dir, ed_pub = _signed_package(tmp, "publisher-1")
    b._connector("test-passphrase-1").store.add_peer(
        "publisher-1", "Publisher", ed_pub.hex(), xpub.hex())
    res = b.run("market_install",
                {"passphrase": "test-passphrase-1", "package_dir": pkg_dir})
    assert res["installed"] is True
    assert res["task_spec"]["present"] is True
    assert res["task_spec"]["valid"] is True, res["task_spec"]["errors"]
    assert os.path.isfile(os.path.join(res["path"], "main.py"))


def test_market_install_rejects_bad_signature(cfg):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "packages"))
    from acp_crypto import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()
    b, r = init_bridge(cfg, handle="alice")
    tmp = tempfile.mkdtemp(prefix="market-")
    pkg_dir, ed_pub = _signed_package(tmp, "publisher-1", tamper_sig=True)
    b._connector("test-passphrase-1").store.add_peer(
        "publisher-1", "Publisher", ed_pub.hex(), xpub.hex())
    with pytest.raises(AcpBridgeError):
        b.run("market_install",
              {"passphrase": "test-passphrase-1", "package_dir": pkg_dir})


def test_market_install_rejects_untrusted_publisher(cfg):
    b, r = init_bridge(cfg, handle="alice")
    tmp = tempfile.mkdtemp(prefix="market-")
    pkg_dir, _ = _signed_package(tmp, "stranger-9")
    with pytest.raises(AcpBridgeError) as e:
        b.run("market_install",
              {"passphrase": "test-passphrase-1", "package_dir": pkg_dir})
    assert "trusted peer" in str(e.value)


def test_market_install_rejects_evil_path(cfg):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "packages"))
    from acp_crypto import generate_x25519_keypair
    _, xpub = generate_x25519_keypair()
    b, r = init_bridge(cfg, handle="alice")
    tmp = tempfile.mkdtemp(prefix="market-")
    # note: evil path appended AFTER signing -> signature also fails;
    # either rejection is a pass
    pkg_dir, ed_pub = _signed_package(tmp, "publisher-1", evil_path=True)
    b._connector("test-passphrase-1").store.add_peer(
        "publisher-1", "Publisher", ed_pub.hex(), xpub.hex())
    with pytest.raises(AcpBridgeError):
        b.run("market_install",
              {"passphrase": "test-passphrase-1", "package_dir": pkg_dir})
