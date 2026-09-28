"""End-to-end connector test: two real Connector instances on localhost.

Pair -> message -> presence -> file -> family -> project -> key rotation
-> revoke. Run: python3 tests/test_connector.py
"""
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))

from acp_connector import Connector, AcpError

PASS = []
FAIL = []


def test(name):
    def deco(fn):
        fn._name = name
        return fn
    return deco


def wait_until(fn, timeout=30, interval=0.2, what="condition"):
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


def expect_acp_error(fn, code):
    try:
        fn()
    except AcpError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e.detail}"
        return e
    raise AssertionError(f"expected AcpError({code}), no error raised")


home1 = tempfile.mkdtemp(prefix="acp-test-c1-")
home2 = tempfile.mkdtemp(prefix="acp-test-c2-")
c1 = Connector(home1, "test-passphrase-one", handle="agent-one")
c2 = Connector(home2, "test-passphrase-two", handle="agent-two")
port1 = c1.start_server("127.0.0.1", 0)
port2 = c2.start_server("127.0.0.1", 0)
print(f"c1={c1.peer_id[:12]}... port={port1}  c2={c2.peer_id[:12]}... port={port2}",
      flush=True)


# ---------------------------------------------------------------- pairing
@test("1. pairing handshake")
def t_pairing():
    sessions2 = []
    ev = threading.Event()
    c2.on_pairing_request(lambda s: (sessions2.append(s), ev.set()))
    s1 = c1.pair_initiate("127.0.0.1", port2)
    assert ev.wait(30), "responder never received pair_request"
    s2 = sessions2[0]
    assert s2.code and len(s2.code) == 6, f"bad code: {s2.code!r}"
    assert all(ch in "ABCDEFGHJKMNPQRSTUVWXYZ23456789" for ch in s2.code)
    s2.accept()
    wait_until(lambda: s1.state == "await_code",
               what="challenge processing")
    # wrong code must fail cleanly
    expect_acp_error(lambda: s1.confirm("ZZZZZZ"), "PAIRING_FAILED")
    assert s1.state == "await_code"
    s1.confirm(s2.code)
    wait_until(lambda: s1.state == "done" and s2.state == "done",
               what="pairing completion")
    p12 = c1.store.get_peer(c2.peer_id)
    p21 = c2.store.get_peer(c1.peer_id)
    assert p12 and not p12["revoked"], "c1 did not store c2 as peer"
    assert p21 and not p21["revoked"], "c2 did not store c1 as peer"
    assert p12["ed_pub"] == c2.identity.ed_pub.hex(), "c1 has wrong c2 ipub"
    assert p12["x_pub"] == c2.identity.x_pub.hex(), "c1 has wrong c2 x_pub"
    assert p21["ed_pub"] == c1.identity.ed_pub.hex(), "c2 has wrong c1 ipub"
    # default pairing grants
    assert c1.permissions.has(c2.peer_id, "send_message")
    assert c1.permissions.has(c2.peer_id, "send_file")
    assert not c1.permissions.has(c2.peer_id, "family_read")
    print(f"   paired: {c1.peer_id[:16]}... <-> {c2.peer_id[:16]}...",
          flush=True)


# ---------------------------------------------------------------- messaging
@test("2. E2E messaging with ack")
def t_messaging():
    got = []
    ev = threading.Event()
    c2.on_message(lambda s, t, m: (got.append((s, t, m)), ev.set()))
    mid = c1.send_message(c2.peer_id, "hello from c1")
    assert ev.wait(30), "c2 never received the message"
    sender, text, msg_id = got[0]
    assert sender == c1.peer_id, f"wrong sender {sender[:16]}"
    assert text == "hello from c1", f"wrong text {text!r}"
    assert msg_id == mid
    row = c1.store.get_message(mid)
    assert row and row["status"] == "acked", "sender did not record ack"
    assert row["text"] == "hello from c1"
    # reverse direction
    got1 = []
    ev1 = threading.Event()
    c1.on_message(lambda s, t, m: (got1.append((s, t, m)), ev1.set()))
    mid2 = c2.send_message(c1.peer_id, "hello from c2")
    assert ev1.wait(30), "c1 never received the reply"
    assert got1[0][1] == "hello from c2" and got1[0][2] == mid2
    print(f"   msg {mid[:12]}... acked both directions", flush=True)


# ---------------------------------------------------------------- presence
@test("3. presence broadcast")
def t_presence():
    c1.set_presence("online")
    wait_until(
        lambda: (c2.store.get_presence(c1.peer_id) or {}).get("status")
                == "online",
        what="presence propagation")
    assert c1.get_presence(c1.peer_id)["status"] == "online"
    print("   c2 sees c1 as online", flush=True)


# ------------------------------------------------------------------- files
@test("4. file transfer with hash verification")
def t_file():
    content = b"ACP-TEST-PAYLOAD:" * 4096  # 69632 bytes -> 3 chunks
    src = os.path.join(home1, "send.bin")
    with open(src, "wb") as f:
        f.write(content)
    offers = []
    c2.on_file_offer(
        lambda s, n, sz, h: offers.append((s, n, sz, h)) or True)
    fid = c1.send_file(c2.peer_id, src)
    t = wait_until(
        lambda: next((r for r in [c2.store.get_transfer(fid)]
                      if r and r["state"] == "done"), None),
        what="file reception")
    assert offers, "on_file_offer never fired"
    assert offers[0][0] == c1.peer_id
    assert offers[0][1] == "send.bin" and offers[0][2] == len(content)
    with open(t["path"], "rb") as f:
        data = f.read()
    assert data == content, "file content mismatch"
    assert hashlib.sha256(data).hexdigest() == t["sha256"]
    assert os.path.dirname(t["path"]) == c2.incoming_dir
    assert os.path.basename(t["path"]) == "send.bin", t["path"]
    assert c1.store.get_transfer(fid)["state"] == "done"
    print(f"   file {fid[:12]}... {len(content)} bytes, sha256 verified",
          flush=True)


# ------------------------------------------------------------------ family
@test("5. family visibility + permission gating")
def t_family():
    fam = c1.family_add("Test Mother", relation="mother", notes="n",
                        visible_to=[c2.peer_id])
    hidden = c1.family_add("Secret", relation="x", visible_to=[])
    c1.grant_permission(c2.peer_id, "family_read")
    lst = c1.family_list(for_peer=c2.peer_id)
    ids = [m["id"] for m in lst]
    assert fam in ids, "c2 cannot see visible member"
    assert hidden not in ids, "c2 sees a hidden member"
    assert len(c1.family_list()) == 2, "owner must see all"
    c1.revoke_permission(c2.peer_id, "family_read")
    expect_acp_error(lambda: c1.family_list(for_peer=c2.peer_id),
                     "POLICY_DENIED")
    # audit recorded the denial
    actions = [r["action"] for r in c1.audit_log(limit=30)]
    assert "permission.denied" in actions
    print(f"   family {fam} visible-then-denied as expected", flush=True)


# ---------------------------------------------------------------- projects
@test("6. projects/tasks with permission gating")
def t_projects():
    pr = c1.project_create("Test Project", notes="n")
    tk = c1.task_add(pr, "Do the thing", assignee_pid=c2.peer_id,
                     notes="nn")
    c1.grant_permission(c2.peer_id, "project_read")
    proj = c1.project_get(pr, for_peer=c2.peer_id)
    assert proj["title"] == "Test Project"
    assert len(proj["tasks"]) == 1
    assert proj["tasks"][0]["id"] == tk
    assert proj["tasks"][0]["assignee"] == c2.peer_id
    assert proj["tasks"][0]["status"] == "pending"
    c1.task_update(tk, status="in_progress")
    proj = c1.project_get(pr, for_peer=c2.peer_id)
    assert proj["tasks"][0]["status"] == "in_progress"
    c1.revoke_permission(c2.peer_id, "project_read")
    expect_acp_error(lambda: c1.project_get(pr, for_peer=c2.peer_id),
                     "POLICY_DENIED")
    print(f"   project {pr} task {tk} gated as expected", flush=True)


# ------------------------------------------------------------ key rotation
@test("7. KEY_ROTATE keeps the channel alive")
def t_rotate():
    old_x = c2.store.get_peer(c1.peer_id)["x_pub"]
    c1.rotate_keys()
    wait_until(lambda: c2.store.get_peer(c1.peer_id)["x_pub"] != old_x,
               what="key rotation propagation")
    assert c2.store.get_peer(c1.peer_id)["ed_pub"] == \
        c1.identity.ed_pub.hex(), "identity key must not change"
    got = []
    ev = threading.Event()
    c2.on_message(lambda s, t, m: (got.append(t), ev.set()))
    c1.send_message(c2.peer_id, "post-rotation")
    assert ev.wait(30) and got[0] == "post-rotation"
    print("   rotation applied, messaging still works", flush=True)


# ------------------------------------------------------------------ revoke
@test("8. revoke severs trust")
def t_revoke():
    c1.revoke_peer(c2.peer_id)
    wait_until(lambda: c2.store.get_peer(c1.peer_id)["revoked"] == 1,
               what="revoke notice delivery")
    assert c1.store.get_peer(c2.peer_id)["revoked"] == 1
    assert c1.store.get_peer(c2.peer_id)["x_pub"] is None, \
        "revoked peer keys must be dropped"
    try:
        c1.send_message(c2.peer_id, "after revoke")
        raise AssertionError("send to revoked peer should fail")
    except AcpError as e:
        assert e.code in ("POLICY_DENIED", "NOT_FOUND"), e.code
    actions = [r["action"] for r in c1.audit_log(limit=30)]
    assert "peer.revoked" in actions
    print("   revoke propagated; further sends fail", flush=True)


def main():
    fns = [t_pairing, t_messaging, t_presence, t_file, t_family,
           t_projects, t_rotate, t_revoke]
    for fn in fns:
        name = fn._name
        t0 = time.time()
        try:
            fn()
        except Exception as e:
            FAIL.append((name, e))
            print(f"FAIL {name}: {type(e).__name__}: {e}", flush=True)
        else:
            PASS.append(name)
            print(f"PASS {name} ({time.time()-t0:.1f}s)", flush=True)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed", flush=True)
    try:
        c1.stop()
    except Exception:
        pass
    try:
        c2.stop()
    except Exception:
        pass
    shutil.rmtree(home1, ignore_errors=True)
    shutil.rmtree(home2, ignore_errors=True)
    # audit.log files were inside the temp homes; nothing to keep
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
