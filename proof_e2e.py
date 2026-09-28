#!/usr/bin/env python3
"""Agent Community — end-to-end proof (ACP 1.0).

A runnable demo, not a test file. Spins up two real Connector instances
(Alice and Bob) on localhost and walks the whole lifecycle:

  1. pairing with the real pair code
  2. E2E-encrypted message exchange
  3. file transfer with SHA-256 verification
  4. family member added, visible to Bob
  5. project + task created
  6. POLICY_DENIED: Bob's family grant is revoked, his read is denied
  7. revocation severs trust

Every step prints PASS (or FAIL + traceback). Exits 0 on success.

Run: python3 proof_e2e.py
"""
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_connector import Connector, AcpError  # noqa: E402

STEPS = []


def step(name):
    STEPS.append(name)
    print(f"\n=== {name} ===", flush=True)


def ok(detail=""):
    print(f"PASS{(' — ' + detail) if detail else ''}", flush=True)


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


def main():
    home_a = tempfile.mkdtemp(prefix="acp-proof-alice-")
    home_b = tempfile.mkdtemp(prefix="acp-proof-bob-")
    alice = bob = None
    try:
        # ---------------------------------------------------------- 0. boot
        step("0. boot two connectors on localhost")
        alice = Connector(home_a, "proof-pass-alice", handle="alice")
        bob = Connector(home_b, "proof-pass-bob", handle="bob")
        port_a = alice.start_server("127.0.0.1", 0)
        port_b = bob.start_server("127.0.0.1", 0)
        ok(f"alice={alice.peer_id[:16]}… port={port_a}, "
           f"bob={bob.peer_id[:16]}… port={port_b}")

        # ---------------------------------------------------------- 1. pair
        step("1. pairing with the real pair code")
        sessions = []
        ev = threading.Event()
        bob.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
        s_alice = alice.pair_initiate("127.0.0.1", port_b)
        assert ev.wait(30), "bob never received the pair request"
        s_bob = sessions[0]
        code = s_bob.code  # the code bob's user reads off their screen
        print(f"   bob shows code: {code}", flush=True)
        s_bob.accept()
        wait_until(lambda: s_alice.state == "await_code",
                   what="challenge")
        s_alice.confirm(code)  # alice's user types what bob shows
        wait_until(lambda: s_alice.state == "done"
                   and s_bob.state == "done", what="pairing completion")
        assert alice.store.get_peer(bob.peer_id) is not None
        assert bob.store.get_peer(alice.peer_id) is not None
        ok("mutual trust stored; default grants issued")

        # ---------------------------------------------------------- 2. msg
        step("2. E2E-encrypted message exchange")
        got = []
        mev = threading.Event()
        bob.on_message(lambda s, t, m: (got.append((s, t, m)), mev.set()))
        mid = alice.send_message(bob.peer_id,
                                 "hello bob, this box is E2E-encrypted")
        assert mev.wait(30), "bob never received the message"
        sender, text, msg_id = got[0]
        assert sender == alice.peer_id and msg_id == mid
        assert text == "hello bob, this box is E2E-encrypted"
        row = alice.store.get_message(mid)
        assert row and row["status"] == "acked"
        ok(f"message {mid[:12]}… delivered and acked")

        # ---------------------------------------------------------- 3. file
        step("3. file transfer with SHA-256 verification")
        content = b"ACP-PROOF-FILE:" * 4096
        src = os.path.join(home_a, "proof.dat")
        with open(src, "wb") as f:
            f.write(content)
        want = hashlib.sha256(content).hexdigest()
        bob.on_file_offer(lambda s, n, sz, h: True)
        fid = alice.send_file(bob.peer_id, src)
        t = wait_until(
            lambda: next((r for r in [bob.store.get_transfer(fid)]
                          if r and r["state"] == "done"), None),
            what="file reception")
        with open(t["path"], "rb") as f:
            data = f.read()
        assert data == content
        assert hashlib.sha256(data).hexdigest() == want == t["sha256"]
        ok(f"file {fid[:12]}… {len(content)} bytes, sha256 match")

        # ---------------------------------------------------------- 4. family
        step("4. family member visible to bob")
        fam = alice.family_add("Proof Mother", relation="mother",
                               notes="demo", visible_to=[bob.peer_id])
        alice.grant_permission(bob.peer_id, "family_read")
        visible = alice.family_list(for_peer=bob.peer_id)
        assert any(m["id"] == fam and m["name"] == "Proof Mother"
                   for m in visible), visible
        ok(f"bob can see family member {fam}")

        # ---------------------------------------------------------- 5. project
        step("5. project + task")
        proj = alice.project_create("Proof Project", notes="demo")
        task = alice.task_add(proj, "Prove the network works",
                              assignee_pid=bob.peer_id, notes="demo")
        alice.grant_permission(bob.peer_id, "project_read")
        p = alice.project_get(proj, for_peer=bob.peer_id)
        assert p["title"] == "Proof Project"
        assert len(p["tasks"]) == 1
        assert p["tasks"][0]["id"] == task
        assert p["tasks"][0]["assignee"] == bob.peer_id
        ok(f"project {proj} with task {task} assigned to bob")

        # ---------------------------------------------------------- 6. denied
        step("6. POLICY_DENIED after the grant is revoked")
        alice.revoke_permission(bob.peer_id, "family_read")
        try:
            alice.family_list(for_peer=bob.peer_id)
        except AcpError as e:
            assert e.code == "POLICY_DENIED", e.code
            ok("bob's family read denied after revocation")
        else:
            raise AssertionError("family list should have been denied")
        denied = [r["action"] for r in alice.audit_log(limit=30)]
        assert "permission.denied" in denied
        ok("denial written to the audit log")

        # ---------------------------------------------------------- 7. revoke
        step("7. revocation severs trust")
        alice.revoke_peer(bob.peer_id)
        wait_until(lambda: (bob.store.get_peer(alice.peer_id) or {})
                   .get("revoked") == 1, what="revoke propagation")
        try:
            alice.send_message(bob.peer_id, "after revoke")
        except AcpError as e:
            assert e.code in ("POLICY_DENIED", "NOT_FOUND"), e.code
            ok(f"send to revoked peer refused ({e.code})")
        else:
            raise AssertionError("send to revoked peer should fail")

        print(f"\nALL {len(STEPS)} STEPS PASSED", flush=True)
        return 0
    except Exception:
        print("\nPROOF FAILED", flush=True)
        traceback.print_exc()
        return 1
    finally:
        for c in (alice, bob):
            if c is not None:
                try:
                    c.stop()
                except Exception:
                    pass
        shutil.rmtree(home_a, ignore_errors=True)
        shutil.rmtree(home_b, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
