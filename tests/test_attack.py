"""Adversarial tests for Agent Community (ACP 1.0).

Each test models a concrete attacker and asserts the defense holds --
i.e. every attack MUST FAIL (the test passes when the attack is
defeated):

  1. forged signature          -> INVALID_SIG
  2. replay                    -> REPLAY, no duplicate delivery
  3. wrong pairing code        -> PAIRING_FAILED, no peer stored
  4. MITM key substitution     -> handshake fails, nobody trusted
  5. tampered file chunk       -> FILE_HASH_MISMATCH, file not delivered
  6. permission escalation     -> POLICY_DENIED + audit entry
  7. expired envelope          -> EXPIRED
  8. unknown sender            -> UNKNOWN_SENDER
  9. E2E to wrong recipient    -> DECRYPT_FAIL
 10. oversized file            -> FILE_TOO_LARGE, rejected before transfer
 11. relay visibility          -> relay sees routing metadata only;
                                  the E2E box stays opaque

Run: python3 tests/test_attack.py
"""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_relay"))

from acp_crypto import (  # noqa: E402
    generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import (  # noqa: E402
    AcpError, MSG, PRESENCE, PAIR_CHALLENGE, FILE_CHUNK,
    b62encode, b62decode, b62encode_fixed, b62decode_fixed, canonical,
    make_envelope, make_e2e_envelope, verify_envelope,
    open_e2e_envelope, frame_envelope,
)
from acp_connector import Connector  # noqa: E402
from acp_connector.pairing import code_hash, new_code  # noqa: E402
import acp_connector.files as files_mod  # noqa: E402

PASS = []
FAIL = []


def case(name):
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


def audit_has(conn, action, code=None, limit=60):
    for r in conn.audit_log(limit=limit):
        if r["action"] != action:
            continue
        if code is None:
            return True
        try:
            details = json.loads(r.get("details") or "{}")
        except (ValueError, TypeError):
            details = {}
        if details.get("code") == code or details.get("error") == code:
            return True
    return False


class BlackHole:
    """Fake connection: records envelopes 'sent back' to the attacker."""

    def __init__(self):
        self.sent = []
        self.peer_addr = None

    def send_env(self, env):
        self.sent.append(env)


def make_home(prefix):
    return tempfile.mkdtemp(prefix=prefix)


def start_pair(handle_a, handle_b):
    """Two connectors, server each, fully paired. Returns
    (ca, cb, ha, hb, pa, pb)."""
    ha, hb = make_home("acp-atk-a-"), make_home("acp-atk-b-")
    ca = Connector(ha, "atk-pass-a", handle=handle_a)
    cb = Connector(hb, "atk-pass-b", handle=handle_b)
    pa, pb = ca.start_server("127.0.0.1", 0), cb.start_server("127.0.0.1", 0)
    sessions = []
    ev = threading.Event()
    cb.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
    s1 = ca.pair_initiate("127.0.0.1", pb)
    assert ev.wait(30), "responder never got pair_request"
    s2 = sessions[0]
    s2.accept()
    wait_until(lambda: s1.state == "await_code", what="challenge")
    s1.confirm(s2.code)
    wait_until(lambda: s1.state == "done" and s2.state == "done",
               what="pairing")
    return ca, cb, ha, hb, pa, pb


HOMES = []
CONNS = []


def track(ca, cb, ha, hb):
    HOMES.extend([ha, hb])
    CONNS.extend([ca, cb])
    return ca, cb


# ------------------------------------------------------------------ fixtures
_ca, _cb, _ha, _hb, _pa, _pb = start_pair("atk-alice", "atk-bob")
alice, bob = track(_ca, _cb, _ha, _hb)
home_a, home_b, port_a, port_b = _ha, _hb, _pa, _pb
print(f"alice={alice.peer_id[:12]}... bob={bob.peer_id[:12]}...",
      flush=True)


def bob_x_pub():
    return bytes.fromhex(alice.store.get_peer(bob.peer_id)["x_pub"])


def alice_x_pub():
    return bytes.fromhex(bob.store.get_peer(alice.peer_id)["x_pub"])


# ------------------------------------------------------------------ 1. forge
@case("1. forged signature -> INVALID_SIG")
def t_forged_signature():
    env = make_e2e_envelope(
        MSG, alice.peer_id, bob.peer_id,
        {"text": "legit", "msg_id": "m-forge-1"},
        alice.identity.ed_priv, alice.identity.x_priv,
        alice.identity.x_pub, bob_x_pub())
    # sanity: the untampered envelope verifies
    verify_envelope(env, bob._get_pubkey)
    # attacker flips a byte inside the E2E box
    forged = dict(env)
    box = dict(env["box"])
    raw = bytearray(b62decode_fixed(box["ct"]))
    raw[len(raw) // 2] ^= 0x01
    box["ct"] = b62encode_fixed(bytes(raw))
    forged["box"] = box
    expect_acp_error(lambda: verify_envelope(forged, bob._get_pubkey),
                     "INVALID_SIG")
    # and a plaintext-envelope forgery fails the same way
    penv = make_envelope(PRESENCE, alice.peer_id, bob.peer_id,
                         {"state": "online"}, alice.identity.ed_priv)
    pforged = dict(penv)
    pforged["payload"] = {"state": "busy"}
    expect_acp_error(lambda: verify_envelope(pforged, bob._get_pubkey),
                     "INVALID_SIG")
    print("   tampered box and tampered payload both rejected",
          flush=True)


# ------------------------------------------------------------------ 2. replay
@case("2. replay -> REPLAY, no duplicate delivery")
def t_replay():
    msg_id = "m-replay-" + os.urandom(4).hex()
    env = make_e2e_envelope(
        MSG, alice.peer_id, bob.peer_id,
        {"text": "deliver exactly once", "msg_id": msg_id},
        alice.identity.ed_priv, alice.identity.x_priv,
        alice.identity.x_pub, bob_x_pub())
    sink = BlackHole()
    delivered = []
    ev = threading.Event()
    bob.on_message(lambda s, t, m: (delivered.append(m), ev.set()))
    # first delivery: accepted
    bob._on_frame(sink, env)
    assert ev.wait(30), "first delivery never arrived"
    assert delivered == [msg_id]
    assert bob.store.get_message(msg_id) is not None
    # attacker re-injects the identical frame
    bob._on_frame(sink, env)
    time.sleep(1.0)  # let the reader-thread-free path settle
    assert delivered == [msg_id], "duplicate delivery!"
    assert bob.store.get_message(msg_id) is not None
    # the re-injection was answered with ERROR(REPLAY)
    replays = [e for e in sink.sent
               if e.get("kind") == "error"
               and (e.get("payload") or {}).get("code") == "REPLAY"]
    assert replays, f"no REPLAY error sent back; got {sink.sent}"
    assert audit_has(bob, "envelope.rejected", code="REPLAY")
    print("   second delivery rejected with REPLAY; stored once",
          flush=True)


# ---------------------------------------------------------- 3. wrong code
@case("3. wrong pairing code -> PAIRING_FAILED, no peer stored")
def t_wrong_code():
    hd, he = make_home("acp-atk-d-"), make_home("acp-atk-e-")
    dave = Connector(hd, "atk-pass-d", handle="atk-dave")
    erin = Connector(he, "atk-pass-e", handle="atk-erin")
    HOMES.extend([hd, he])
    CONNS.extend([dave, erin])
    pe = erin.start_server("127.0.0.1", 0)
    dave.start_server("127.0.0.1", 0)
    sessions = []
    ev = threading.Event()
    erin.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
    s1 = dave.pair_initiate("127.0.0.1", pe)
    assert ev.wait(30), "erin never got pair_request"
    s2 = sessions[0]
    s2.accept()
    wait_until(lambda: s1.state == "await_code", what="challenge")
    # attacker (or a typo-ing user) confirms with the wrong code
    expect_acp_error(lambda: s1.confirm("ZZZZZZ"), "PAIRING_FAILED")
    assert s1.state == "await_code", "session must not advance"
    assert s2.state != "done"
    # and with a well-formed but wrong code
    expect_acp_error(lambda: s1.confirm("ABCDEF"), "PAIRING_FAILED")
    # no trust was established on either side
    assert dave.store.get_peer(erin.peer_id) is None, \
        "dave stored erin without a valid code"
    assert erin.store.get_peer(dave.peer_id) is None, \
        "erin stored dave without a valid code"
    print("   wrong codes rejected; trust stores empty both sides",
          flush=True)


# ---------------------------------------------------------- 4. MITM keys
@case("4. MITM key substitution -> handshake fails, nobody trusted")
def t_mitm():
    hf, hg = make_home("acp-atk-f-"), make_home("acp-atk-g-")
    frank = Connector(hf, "atk-pass-f", handle="atk-frank")
    grace = Connector(hg, "atk-pass-g", handle="atk-grace")
    HOMES.extend([hf, hg])
    CONNS.extend([frank, grace])
    pf = frank.start_server("127.0.0.1", 0)
    pg = grace.start_server("127.0.0.1", 0)

    sessions = []
    ev = threading.Event()
    grace.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
    s1 = frank.pair_initiate("127.0.0.1", pg)
    assert ev.wait(30), "grace never got pair_request"
    s_grace = sessions[0]

    # --- attacker sits between: drops grace's real pair_challenge ---
    real_send = grace._send_plain
    dropped = []

    def intercepted(kind, to_pid, payload):
        if kind == PAIR_CHALLENGE:
            dropped.append(payload)
            return
        return real_send(kind, to_pid, payload)

    grace._send_plain = intercepted
    try:
        s_grace.accept()
        assert wait_until(lambda: bool(dropped), what="challenge drop")
    finally:
        grace._send_plain = real_send
    real_code = s_grace.code  # what frank's user reads on grace's screen

    # --- attacker injects its own challenge, reusing frank's code hash ---
    # (it cannot forge grace's signature, so it signs with its own keys;
    #  it also does not know grace's code)
    m_ed_priv, m_ed_pub = generate_ed25519_keypair()
    _, m_x_pub = generate_x25519_keypair()
    m_pid = b62encode(m_ed_pub)
    chall = {
        "code_hash": code_hash(new_code()),
        "x_pub": m_x_pub.hex(),
        "ipub": m_ed_pub.hex(),
        "handle": "mallory",
        "expires": int(time.time()) + 600,
    }
    menv = make_envelope(PAIR_CHALLENGE, m_pid, frank.peer_id, chall,
                         m_ed_priv)
    sock = socket.create_connection(("127.0.0.1", pf), timeout=10)
    try:
        sock.sendall(frame_envelope(menv))
        # frank's reader thread processes the forged challenge
        wait_until(lambda: s1.state == "await_code",
                   what="forged challenge processing")
    finally:
        sock.close()

    # frank's user types the code shown on grace's real screen -> mismatch
    expect_acp_error(lambda: s1.confirm(real_code), "PAIRING_FAILED")
    assert s1.state != "done"
    assert s_grace.state != "done"
    # neither side trusts anyone from this handshake
    assert frank.store.get_peer(grace.peer_id) is None, \
        "frank trusted grace after MITM"
    assert grace.store.get_peer(frank.peer_id) is None, \
        "grace trusted frank after MITM"
    assert frank.store.get_peer(m_pid) is None, \
        "frank trusted the MITM identity"
    print("   forged challenge could not complete pairing; no trust",
          flush=True)


# ---------------------------------------------------------- 5. chunk tamper
@case("5. tampered file chunk -> FILE_HASH_MISMATCH, file not delivered")
def t_chunk_tamper():
    content = b"ACP-ATTACK-PAYLOAD:" * 4096  # 77824 bytes -> 3 chunks
    src = os.path.join(home_a, "attack.bin")
    with open(src, "wb") as f:
        f.write(content)

    captured = {}

    orig_e2e = alice._send_e2e

    def spy(kind, to_pid, payload):
        if kind == "file_offer":
            captured["file_id"] = payload["file_id"]
        return orig_e2e(kind, to_pid, payload)

    alice._send_e2e = spy
    conn = alice._get_conn(bob.peer_id)
    orig_send = conn.send_env
    tampered = {"done": False}

    def evil_send(env):
        # attacker flips a byte in the first chunk frame on the wire
        if env.get("kind") == FILE_CHUNK and not tampered["done"]:
            tampered["done"] = True
            env = dict(env)
            box = dict(env["box"])
            raw = bytearray(b62decode_fixed(box["ct"]))
            raw[len(raw) // 2] ^= 0x01
            box["ct"] = b62encode_fixed(bytes(raw))
            env["box"] = box
            # the Ed25519 signature no longer matches either: the frame
            # is rejected at the signature layer, so the chunk never
            # lands and the whole-file hash cannot match.
        return orig_send(env)

    conn.send_env = evil_send
    # the sender would otherwise block 60 s waiting for a FILE_ACK that
    # will never come; the receiver-side verdict is what we assert.
    old_finish = files_mod.FINISH_TIMEOUT
    files_mod.FINISH_TIMEOUT = 8
    sender_err = []
    try:
        t = threading.Thread(
            target=lambda: sender_err.append(_send_file_catch()),
            daemon=True)
        t.start()
        assert wait_until(lambda: captured.get("file_id"),
                          what="file offer"), "offer never sent"
        fid = captured["file_id"]

        def failed():
            r = bob.store.get_transfer(fid)
            return r is not None and r["state"] == "failed"

        assert wait_until(failed, timeout=45,
                          what="receiver hash-mismatch verdict")
        assert tampered["done"], "no chunk was tampered"
        # receiver reported FILE_HASH_MISMATCH and kept the file quarantined
        assert audit_has(bob, "file.hash_mismatch"), \
            "no file.hash_mismatch audit event"
        delivered = [n for n in os.listdir(bob.incoming_dir)
                     if not n.endswith(".part")]
        assert "attack.bin" not in delivered, \
            f"tampered file was delivered: {delivered}"
        row = bob.store.get_transfer(fid)
        assert row["state"] == "failed"
        print("   chunk rejected; FILE_HASH_MISMATCH; nothing delivered",
              flush=True)
    finally:
        alice._send_e2e = orig_e2e
        conn.send_env = orig_send
        files_mod.FINISH_TIMEOUT = old_finish


def _send_file_catch():
    try:
        alice.send_file(bob.peer_id,
                        os.path.join(home_a, "attack.bin"))
        return None
    except AcpError as e:
        return e.code
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------- 6. escalation
@case("6. permission escalation -> POLICY_DENIED + audit entry")
def t_permission_escalation():
    # bob holds only the default pairing grants: no family_read
    assert not alice.permissions.has(bob.peer_id, "family_read"), \
        "precondition broken: bob already has family_read"
    expect_acp_error(lambda: alice.family_list(for_peer=bob.peer_id),
                     "POLICY_DENIED")
    assert audit_has(alice, "permission.denied"), \
        "no permission.denied audit entry"
    # and nothing leaked: the denial happens before any rows are read
    print("   family list denied for ungranted peer; denial audited",
          flush=True)


# ---------------------------------------------------------- 7. expired
@case("7. expired envelope -> EXPIRED")
def t_expired():
    env = make_envelope(PRESENCE, alice.peer_id, bob.peer_id,
                        {"state": "online"}, alice.identity.ed_priv,
                        ts=int(time.time()) - 3600)
    expect_acp_error(lambda: verify_envelope(env, bob._get_pubkey),
                     "EXPIRED")
    # a fresh envelope from the same keys verifies fine
    fresh = make_envelope(PRESENCE, alice.peer_id, bob.peer_id,
                          {"state": "online"}, alice.identity.ed_priv)
    verify_envelope(fresh, bob._get_pubkey)
    print("   1-hour-old envelope rejected; fresh envelope accepted",
          flush=True)


# ---------------------------------------------------------- 8. unknown sender
@case("8. unknown sender -> UNKNOWN_SENDER")
def t_unknown_sender():
    u_priv, u_pub = generate_ed25519_keypair()
    u_pid = b62encode(u_pub)
    env = make_envelope(PRESENCE, u_pid, bob.peer_id, {"state": "online"},
                        u_priv)
    expect_acp_error(lambda: verify_envelope(env, bob._get_pubkey),
                     "UNKNOWN_SENDER")
    print("   correctly signed envelope from a stranger rejected",
          flush=True)


# ---------------------------------------------------------- 9. wrong recipient
@case("9. E2E to wrong recipient -> DECRYPT_FAIL")
def t_wrong_recipient():
    hc = make_home("acp-atk-c-")
    carol = Connector(hc, "atk-pass-c", handle="atk-carol")
    HOMES.append(hc)
    CONNS.append(carol)
    pc = carol.start_server("127.0.0.1", 0)
    sessions = []
    ev = threading.Event()
    carol.on_pairing_request(lambda s: (sessions.append(s), ev.set()))
    s1 = alice.pair_initiate("127.0.0.1", pc)
    assert ev.wait(30)
    s2 = sessions[0]
    s2.accept()
    wait_until(lambda: s1.state == "await_code", what="challenge")
    s1.confirm(s2.code)
    wait_until(lambda: s1.state == "done" and s2.state == "done",
               what="pairing")

    # attacker (or a buggy sender) encrypts for BOB's key but addresses
    # the envelope to CAROL
    env = make_e2e_envelope(
        MSG, alice.peer_id, carol.peer_id,
        {"text": "for bob only", "msg_id": "m-wrong-rcpt"},
        alice.identity.ed_priv, alice.identity.x_priv,
        alice.identity.x_pub, bob_x_pub())
    # carol holds no part of the alice<->bob pairwise key: DECRYPT_FAIL
    expect_acp_error(
        lambda: open_e2e_envelope(env, carol._get_pubkey,
                                  carol.identity.x_priv),
        "DECRYPT_FAIL")
    # a third party with fresh keys fails too
    _, mallory_x_priv = generate_x25519_keypair()
    expect_acp_error(
        lambda: open_e2e_envelope(env, carol._get_pubkey,
                                  mallory_x_priv),
        "DECRYPT_FAIL")
    # the box is well-formed: bob, the key holder, opens it (the pairwise
    # key is symmetric by design, so the defense is "only key holders
    # read", not "only the named recipient reads")
    pt = open_e2e_envelope(env, bob._get_pubkey, bob.identity.x_priv)
    assert pt["text"] == "for bob only"
    # wire level: deliver the mis-addressed envelope to carol's connector;
    # it rejects the frame and stores nothing
    sink = BlackHole()
    carol._on_frame(sink, env)
    errs = [e for e in sink.sent
            if e.get("kind") == "error"
            and (e.get("payload") or {}).get("code") == "DECRYPT_FAIL"]
    assert errs, f"carol did not reject with DECRYPT_FAIL: {sink.sent}"
    assert carol.store.get_message("m-wrong-rcpt") is None, \
        "carol stored a message she could not decrypt"
    print("   box for bob delivered to carol: rejected, unread, unstored",
          flush=True)


# ---------------------------------------------------------- 10. oversized
@case("10. oversized file -> FILE_TOO_LARGE before transfer")
def t_oversized_file():
    alice.set_file_size_cap(1024)
    big = os.path.join(home_a, "big.bin")
    with open(big, "wb") as f:
        f.write(b"x" * 2048)
    offered = []
    orig_e2e = alice._send_e2e

    def spy(kind, to_pid, payload):
        if kind == "file_offer":
            offered.append(payload["file_id"])
        return orig_e2e(kind, to_pid, payload)

    alice._send_e2e = spy
    try:
        expect_acp_error(lambda: alice.send_file(bob.peer_id, big),
                         "FILE_TOO_LARGE")
        assert not offered, "FILE_OFFER went out despite the cap"
    finally:
        alice._send_e2e = orig_e2e
        alice.set_file_size_cap(100 * 1024 * 1024)
    print("   2 KiB file rejected against a 1 KiB cap; no offer sent",
          flush=True)


# ---------------------------------------------------------- 11. relay
@case("11. relay sees metadata only; E2E box stays opaque")
def t_relay_visibility():
    import relay as relay_mod  # noqa: E402

    server, thread = relay_mod.run("127.0.0.1", 0)
    port = server.server_address[1]
    try:
        cli_a, pid_a = relay_mod.RelayClient.connect(
            "127.0.0.1", port, alice.identity.ed_priv)
        cli_b, pid_b = relay_mod.RelayClient.connect(
            "127.0.0.1", port, bob.identity.ed_priv)
        try:
            assert pid_a == alice.peer_id and pid_b == bob.peer_id
            # what a relay operator (or wire observer) sees:
            env = make_e2e_envelope(
                MSG, alice.peer_id, bob.peer_id,
                {"text": "relay must not read this",
                 "msg_id": "m-relay-1"},
                alice.identity.ed_priv, alice.identity.x_priv,
                alice.identity.x_pub, bob_x_pub())
            frame = canonical(env)
            cli_a.send_frame(frame)
            got = cli_b.recv_frame(timeout=10)
            assert got == frame, "relay did not forward exact bytes"
            seen = json.loads(got.decode("utf-8"))
            # routing metadata is visible (needed to route)
            assert seen["from"] == alice.peer_id
            assert seen["to"] == bob.peer_id
            assert seen["kind"] == "msg"
            # ...but the content is ciphertext only
            assert "payload" not in seen and "box" in seen
            assert isinstance(seen["box"]["ct"], str)
            # nobody without bob's X25519 key can read it
            _, wrong_priv = generate_x25519_keypair()
            expect_acp_error(
                lambda: open_e2e_envelope(seen, bob._get_pubkey,
                                          wrong_priv),
                "DECRYPT_FAIL")
            # bob can
            pt = open_e2e_envelope(seen, bob._get_pubkey,
                                   bob.identity.x_priv)
            assert pt["text"] == "relay must not read this"
            # offline target: relay answers, does not swallow
            dead = make_envelope(
                PRESENCE, alice.peer_id, "acp_agent_deadbeef",
                {"state": "online"}, alice.identity.ed_priv)
            cli_a.send_frame(canonical(dead))
            resp = cli_a.recv_json(timeout=10)
            assert resp == {"relayed": False, "to": "acp_agent_deadbeef",
                            "error": "offline"}, resp
        finally:
            cli_a.close()
            cli_b.close()
    finally:
        relay_mod.graceful_shutdown(server, thread)
    print("   relay routes on metadata; box opaque; offline -> error",
          flush=True)


def main():
    fns = [t_forged_signature, t_replay, t_wrong_code, t_mitm,
           t_chunk_tamper, t_permission_escalation, t_expired,
           t_unknown_sender, t_wrong_recipient, t_oversized_file,
           t_relay_visibility]
    for fn in fns:
        name = fn._name
        t0 = time.time()
        try:
            fn()
        except Exception as e:
            FAIL.append((name, e))
            print(f"FAIL {name}: {type(e).__name__}: {e}", flush=True)
            import traceback
            traceback.print_exc()
        else:
            PASS.append(name)
            print(f"PASS {name} ({time.time()-t0:.1f}s)", flush=True)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed", flush=True)
    for c in CONNS:
        try:
            c.stop()
        except Exception:
            pass
    for h in HOMES:
        shutil.rmtree(h, ignore_errors=True)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
