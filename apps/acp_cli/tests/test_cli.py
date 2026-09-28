"""End-to-end CLI test: two AcpShell instances, sharing nothing but localhost.

Flow: init two homes -> serve on two (ephemeral) ports -> pair -> read the
responder's code from its captured stdout -> confirm -> peers on both sides
-> msg -> inbox -> grant + family-add + family-list visibility -> send-file.

Run:  python tests/test_cli.py        (from apps/acp_cli)
   or python -m pytest tests/test_cli.py
"""
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

CLI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, CLI_DIR)

from cli import AcpShell, init_home, build_shell  # noqa: E402

PASSPHRASE = "cli-test-passphrase"


def wait_for(pred, timeout=20, tick=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(tick)
    return False


class CliTwoAgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="acp_cli_test_")
        self.home_a = os.path.join(self.tmp, "alice")
        self.home_b = os.path.join(self.tmp, "bob")
        self.shells = []

    def tearDown(self):
        for s in self.shells:
            try:
                s.conn.stop()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _serve(self, home, handle):
        init_home(home, handle, PASSPHRASE)
        shell = build_shell(home, PASSPHRASE, "127.0.0.1", 0)
        self.shells.append(shell)
        return shell

    def _pair(self, shell_a, shell_b, out):
        """Pair a (initiator) with b (responder); code read from b's stdout."""
        port_b = shell_b.server_addr[1]
        with contextlib.redirect_stdout(out):
            shell_a.onecmd("pair 127.0.0.1 %d" % port_b)
            ok = wait_for(
                lambda: re.search(r"Your code:\s*([A-Z2-9]{6})",
                                  out.getvalue()) is not None,
                timeout=20)
            self.assertTrue(ok, "responder never printed a pairing code")
            code = re.search(r"Your code:\s*([A-Z2-9]{6})",
                             out.getvalue()).group(1)
            ok = wait_for(
                lambda: shell_a._pending_pair is not None
                and shell_a._pending_pair.state == "await_code",
                timeout=20)
            self.assertTrue(ok, "initiator never reached await_code")
            shell_a.onecmd("confirm " + code)
        self.assertEqual(shell_a._pending_pair.state, "done",
                         "initiator pairing did not complete; output:\n%s"
                         % out.getvalue())
        ok = wait_for(
            lambda: any(p["agent_id"] == shell_a.conn.peer_id
                        for p in shell_b.conn.list_peers()),
            timeout=20)
        self.assertTrue(ok, "responder never stored the peer")
        return code

    def test_full_flow(self):
        alice = self._serve(self.home_a, "alice")
        bob = self._serve(self.home_b, "bob")
        pid_a = alice.conn.peer_id
        pid_b = bob.conn.peer_id
        self.assertNotEqual(pid_a, pid_b)

        out = io.StringIO()

        # ---- pair + confirm (code parsed from responder's stdout) ----
        with contextlib.redirect_stdout(out):
            self._pair(alice, bob, out)
        text = out.getvalue()
        self.assertIn("PAIRING REQUEST from 'alice'", text)
        self.assertIn("Waiting for code", text)
        self.assertIn("Paired with 'bob'", text)
        self.assertIn("Paired with 'alice'", text)

        # ---- peers shows both sides ----
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("peers")
            bob.onecmd("peers")
        peers_out = buf.getvalue()
        self.assertIn(pid_b[:16], peers_out)
        self.assertIn(pid_a[:16], peers_out)
        self.assertIn("bob", peers_out)
        self.assertIn("alice", peers_out)

        # ---- msg + live print + inbox ----
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("msg %s hello from alice" % pid_b)
        sent_out = buf.getvalue()
        self.assertIn("sent (", sent_out)
        ok = wait_for(lambda: "hello from alice" in buf.getvalue()
                      and "MSG from %s" % pid_a[:12] in buf.getvalue(),
                      timeout=20)
        self.assertTrue(ok, "bob never printed the live message; got:\n%s"
                        % buf.getvalue())

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bob.onecmd("inbox")
        self.assertIn("hello from alice", buf.getvalue())

        # ---- grant + family visibility ----
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("grant %s family_read" % pid_b)
            alice.onecmd("perms %s" % pid_b)
        self.assertIn("family_read", buf.getvalue())

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd('family-add Mom mother "lives in Houston" %s'
                         % pid_b)
            alice.onecmd('family-add Secret sibling "hidden notes" ""')
        add_out = buf.getvalue()
        self.assertIn("family member added: fam_", add_out)

        # owner sees everything
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("family-list")
        owner_view = buf.getvalue()
        self.assertIn("Mom", owner_view)
        self.assertIn("Secret", owner_view)

        # bob's gated preview: sees Mom, not Secret
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("family-list %s" % pid_b)
        bob_view = buf.getvalue()
        self.assertIn("Mom", bob_view)
        self.assertNotIn("Secret", bob_view)

        # ---- send-file ----
        payload = os.path.join(self.tmp, "note.txt")
        with open(payload, "w") as f:
            f.write("hello file world " * 100)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("send-file %s %s" % (pid_b, payload))
        ok = wait_for(lambda: "FILE received: note.txt" in buf.getvalue(),
                      timeout=60)
        self.assertTrue(ok, "bob never printed FILE received; got:\n%s"
                        % buf.getvalue())
        self.assertIn("sha256 ok", buf.getvalue())
        received = os.path.join(bob.conn.incoming_dir, "note.txt")
        ok = wait_for(lambda: os.path.isfile(received), timeout=10)
        self.assertTrue(ok, "file never landed in bob's incoming dir")
        with open(received) as f:
            self.assertEqual(f.read(), "hello file world " * 100)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bob.onecmd("files")
        self.assertIn("note.txt", buf.getvalue())

        # ---- error paths stay clean (no tracebacks) ----
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            alice.onecmd("bogus-command-xyz")
            alice.onecmd("msg deadbeef hello")
            alice.onecmd("grant %s not_a_perm" % pid_b)
        err_out = buf.getvalue()
        self.assertIn("unknown command", err_out)
        self.assertIn("ERROR NOT_FOUND", err_out)
        self.assertIn("ERROR INTERNAL", err_out)
        self.assertNotIn("Traceback", err_out)

    def test_init_is_idempotent(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pid1 = init_home(self.home_a, "alice", PASSPHRASE)
        with contextlib.redirect_stdout(buf):
            pid2 = init_home(self.home_a, "alice", PASSPHRASE)
        self.assertEqual(pid1, pid2)
        self.assertIn("peer id: %s" % pid1, buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
