"""End-to-end CLI test: two AcpShell instances, sharing nothing but localhost.

Flow: init two homes -> serve on two (ephemeral) ports -> pair -> read the
responder's code from its captured stdout -> confirm -> peers on both sides
-> msg -> inbox -> grant + family-add + family-list visibility -> send-file.

Run:  python tests/test_cli.py        (from apps/acp_cli)
   or python -m pytest tests/test_cli.py
"""
import contextlib
import io
import json
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
import cli  # noqa: E402  (module object, for monkeypatching cli.Connector)
from cli import build_parser, main  # noqa: E402
from acp_connector import AcpError  # noqa: E402

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


# ---------------------------------------------------------------------------
# Workstream E: one-shot subcommand tests.
#
# Argparse-level tests (no network, no Connector) plus dispatch tests that
# run main() against a fake Connector (monkeypatched onto cli.Connector).
# ---------------------------------------------------------------------------

def _msg(mid, sender, text, read_at=0, reply_to=None, created_at=1727575200):
    return {"message_id": mid, "sender_id": sender, "scope": "direct",
            "scope_id": None, "text": text, "timestamp": created_at,
            "status": "delivered", "created_at": created_at,
            "read_at": read_at, "reply_to": reply_to, "auto": 0}


class FakeGroups:
    def __init__(self):
        self.groups = []        # [{"group_id", "name"}]
        self.channels = {}      # gid -> {"members", "project_id", "topic"}
        self.history = {}       # gid -> [rows]
        self.opened = []        # (name, member_pids, project_id, topic)
        self.posted = []        # (gid, text, reply_to, refs)
        self.linked = []        # (gid, project_id)

    def list_groups(self):
        return [{"group_id": g["group_id"], "name": g["name"],
                 "admin_id": "me", "epoch": 1,
                 "created_by": "me", "created_at": 1}
                for g in self.groups]

    def get_channel(self, gid):
        for g in self.groups:
            if g["group_id"] == gid:
                info = self.channels.get(gid, {})
                return {"group_id": gid, "name": g["name"],
                        "members": info.get("members", []),
                        "project_id": info.get("project_id"),
                        "topic": info.get("topic", "")}
        return None

    def get_channel_history(self, gid, limit=100):
        return self.history.get(gid, [])[:limit]

    def open_channel(self, name, member_pids, project_id=None, topic=""):
        gid = "grp%08d" % (len(self.groups) + 1)
        self.groups.append({"group_id": gid, "name": name})
        self.channels[gid] = {"members": list(member_pids),
                              "project_id": project_id, "topic": topic}
        self.opened.append((name, list(member_pids), project_id, topic))
        return gid

    def send_channel_message(self, gid, text, reply_to=None, refs=None):
        self.posted.append((gid, text, reply_to, list(refs or [])))
        return "chmsg%08d" % len(self.posted)

    def link_project(self, gid, project_id):
        self.linked.append((gid, project_id))


class FakeConnector:
    """Stands in for acp_connector.Connector in one-shot dispatch tests."""

    def __init__(self, home, passphrase):
        self.home = home
        self.passphrase = passphrase
        self.peer_id = "mepeerid0123456789abcdef"
        self.handle = "tester"
        self.peers = []
        self.inbox_rows = []
        self.messages = {}
        self.thread_rows = []
        self.marked = []
        self.presence_rows = []
        self.presence_set_calls = []
        self.typing_calls = []
        self.sent = []
        self.replied = []
        self.relay_url = None
        self.stopped = False
        self.groups = FakeGroups()

    # -- messaging --
    def send_message(self, peer_pid, text, **kw):
        self.sent.append((peer_pid, text, kw))
        return "mid_" + peer_pid[:8]

    def send_reply(self, peer_pid, reply_to_msg_id, text):
        self.replied.append((peer_pid, reply_to_msg_id, text))
        return "mid_reply_1234"

    def inbox(self, limit=50, unread_only=False, peer_pid=None):
        rows = self.inbox_rows
        if unread_only:
            rows = [r for r in rows if not r.get("read_at")]
        if peer_pid is not None:
            rows = [r for r in rows if r.get("sender_id") == peer_pid]
        return rows[:limit]

    def get_message(self, message_id):
        return self.messages.get(message_id)

    def mark_read(self, message_id):
        self.marked.append(message_id)

    def get_thread(self, message_id):
        if message_id not in self.messages:
            raise AcpError("NOT_FOUND", "unknown message %s" % message_id)
        return self.thread_rows

    # -- peers --
    def list_peers(self, include_revoked=False):
        return [{"agent_id": p, "display_name": "?%s" % p[:6],
                 "revoked": False} for p in self.peers]

    # -- presence / typing --
    def set_presence(self, state):
        if state not in ("online", "offline", "busy", "paused", "unknown"):
            raise AcpError("INTERNAL", "bad presence state")
        self.presence_set_calls.append(state)

    def get_presence(self, peer_pid):
        for r in self.presence_rows:
            if r["agent_id"] == peer_pid:
                return r
        return {"agent_id": peer_pid, "status": "unknown", "updated_at": 0}

    def list_presence(self):
        return self.presence_rows

    def typing_start(self, peer_pid):
        self.typing_calls.append(("start", peer_pid))

    def typing_stop(self, peer_pid):
        self.typing_calls.append(("stop", peer_pid))

    def typing_start_group(self, gid):
        self.typing_calls.append(("gstart", gid))

    def typing_stop_group(self, gid):
        self.typing_calls.append(("gstop", gid))

    # -- lifecycle --
    def relay_connect(self, url):
        self.relay_url = url

    def stop(self):
        self.stopped = True


class ArgParseTest(unittest.TestCase):
    """Each new subcommand parses; --help smoke for all."""

    NEW_COMMANDS = ["inbox", "inbox-read", "inbox-thread", "send", "reply",
                    "presence", "typing", "channel-create", "channel-list",
                    "channel-post", "channel-history", "channel-link",
                    "autopilot-status"]

    def test_top_help_lists_all_new_commands(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                build_parser().parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)
        text = buf.getvalue()
        for name in self.NEW_COMMANDS:
            self.assertIn(name, text, "acp --help missing %s" % name)

    def test_each_subcommand_help_smoke(self):
        for name in self.NEW_COMMANDS:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    build_parser().parse_args([name, "--help"])
            self.assertEqual(cm.exception.code, 0, name)
            self.assertTrue(buf.getvalue().strip(), name)

    def test_parses(self):
        p = build_parser()
        cases = [
            (["inbox", "--home", "h"],
             {"cmd": "inbox", "limit": 50, "unread": False, "peer": None}),
            (["inbox", "--home", "h", "--limit", "5", "--unread",
              "--peer", "abc"],
             {"limit": 5, "unread": True, "peer": "abc"}),
            (["inbox-read", "m1", "--home", "h"], {"msg_id": "m1"}),
            (["inbox-thread", "m1", "--home", "h"], {"msg_id": "m1"}),
            (["send", "p1", "hello", "world", "--home", "h",
              "--url", "wss://x"],
             {"pid": "p1", "text": ["hello", "world"],
              "url": "wss://x"}),
            (["reply", "p1", "m1", "ok", "--home", "h"],
             {"pid": "p1", "msg_id": "m1", "text": ["ok"],
              "url": None}),
            (["presence", "--home", "h"],
             {"set": None, "peer": None}),
            (["presence", "--home", "h", "--set", "busy"],
             {"set": "busy"}),
            (["presence", "--home", "h", "--peer", "p1"],
             {"peer": "p1"}),
            (["typing", "p1", "start", "--home", "h"],
             {"target": "p1", "action": "start", "group": False}),
            (["typing", "g1", "stop", "--group", "--home", "h"],
             {"target": "g1", "action": "stop", "group": True}),
            (["channel-create", "ops", "p1", "p2", "--home", "h",
              "--project", "pr1", "--topic", "t"],
             {"name": "ops", "members": ["p1", "p2"],
              "project": "pr1", "topic": "t"}),
            (["channel-list", "--home", "h"], {"cmd": "channel-list"}),
            (["channel-post", "g1", "hi", "--home", "h",
              "--reply-to", "r1", "--ref", "t1", "--ref", "t2"],
             {"group_id": "g1", "text": ["hi"], "reply_to": "r1",
              "ref": ["t1", "t2"]}),
            (["channel-history", "g1", "--home", "h", "--limit", "7"],
             {"group_id": "g1", "limit": 7}),
            (["channel-link", "g1", "pr9", "--home", "h"],
             {"group_id": "g1", "project_id": "pr9"}),
            (["autopilot-status", "--home", "h"],
             {"cmd": "autopilot-status"}),
        ]
        for argv, expect in cases:
            a = p.parse_args(argv)
            for k, v in expect.items():
                self.assertEqual(getattr(a, k), v,
                                 "%s: %s" % (argv, k))

    def test_presence_set_and_peer_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["presence", "--home", "h", "--set", "busy", "--peer", "p1"])

    def test_typing_action_choices(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["typing", "p1", "hover", "--home", "h"])


class OneShotDispatchTest(unittest.TestCase):
    """main() dispatch against a fake Connector (no network)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="acp_oneshot_")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        # satisfy the initialized-home check in _open()
        open(os.path.join(self.home, "connector.db"), "w").close()
        self._real_connector = cli.Connector
        self.conns = []

        def factory(home, passphrase):
            fake = FakeConnector(home, passphrase)
            self.conns.append(fake)
            return fake

        cli.Connector = factory

    def tearDown(self):
        cli.Connector = self._real_connector
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, argv):
        buf = io.StringIO()
        # --passphrase is a top-level flag: it must precede the subcommand.
        with contextlib.redirect_stdout(buf):
            rc = main(["--passphrase", "test"] + argv +
                      ["--home", self.home])
        return rc, buf.getvalue()

    @property
    def conn(self):
        return self.conns[-1]

    # ------------------------------------------------------------ inbox
    def test_inbox_lists_newest_first_with_markers(self):
        me = "mepeerid0123456789abcdef"
        peer = "peerABCDEF0123456789"
        fake_holder = {}

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.inbox_rows = [
                _msg("m3", me, "my outbound", read_at=5),
                _msg("m2", peer, "seen inbound", read_at=9,
                     created_at=1727575100),
                _msg("m1", peer, "fresh inbound", reply_to="m0abcdef",
                     created_at=1727575000),
            ]
            fake_holder["f"] = fake
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["inbox"])
        self.assertEqual(rc, 0)
        lines = [l for l in out.splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)
        # newest first: m3, m2, m1
        self.assertIn("my outbound", lines[0])
        self.assertIn("seen inbound", lines[1])
        self.assertIn("fresh inbound", lines[2])
        # unread marker only on m1
        self.assertTrue(lines[0].startswith(" "))
        self.assertTrue(lines[1].startswith(" "))
        self.assertTrue(lines[2].startswith("*"))
        # sender rendering: "you" for outbound, short pid for inbound
        self.assertIn("you", lines[0])
        self.assertIn(peer[:12], lines[1])
        # reply_to indicator on m1
        self.assertIn("re:", lines[2])
        self.assertNotIn("re:", lines[0])
        self.assertTrue(fake_holder["f"].stopped)

    def test_inbox_empty(self):
        rc, out = self.run_main(["inbox"])
        self.assertEqual(rc, 0)
        self.assertIn("(inbox empty)", out)

    def test_inbox_unread_and_peer_filters(self):
        peer = "peerABCDEF0123456789"
        other = "otherPEER9999999999"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer, other]
            fake.inbox_rows = [
                _msg("m2", other, "unread other"),
                _msg("m1", peer, "unread from peer", created_at=1727575000),
            ]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["inbox", "--unread", "--peer", "peerA"])
        self.assertEqual(rc, 0)
        self.assertIn("unread from peer", out)
        self.assertNotIn("unread other", out)

    def test_inbox_unknown_peer_prefix(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = ["peerABCDEF0123456789"]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["inbox", "--peer", "nobody"])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR NOT_FOUND", out)

    def test_inbox_read_prints_all_fields_then_marks_read(self):
        m = _msg("m1", "peerABCDEF0123456789", "hello there",
                 reply_to="m0")

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.messages = {"m1": dict(m)}
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["inbox-read", "m1"])
        self.assertEqual(rc, 0)
        for field in ("message_id", "sender_id", "scope", "scope_id",
                      "text", "timestamp", "status", "created_at",
                      "read_at", "reply_to", "auto"):
            self.assertIn(field + ":", out)
        self.assertIn("hello there", out)
        self.assertIn("(marked read)", out)
        self.assertEqual(self.conn.marked, ["m1"])

    def test_inbox_read_unknown_id(self):
        rc, out = self.run_main(["inbox-read", "nope"])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR NOT_FOUND", out)

    def test_inbox_thread_indents_by_depth(self):
        me = "mepeerid0123456789abcdef"
        peer = "peerABCDEF0123456789"
        root = _msg("r", peer, "root", created_at=1727575000)
        c1 = _msg("c1", me, "child1", reply_to="r", created_at=1727575100)
        c2 = _msg("c2", peer, "child2", reply_to="c1", created_at=1727575200)

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.messages = {"r": root, "c1": c1, "c2": c2}
            fake.thread_rows = [root, c1, c2]  # oldest-first
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["inbox-thread", "c2"])
        self.assertEqual(rc, 0)
        lines = [l for l in out.splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("["), lines[0])
        self.assertTrue(lines[1].startswith("  ["), lines[1])
        self.assertTrue(lines[2].startswith("    ["), lines[2])
        self.assertIn("you", lines[1])  # c1 is outbound -> "you"

    def test_inbox_thread_unknown_id(self):
        rc, out = self.run_main(["inbox-thread", "nope"])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR NOT_FOUND", out)

    # ------------------------------------------------------------ presence
    def test_presence_table(self):
        me = "mepeerid0123456789abcdef"
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.presence_rows = [
                {"agent_id": me, "status": "online", "updated_at": 1727575200},
                {"agent_id": peer, "status": "busy", "updated_at": 1727575100},
            ]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["presence"])
        self.assertEqual(rc, 0)
        self.assertIn("PEER", out)
        self.assertIn("you", out)
        self.assertIn("online", out)
        self.assertIn(peer[:12], out)
        self.assertIn("busy", out)

    def test_presence_set(self):
        rc, out = self.run_main(["presence", "--set", "busy"])
        self.assertEqual(rc, 0)
        self.assertIn("presence set: busy", out)
        self.assertEqual(self.conn.presence_set_calls, ["busy"])

    def test_presence_peer(self):
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer]
            fake.presence_rows = [
                {"agent_id": peer, "status": "paused",
                 "updated_at": 1727575100}]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["presence", "--peer", "peerA"])
        self.assertEqual(rc, 0)
        self.assertIn("paused", out)

    # ------------------------------------------------------------ channels
    def test_channel_list(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            gid = fake.groups.open_channel(
                "ops", ["mepeerid0123456789abcdef", "peerABCDEF0123456789"],
                project_id="proj_9", topic="releases")
            fake.groups.open_channel("random", ["mepeerid0123456789abcdef"])
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["channel-list"])
        self.assertEqual(rc, 0)
        self.assertIn("ops", out)
        self.assertIn("proj_9", out)
        self.assertIn("releases", out)
        self.assertIn("random", out)
        self.assertIn("GROUP", out)

    def test_channel_history(self):
        me = "mepeerid0123456789abcdef"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            gid = fake.groups.open_channel("ops", [me])
            fake.groups.history[gid] = [
                {"message_id": "h1", "epoch": 1, "seq": 1,
                 "sender_id": "peerABCDEF0123456789", "text": "first",
                 "ts": 1727575000, "reply_to": None, "refs": []},
                {"message_id": "h2", "epoch": 1, "seq": 2,
                 "sender_id": me, "text": "second",
                 "ts": 1727575100, "reply_to": "h1", "refs": ["task_1"]},
            ]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["channel-history", "grp0"])
        self.assertEqual(rc, 0)
        i1, i2 = out.index("first"), out.index("second")
        self.assertLess(i1, i2)  # oldest first
        self.assertIn("re:", out)
        self.assertIn("task_1", out)
        self.assertIn("you", out)

    def test_channel_create(self):
        p1, p2 = "peerAAA111111111111", "peerBBB222222222222"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [p1, p2]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["channel-create", "ops", "peerA", "peerB",
                                 "--project", "pr1", "--topic", "t1"])
        self.assertEqual(rc, 0)
        self.assertIn("channel created: grp", out)
        self.assertEqual(self.conn.groups.opened,
                         [("ops", [p1, p2], "pr1", "t1")])

    def test_channel_post(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.groups.open_channel("ops", ["mepeerid0123456789abcdef"])
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["channel-post", "grp0", "hello", "world",
                                 "--reply-to", "r1", "--ref", "t1",
                                 "--ref", "t2"])
        self.assertEqual(rc, 0)
        self.assertIn("sent (", out)
        self.assertEqual(self.conn.groups.posted,
                         [("grp00000001", "hello world", "r1",
                           ["t1", "t2"])])

    def test_channel_link(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.groups.open_channel("ops", ["mepeerid0123456789abcdef"])
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["channel-link", "grp0", "proj9"])
        self.assertEqual(rc, 0)
        self.assertIn("linked to project proj9", out)
        self.assertEqual(self.conn.groups.linked, [("grp00000001", "proj9")])

    # ------------------------------------------------------------ send/reply/typing
    def test_send(self):
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["send", "peerA", "hello", "there"])
        self.assertEqual(rc, 0)
        self.assertIn("sent (", out)
        self.assertEqual(self.conn.sent, [(peer, "hello there", {})])
        self.assertIsNone(self.conn.relay_url)  # no --url: no relay connect

    def test_send_with_url_connects_relay_first(self):
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["send", "peerA", "hi",
                                 "--url", "wss://relay.example/acp"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.conn.relay_url, "wss://relay.example/acp")
        self.assertEqual(self.conn.sent, [(peer, "hi", {})])

    def test_send_ambiguous_prefix(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = ["ab11111111111111", "ab22222222222222"]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["send", "ab", "hi"])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR INTERNAL", out)
        self.assertIn("ambiguous", out)

    def test_reply(self):
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["reply", "peerA", "m0", "got", "it"])
        self.assertEqual(rc, 0)
        self.assertIn("sent (", out)
        self.assertEqual(self.conn.replied, [(peer, "m0", "got it")])

    def test_typing_peer(self):
        peer = "peerABCDEF0123456789"

        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.peers = [peer]
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["typing", "peerA", "start"])
        self.assertEqual(rc, 0)
        self.assertIn("typing start ->", out)
        self.assertEqual(self.conn.typing_calls, [("start", peer)])

    def test_typing_group_stop(self):
        def factory2(home, passphrase):
            fake = FakeConnector(home, passphrase)
            fake.groups.open_channel("ops", ["mepeerid0123456789abcdef"])
            self.conns.append(fake)
            return fake

        cli.Connector = factory2
        rc, out = self.run_main(["typing", "grp0", "stop", "--group"])
        self.assertEqual(rc, 0)
        self.assertIn("group", out)
        self.assertEqual(self.conn.typing_calls, [("gstop", "grp00000001")])

    # ------------------------------------------------------------ autopilot
    def test_autopilot_status_no_config(self):
        rc, out = self.run_main(["autopilot-status"])
        self.assertEqual(rc, 0)
        self.assertIn("autopilot off (no config)", out)

    def test_autopilot_status_with_config(self):
        cfg = {"peers": {"peerABCDEF0123456789":
                         {"mode": "hook", "hook": "replybot",
                          "max_per_min": 6, "reply_to_auto": False}},
               "channels": {"grp00000001": {"mode": "echo"}}}
        with open(os.path.join(self.home, "autopilot.json"), "w") as f:
            json.dump(cfg, f)
        rc, out = self.run_main(["autopilot-status"])
        self.assertEqual(rc, 0)
        self.assertIn("autopilot on", out)
        self.assertIn("peers (1):", out)
        self.assertIn("channels (1):", out)
        self.assertIn("mode=hook", out)
        self.assertIn("hook=replybot", out)
        self.assertIn("mode=echo", out)

    def test_autopilot_status_invalid_config(self):
        with open(os.path.join(self.home, "autopilot.json"), "w") as f:
            f.write("{not json")
        rc, out = self.run_main(["autopilot-status"])
        self.assertEqual(rc, 0)
        self.assertIn("autopilot off (invalid config", out)

    # ------------------------------------------------------------ errors
    def test_uninitialized_home_errors(self):
        bare = os.path.join(self.tmp, "bare")
        os.makedirs(bare)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--passphrase", "test", "inbox", "--home", bare])
        self.assertEqual(rc, 1)
        self.assertIn("ERROR NOT_FOUND", buf.getvalue())

    def test_connector_is_stopped_after_each_command(self):
        rc, out = self.run_main(["inbox"])
        self.assertEqual(rc, 0)
        self.assertTrue(self.conn.stopped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
