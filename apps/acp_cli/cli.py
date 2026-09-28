#!/usr/bin/env python3
"""acp — command-line interface for the ACP 1.0 Agent Community connector.

Two subcommands:

    acp init  --home DIR --handle NAME   create identity + database
    acp serve --home DIR --port N         start the connector + interactive REPL

Stdlib only. No network except localhost (and the optional directory URL
the user passes to `register`, which is also expected to be local in V1).
"""
import argparse
import cmd
import functools
import getpass
import os
import re
import shlex
import sys
import threading
import time

CLI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(os.path.dirname(CLI_DIR))
sys.path.insert(0, os.path.join(PROJ_ROOT, "packages"))
sys.path.insert(0, os.path.join(PROJ_ROOT, "services"))

from acp_connector import Connector, PERMS, AcpError  # noqa: E402
from acp_proto import b62encode  # noqa: E402
from acp_api.client import DirectoryClient, DirectoryError  # noqa: E402

HANDLE_RE = re.compile(r"^[a-z0-9_]{3,32}$")
PRESENCE_STATES = ("online", "offline", "busy", "paused", "unknown")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def get_passphrase(args):
    """Passphrase precedence: --passphrase flag > ACP_PASSPHRASE env > prompt."""
    if getattr(args, "passphrase", None):
        return args.passphrase
    env = os.environ.get("ACP_PASSPHRASE")
    if env:
        return env
    return getpass.getpass("passphrase: ")


def _short(pid, n=12):
    pid = str(pid or "")
    return pid[:n] + "..." if len(pid) > n else pid


def _fmt_ts(ts):
    try:
        return time.strftime("%m-%d %H:%M", time.localtime(int(ts)))
    except (TypeError, ValueError):
        return "?"


def guard(fn):
    """REPL command wrapper: AcpError -> 'ERROR <code>: <detail>', never a
    traceback. KeyboardInterrupt aborts just the command, not the REPL."""
    @functools.wraps(fn)
    def wrapper(self, arg):
        try:
            return fn(self, arg)
        except AcpError as e:
            self._emit("ERROR %s: %s" % (e.code, e.detail or ""))
        except DirectoryError as e:
            self._emit("ERROR DIRECTORY: %s" % (e,))
        except KeyboardInterrupt:
            self._emit("interrupted")
        except Exception as e:  # noqa: BLE001 - REPL must never die
            self._emit("ERROR INTERNAL: %s: %s" % (type(e).__name__, e))
    return wrapper


# ---------------------------------------------------------------------------
# init / serve entry points
# ---------------------------------------------------------------------------

def init_home(home, handle, passphrase):
    """Create identity + DB at home. Idempotent: re-running prints the
    existing identity instead of overwriting it."""
    home = os.path.abspath(home)
    db_path = os.path.join(home, "connector.db")
    if os.path.exists(db_path):
        conn = Connector(home, passphrase)
        print("home already initialized at %s" % home)
    else:
        conn = Connector(home, passphrase, handle)
        print("identity created at %s" % home)
    try:
        print("handle:  %s" % conn.handle)
        print("peer id: %s" % conn.peer_id)
        return conn.peer_id
    finally:
        conn.stop()


def build_shell(home, passphrase, host="127.0.0.1", port=0):
    """Create a Connector, start its TCP server, and return a REPL shell
    with live-event callbacks registered (but do not enter the loop)."""
    conn = Connector(os.path.abspath(home), passphrase)
    actual = conn.start_server(host, port)
    shell = AcpShell(conn, server_addr=(host, actual))
    shell.register_callbacks()
    return shell


def serve_home(home, passphrase, host, port):
    home = os.path.abspath(home)
    if not os.path.exists(os.path.join(home, "connector.db")):
        print("ERROR NOT_FOUND: %s is not initialized "
              "(run: acp init --home %s --handle NAME first)" % (home, home))
        return 1
    shell = build_shell(home, passphrase, host, port)
    conn = shell.conn
    print("serving as '%s' (%s)" % (conn.handle, _short(conn.peer_id)))
    print("listening on %s:%d" % shell.server_addr)
    print("type 'help' for commands, 'quit' to exit.")
    try:
        shell.run_forever()
    finally:
        try:
            conn.stop()
        except Exception:
            pass
        print("stopped.")
    return 0


# ---------------------------------------------------------------------------
# the REPL
# ---------------------------------------------------------------------------

class AcpShell(cmd.Cmd):
    """Interactive ACP shell. All networked commands run against the local
    Connector; inbound events (pairing requests, messages, files) are
    printed live from the connector's reader threads."""

    def __init__(self, connector, server_addr=None, stdin=None, stdout=None):
        super().__init__(stdin=stdin, stdout=stdout)
        self.conn = connector
        self.server_addr = server_addr or ("?", 0)
        self.prompt = "acp(%s)> " % connector.handle
        self.intro = None
        # Let dashed names (family-add, send-file, ...) lex as one command
        # word; parseline() below maps them to do_family_add etc.
        self.identchars = self.identchars + "-"
        self._print_lock = threading.Lock()
        self._pending_pair = None      # initiator PairingSession from `pair`
        self._responder_sessions = []  # responder sessions (for announcements)
        self._dir_url = None           # last directory URL from `register`
        self.last_pair_code = None     # last code shown by a pairing request

    # ------------------------------------------------------------ plumbing
    def _emit(self, line):
        with self._print_lock:
            print(line, flush=True)

    def register_callbacks(self):
        self.conn.on_pairing_request(self._on_pair_request)
        self.conn.on_message(self._on_message)
        # Announce completed inbound file transfers (FileTransfer has no
        # receive callback; wrap the handler on this instance only).
        files = self.conn.files
        orig_done = files.handle_done

        def done_and_announce(env, payload):
            orig_done(env, payload)
            try:
                t = self.conn.store.get_transfer(payload.get("file_id"))
            except Exception:
                t = None
            if t is not None and t["state"] == "done":
                self._emit("FILE received: %s (%d bytes, sha256 ok)"
                           % (os.path.basename(t["name"] or "file"),
                              t["size"] or 0))

        files.handle_done = done_and_announce
        # Announce pairing completion on the responder side (the initiator
        # side is announced by the `confirm` command's welcome wait).
        pairing = self.conn.pairing
        orig_confirm = pairing.handle_confirm

        def confirm_and_announce(conn, env, payload):
            orig_confirm(conn, env, payload)
            self._emit("Paired with '%s' (%s)"
                       % (payload.get("handle", "?"),
                          _short(env.get("from", "?"))))

        pairing.handle_confirm = confirm_and_announce

    # ------------------------------------------------------- inbound events
    def _on_pair_request(self, session):
        """A pair_request arrived: auto-send the challenge (the human trust
        step is the 6-char code, confirmed out-of-band on the other side),
        then show the code to the local user."""
        self._responder_sessions.append(session)
        self.last_pair_code = session.code
        try:
            session.accept()
        except AcpError as e:
            self._emit("ERROR %s: %s" % (e.code, e.detail or ""))
            return
        self._emit("PAIRING REQUEST from '%s' (%s). Your code: %s"
                   % (session.peer_handle or "?", _short(session.peer_pid),
                      session.code))
        self._emit("Ask the other side to type:  confirm %s" % session.code)

    def _on_message(self, sender_pid, text, msg_id):
        self._emit("MSG from %s: %s" % (_short(sender_pid), text))

    # ------------------------------------------------------------ REPL core
    def parseline(self, line):
        # Accept dashed command names: `family-add` -> do_family_add.
        cmd, arg, line = super().parseline(line)
        if cmd:
            cmd = cmd.replace("-", "_")
        return cmd, arg, line

    def do_help(self, arg):
        # `help family-add` should find do_family_add's docstring.
        return super().do_help(arg.replace("-", "_") if arg else arg)

    def run_forever(self):
        """cmdloop that survives Ctrl-C (fresh prompt) and exits on
        Ctrl-D / quit."""
        first = True
        while True:
            try:
                self.cmdloop(intro=self.intro if first else None)
                return
            except KeyboardInterrupt:
                first = False
                self._emit("")

    def emptyline(self):
        pass  # don't repeat the last command on bare Enter

    def default(self, line):
        self._emit("unknown command '%s' — type 'help' for commands."
                   % line.strip().split(" ")[0])

    def do_EOF(self, arg):
        """Exit the shell (Ctrl-D)."""
        self._emit("")
        return True

    def do_quit(self, arg):
        """quit — stop the server and exit."""
        return True

    do_exit = do_quit

    # -------------------------------------------------------------- helpers
    def _argv(self, arg, minimum=0, usage=""):
        try:
            argv = shlex.split(arg)
        except ValueError as e:
            raise AcpError("INTERNAL", "could not parse arguments: %s" % e)
        if len(argv) < minimum:
            raise AcpError("INTERNAL", "usage: %s" % usage)
        return argv

    def _resolve_pid(self, prefix):
        """Unique-prefix peer lookup; raises AcpError on miss/ambiguity."""
        prefix = (prefix or "").strip()
        if not prefix:
            raise AcpError("NOT_FOUND", "empty peer id")
        peers = self.conn.list_peers(include_revoked=True)
        matches = [p["agent_id"] for p in peers
                   if p["agent_id"] == prefix
                   or p["agent_id"].startswith(prefix)]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise AcpError("NOT_FOUND", "unknown peer '%s'" % prefix)
        raise AcpError("INTERNAL",
                       "ambiguous peer prefix '%s' (%d matches)"
                       % (prefix, len(matches)))

    def _dir_client(self):
        if not self._dir_url:
            raise AcpError(
                "INTERNAL",
                "no directory configured — use: "
                "register <api_url> <handle> first")
        return DirectoryClient(self._dir_url)

    # -------------------------------------------------------------- commands
    @guard
    def do_myid(self, arg):
        """myid — print this agent's peer id and handle."""
        self._emit("peer id: %s" % self.conn.peer_id)
        self._emit("handle:  %s" % self.conn.handle)

    @guard
    def do_pair(self, arg):
        """pair <host> <port> — send a pairing request to another agent."""
        argv = self._argv(arg, 2, "pair <host> <port>")
        host, port_s = argv[0], argv[1]
        try:
            port = int(port_s)
        except ValueError:
            raise AcpError("INTERNAL", "port must be a number")
        session = self.conn.pair_initiate(host, port)
        self._pending_pair = session
        self._emit("Pairing request sent to %s:%d." % (host, port))
        self._emit("Waiting for code — type:  confirm <code shown on "
                   "other side>")

    @guard
    def do_confirm(self, arg):
        """confirm <code> — submit the pairing code shown on the other side."""
        code = arg.strip()
        if not code:
            raise AcpError("INTERNAL", "usage: confirm <code>")
        sess = self._pending_pair
        if sess is None:
            self._emit("no pending pairing — use: pair <host> <port> first")
            return
        if sess.state == "await_challenge":
            self._emit("challenge not received yet — wait a moment, then "
                       "retry: confirm <code>")
            return
        if sess.state == "done":
            self._emit("already paired with '%s' (%s)"
                       % (sess.peer_handle, _short(sess.peer_pid)))
            return
        sess.confirm(code)  # raises AcpError on bad/expired code
        deadline = time.time() + 20
        while sess.state not in ("done", "failed") \
                and time.time() < deadline:
            time.sleep(0.1)
        if sess.state == "done":
            self._emit("Paired with '%s' (%s)"
                       % (sess.peer_handle, _short(sess.peer_pid)))
        elif sess.state == "failed":
            self._emit("pairing failed — check: audit")
        else:
            self._emit("confirm sent; welcome not received yet — "
                       "check: peers")

    @guard
    def do_peers(self, arg):
        """peers — list paired peers (id, handle, presence, revoked)."""
        rows = self.conn.list_peers(include_revoked=True)
        if not rows:
            self._emit("(no paired peers yet — use: pair <host> <port>)")
            return
        self._emit("%-20s %-18s %-9s %s"
                   % ("PEER", "HANDLE", "PRESENCE", "REVOKED"))
        for p in rows:
            try:
                pres = self.conn.get_presence(p["agent_id"])["status"]
            except Exception:
                pres = "?"
            self._emit("%-20s %-18s %-9s %s"
                       % (_short(p["agent_id"], 16),
                          (p["display_name"] or "?")[:18], pres,
                          "yes" if p["revoked"] else ""))

    @guard
    def do_msg(self, arg):
        """msg <pid> <text...> — send an E2E-encrypted message (waits for ACK)."""
        argv = self._argv(arg, 2, "msg <pid> <text...>")
        pid = self._resolve_pid(argv[0])
        text = " ".join(argv[1:])
        mid = self.conn.send_message(pid, text)
        self._emit("sent (%s)" % _short(mid))

    @guard
    def do_inbox(self, arg):
        """inbox [--limit N] — show recent messages, oldest first."""
        limit = 20
        argv = self._argv(arg)
        if argv:
            if argv[0] == "--limit" and len(argv) > 1:
                limit = int(argv[1])
            else:
                try:
                    limit = int(argv[0])
                except ValueError:
                    raise AcpError("INTERNAL",
                                   "usage: inbox [--limit N]")
        rows = self.conn.store.list_messages(limit=limit)
        if not rows:
            self._emit("(inbox empty)")
            return
        me = self.conn.peer_id
        for m in reversed(rows):
            if m["sender_id"] == me:
                arrow, who = "->", "you"
            else:
                arrow, who = "<-", _short(m["sender_id"])
            text = m["text"] or ""
            if len(text) > 200:
                text = text[:197] + "..."
            self._emit("%s %s %-15s %s"
                       % (_fmt_ts(m["created_at"]), arrow, who, text))

    @guard
    def do_send_file(self, arg):
        """send-file <pid> <path> — offer a file; streams E2E once accepted."""
        argv = self._argv(arg, 2, "send-file <pid> <path>")
        pid = self._resolve_pid(argv[0])
        path = os.path.abspath(os.path.expanduser(argv[1]))
        if not os.path.isfile(path):
            raise AcpError("INTERNAL", "not a file: %s" % path)
        fid = self.conn.send_file(pid, path)
        self._emit("sent %s (%s)" % (os.path.basename(path), _short(fid)))

    @guard
    def do_files(self, arg):
        """files — list files received into this home's incoming directory."""
        incoming = self.conn.incoming_dir
        try:
            names = sorted(os.listdir(incoming))
        except OSError:
            names = []
        names = [n for n in names if not n.endswith(".part")]
        self._emit("incoming dir: %s" % incoming)
        if not names:
            self._emit("(no files received yet)")
            return
        for n in names:
            try:
                size = os.path.getsize(os.path.join(incoming, n))
            except OSError:
                size = -1
            self._emit("  %s (%d bytes)" % (n, size))

    @guard
    def do_family_add(self, arg):
        """family-add <name> <relation> <notes> <visible_to> — add a family
        member. visible_to is a comma-separated list of peer ids/prefixes,
        or '*' for every peer. Quote multi-word args."""
        argv = self._argv(arg, 4,
                          "family-add <name> <relation> <notes> <visible_to>")
        name, relation, notes, vis_s = argv[0], argv[1], argv[2], argv[3]
        visible_to = []
        for tok in [t.strip() for t in vis_s.split(",") if t.strip()]:
            if tok == "*":
                visible_to.append("*")
                continue
            try:
                visible_to.append(self._resolve_pid(tok))
            except AcpError:
                visible_to.append(tok)  # literal: full id or future peer
        fam_id = self.conn.family_add(name, relation, notes, visible_to)
        self._emit("family member added: %s" % fam_id)

    @guard
    def do_family_list(self, arg):
        """family-list [pid] — list family members. With a peer id, preview
        what that peer is allowed to see (needs their 'family_read' grant)."""
        argv = self._argv(arg)
        for_peer = None
        if argv:
            for_peer = self._resolve_pid(argv[0])
        members = self.conn.family_list(for_peer=for_peer)
        if not members:
            self._emit("(no family members%s)"
                       % (" visible to %s" % _short(for_peer)
                          if for_peer else ""))
            return
        for m in members:
            notes = (m["notes"] or "")
            if len(notes) > 60:
                notes = notes[:57] + "..."
            vis = ",".join(_short(v) for v in (m["visible_to"] or [])) or "-"
            self._emit("%s  name='%s' relation='%s' notes='%s' visible_to=[%s]"
                       % (m["id"], m["name"], m["relation"], notes, vis))

    @guard
    def do_project_create(self, arg):
        """project-create <title> <notes...> — create a project."""
        argv = self._argv(arg, 1, "project-create <title> <notes...>")
        title = argv[0]
        notes = " ".join(argv[1:])
        proj_id = self.conn.project_create(title, notes)
        self._emit("project created: %s" % proj_id)

    @guard
    def do_task_add(self, arg):
        """task-add <proj> <title> <assignee> <notes...> — add a task.
        assignee is a peer id/prefix, or 'none'."""
        argv = self._argv(arg, 3,
                          "task-add <proj> <title> <assignee> <notes...>")
        proj, title, assignee_s = argv[0], argv[1], argv[2]
        notes = " ".join(argv[3:])
        assignee = None
        if assignee_s.lower() not in ("none", "-"):
            assignee = self._resolve_pid(assignee_s)
        task_id = self.conn.task_add(proj, title, assignee, notes)
        self._emit("task added: %s" % task_id)

    @guard
    def do_task_list(self, arg):
        """task-list <proj> — show a project and its tasks."""
        argv = self._argv(arg, 1, "task-list <proj>")
        proj = self.conn.project_get(argv[0])
        self._emit("project %s: '%s'" % (proj["id"], proj["title"]))
        if proj["notes"]:
            self._emit("  notes: %s" % proj["notes"])
        if not proj["tasks"]:
            self._emit("  (no tasks)")
            return
        for t in proj["tasks"]:
            self._emit("  [%s] %s  assignee=%s  status=%s"
                       % (t["id"], t["title"],
                          _short(t["assignee"]) if t["assignee"] else "-",
                          t["status"]))

    @guard
    def do_grant(self, arg):
        """grant <pid> <perm> — grant a permission scope to a peer."""
        argv = self._argv(arg, 2, "grant <pid> <perm>")
        pid = self._resolve_pid(argv[0])
        scope = argv[1]
        if scope not in PERMS:
            raise AcpError("INTERNAL",
                           "unknown permission '%s' (choose from: %s)"
                           % (scope, ", ".join(PERMS)))
        self.conn.grant_permission(pid, scope)
        self._emit("granted '%s' to %s" % (scope, _short(pid)))

    @guard
    def do_revoke_perm(self, arg):
        """revoke-perm <pid> <perm> — revoke a permission scope from a peer."""
        argv = self._argv(arg, 2, "revoke-perm <pid> <perm>")
        pid = self._resolve_pid(argv[0])
        self.conn.revoke_permission(pid, argv[1])
        self._emit("revoked '%s' from %s" % (argv[1], _short(pid)))

    @guard
    def do_perms(self, arg):
        """perms <pid> — list a peer's permission grants."""
        argv = self._argv(arg, 1, "perms <pid>")
        pid = self._resolve_pid(argv[0])
        rows = self.conn.list_permissions(pid)
        if not rows:
            self._emit("(no grants for %s)" % _short(pid))
            return
        for r in rows:
            exp = (" expires=%s" % _fmt_ts(r["expires_at"])
                   if r["expires_at"] else "")
            self._emit("  %-14s granted_by=%-10s%s"
                       % (r["scope"], r["granted_by"], exp))

    @guard
    def do_revoke_peer(self, arg):
        """revoke-peer <pid> — sever trust with a peer (local tombstone,
        best-effort notice to the peer)."""
        argv = self._argv(arg, 1, "revoke-peer <pid>")
        pid = self._resolve_pid(argv[0])
        self.conn.revoke_peer(pid)
        self._emit("peer %s revoked" % _short(pid))

    @guard
    def do_presence(self, arg):
        """presence [state] — set your presence, or with no args show the
        presence table. state: online|offline|busy|paused|unknown."""
        argv = self._argv(arg)
        if argv:
            state = argv[0]
            if state not in PRESENCE_STATES:
                raise AcpError(
                    "INTERNAL",
                    "bad presence state '%s' (want one of: %s)"
                    % (state, "|".join(PRESENCE_STATES)))
            self.conn.set_presence(state)
            self._emit("presence set: %s" % state)
            return
        rows = self.conn.list_presence()
        if not rows:
            self._emit("(no presence records)")
            return
        for r in rows:
            who = "you" if r["agent_id"] == self.conn.peer_id \
                else _short(r["agent_id"])
            self._emit("  %-15s %-8s updated %s"
                       % (who, r["status"], _fmt_ts(r["updated_at"])))

    @guard
    def do_rotate_keys(self, arg):
        """rotate-keys — rotate the X25519 E2E keypair and broadcast
        KEY_ROTATE to all peers (peer id unchanged)."""
        self.conn.rotate_keys()
        self._emit("E2E keys rotated; KEY_ROTATE broadcast to peers.")

    @guard
    def do_register(self, arg):
        """register <api_url> <handle> — register this agent's handle with
        the directory (also remembers api_url for resolve/dir-presence)."""
        argv = self._argv(arg, 2, "register <api_url> <handle>")
        api_url, handle = argv[0], argv[1]
        if not HANDLE_RE.match(handle):
            raise AcpError("INTERNAL",
                           "handle must match [a-z0-9_]{3,32}")
        client = DirectoryClient(api_url)
        client.register(handle, self.conn.peer_id,
                        b62encode(self.conn.identity.x_pub))
        self._dir_url = api_url
        self._emit("registered handle '%s' at %s" % (handle, api_url))

    @guard
    def do_resolve(self, arg):
        """resolve <handle> — look up a handle in the directory.
        Note: V1 pairing still needs the peer's host:port — ask them for
        it, then: pair <host> <port>."""
        argv = self._argv(arg, 1, "resolve <handle>")
        resp = self._dir_client().resolve(argv[0])
        self._emit("handle '%s':" % resp.get("handle", argv[0]))
        self._emit("  ipub : %s" % _short(resp.get("ipub", ""), 16))
        self._emit("  x_pub: %s" % _short(resp.get("x_pub", ""), 16))
        self._emit("note: V1 pairing needs host:port — ask the peer, then:")
        self._emit("  pair <host> <port>")

    @guard
    def do_dir_presence(self, arg):
        """dir-presence <handle> <state> — publish presence to the directory
        (signed with your identity key)."""
        argv = self._argv(arg, 2, "dir-presence <handle> <state>")
        handle, state = argv[0], argv[1]
        if state not in PRESENCE_STATES:
            raise AcpError(
                "INTERNAL",
                "bad presence state '%s' (want one of: %s)"
                % (state, "|".join(PRESENCE_STATES)))
        self._dir_client().set_presence(handle, state,
                                        self.conn.identity.ed_priv)
        self._emit("directory presence for '%s': %s" % (handle, state))

    @guard
    def do_audit(self, arg):
        """audit [--limit N] — show recent audit events, newest first."""
        limit = 20
        argv = self._argv(arg)
        if argv:
            if argv[0] == "--limit" and len(argv) > 1:
                limit = int(argv[1])
            else:
                try:
                    limit = int(argv[0])
                except ValueError:
                    raise AcpError("INTERNAL",
                                   "usage: audit [--limit N]")
        rows = self.conn.audit_log(limit=limit)
        if not rows:
            self._emit("(audit log empty)")
            return
        for r in rows:
            actor = _short(r["actor"]) if r["actor"] != "local" else "local"
            target = (" -> %s" % _short(r["target"])) if r["target"] else ""
            self._emit("%s %-22s %-15s%s [%s]"
                       % (_fmt_ts(r["timestamp"]), r["action"], actor,
                          target, r["result"]))


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="acp",
                                description="ACP 1.0 agent community CLI")
    p.add_argument("--passphrase",
                   help="identity passphrase (else ACP_PASSPHRASE env, "
                        "else interactive prompt)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create identity + database")
    pi.add_argument("--home", required=True, help="home directory")
    pi.add_argument("--handle", required=True, help="agent handle")

    ps = sub.add_parser("serve", help="start connector + interactive REPL")
    ps.add_argument("--home", required=True, help="home directory")
    ps.add_argument("--port", required=True, type=int, help="listen port")
    ps.add_argument("--host", default="127.0.0.1", help="listen host")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "init":
            init_home(args.home, args.handle, get_passphrase(args))
            return 0
        if args.cmd == "serve":
            return serve_home(args.home, get_passphrase(args),
                              args.host, args.port)
    except AcpError as e:
        print("ERROR %s: %s" % (e.code, e.detail or ""))
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as e:  # noqa: BLE001
        print("ERROR INTERNAL: %s: %s" % (type(e).__name__, e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
