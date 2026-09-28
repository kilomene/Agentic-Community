"""ACP bridge: the vm-agent task engine speaks ACP 1.0.

An agent running on this runtime gets a network identity (the ACP Ed25519
identity) and can pair, message, transfer files, and install capability
packages over the agent network — as ordinary task-engine tools, gated by
the capability system (ACP_NETWORK), the policy layer (RESTRICTED), and
the verifier.

Design rules:
- stdlib only; the ACP stack (packages/acp_*) is imported lazily so this
  module stays importable even where the network layer isn't installed.
- The bridge holds at most one Connector per home directory, for the life
  of the agent process. Crash/restart loses only in-memory sessions;
  identity, peers, and messages persist in the connector's SQLite store.
- The passphrase is NEVER returned, logged, or journaled. It arrives via
  the runtime secrets vault ({"vault": "acp_passphrase"}) and is redacted
  by value from all tool output.
- Pairing is interactive by protocol design: the code is shown on the
  responder's side and typed on the initiator's side. The bridge exposes
  both sides (`pair` / `pair_confirm` for the initiator, `pair_requests` /
  `pair_accept` for the responder) so a task can drive either half.

Ops (op -> args):
  init            {handle, passphrase}            create/load ACP identity
  serve           {passphrase, host, port}        start TCP server
  identity        {passphrase}                    peer_id + handle
  pair            {passphrase, host, port}        initiate pairing (non-blocking)
  pair_status     {passphrase, session_id}        poll a pairing session's state
  pair_requests   {passphrase}                    pending inbound requests (responder)
  pair_accept     {passphrase, session_id}        accept an inbound request
  pair_confirm    {passphrase, session_id, code}  confirm outbound pairing
  message         {passphrase, peer, text}        send E2E message (waits for ack)
  inbox           {passphrase, limit}             recent messages
  peers           {passphrase}                    trusted peers
  send_file       {passphrase, peer, path}        send a file (sha256-verified)
  market_install  {passphrase, package_dir}       verify+quarantine a capability
                                                  package; validate task.json
  stop            {passphrase}                    shut the connector down
"""
import hashlib
import json
import os
import re
import sys
import threading
import time

_ACP = {}  # lazy-loaded modules: Connector, AcpError, manifest fns


def _load_acp():
    """Import the ACP stack, finding it in the monorepo or the install
    prefix. Raises AcpBridgeError if unavailable."""
    if _ACP:
        return _ACP
    try:
        from acp_connector import Connector
        from acp_proto import AcpError
    except ImportError:
        # repo layout: this file is runtime/src/acp_bridge.py, so the
        # monorepo root is two directories up from here.
        here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(here))
        pkgs = os.path.join(repo_root, "packages")
        if os.path.isdir(os.path.join(pkgs, "acp_connector")):
            sys.path.insert(0, pkgs)
        try:
            from acp_connector import Connector  # noqa: F811
            from acp_proto import AcpError  # noqa: F811
        except ImportError as e:
            raise AcpBridgeError(
                "ACP stack not installed: run install.sh from the "
                "Agentic-Community repo (it installs packages/acp_*), "
                f"or set PYTHONPATH. ({e})")
    _ACP["Connector"] = Connector
    _ACP["AcpError"] = AcpError
    return _ACP


class AcpBridgeError(Exception):
    pass


# task.json structural validation: tools and checks the runtime knows.
_KNOWN_TOOLS = {"shell", "write_file", "read_file", "mkdir", "http_get",
                "browser", "acp"}
_KNOWN_CHECKS = {"file_exists", "file_contains", "command_ok",
                 "port_listening", "http_ok", "process_running", "acp"}
# verifier + marketplace checks must stay side-effect free
_READONLY_OPS = {"identity", "inbox", "peers", "pair_requests"}


class AcpBridge:
    def __init__(self, cfg, journal=None):
        self.cfg = cfg or {}
        self._journal = journal
        base = self.cfg.get("base_dir") or os.path.expanduser("~/.vm-agent")
        self.acp_home = os.path.abspath(os.path.expanduser(
            self.cfg.get("acp_home") or os.path.join(base, "acp")))
        self._lock = threading.Lock()
        self._connectors = {}   # home -> Connector
        self._serving = {}      # home -> (host, port)
        self._pair_requests = {}  # home -> [PairingSession, ...]
        self._home = None       # default home, set by `init`

    # ------------------------------------------------------------ internals
    def _log(self, event, **kw):
        if self._journal:
            try:
                self._journal(event, **kw)
            except Exception:
                pass

    def _connector(self, passphrase, handle="agent", home=None):
        """Get-or-create the Connector for a home. The passphrase unlocks
        the Ed25519/X25519 keypair — it never leaves this call."""
        _load_acp()
        home = os.path.abspath(os.path.expanduser(
            home or self._home or self.acp_home))
        with self._lock:
            c = self._connectors.get(home)
            if c is None:
                c = _ACP["Connector"](home, passphrase, handle)
                reqs = self._pair_requests.setdefault(home, [])
                c.on_pairing_request(lambda s: reqs.append(s))
                # Auto-accept inbound file offers: files land in the
                # connector's quarantine-then-inbox flow (sha256-verified,
                # never executed) — the agent decides what to do with them.
                c.on_file_offer(lambda s, n, sz, h: True)
                self._connectors[home] = c
                self._log("ACP_CONNECTOR_OPENED", home=home,
                          peer_id=c.peer_id)
            return c

    def _wait(self, fn, timeout, what, interval=0.2):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(interval)
        raise AcpBridgeError(f"timeout waiting for {what}")

    def _wrap(self, fn, what):
        try:
            return fn()
        except AcpBridgeError:
            raise
        except Exception as e:
            AcpError = _ACP.get("AcpError", Exception)
            if isinstance(e, AcpError):
                raise AcpBridgeError(f"{what}: {e}")
            raise AcpBridgeError(f"{what}: {e!r}")

    # --------------------------------------------------------------- public
    def run(self, op, args):
        """Run one ACP op. Returns a JSON-serializable dict. Raises
        AcpBridgeError on failure (the tool layer turns it into a failed
        ToolResult — never a traceback)."""
        args = dict(args or {})
        passphrase = args.pop("passphrase", None)
        # Every op needs the passphrase: it unlocks the ACP Ed25519/X25519
        # keypair. Pass {"vault": "acp_passphrase"} — the runtime resolves
        # it at execution time and redacts it from every record.
        if not passphrase:
            raise AcpBridgeError(
                f"op '{op}' needs the ACP passphrase "
                "(pass {\"vault\": \"acp_passphrase\"} as 'passphrase')")
        handler = getattr(self, "_op_" + op, None)
        if handler is None:
            raise AcpBridgeError(
                f"unknown acp op: {op!r} (known: "
                + ", ".join(sorted(m[4:] for m in dir(self)
                                    if m.startswith("_op_"))) + ")")
        # Per-op home override; otherwise the home set by `init`.
        home = args.pop("home", None)
        if home:
            home = os.path.abspath(os.path.expanduser(home))
        self._log("ACP_OP", op=op)
        try:
            return handler(args, passphrase, home or self._home)
        except AcpBridgeError:
            raise
        except Exception as e:
            # Never leak tracebacks or crypto internals to the tool
            # result — a clean, actionable error instead.
            AcpError = _ACP.get("AcpError")
            if AcpError and isinstance(e, AcpError):
                raise AcpBridgeError(f"acp {op}: {e}")
            raise AcpBridgeError(f"acp {op}: {e!r}")

    # ------------------------------------------------------------------ ops
    def _op_init(self, args, passphrase, home):
        handle = args.get("handle", "agent")
        home = os.path.abspath(os.path.expanduser(
            home or self.acp_home))
        existed = os.path.exists(os.path.join(home, "connector.db"))
        c = self._wrap(lambda: self._connector(passphrase, handle, home),
                       "acp init")
        self._home = home  # subsequent ops default to this identity
        return {"peer_id": c.peer_id, "handle": c.handle, "home": home,
                "created": not existed}

    def _op_serve(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        home = c.home
        host = args.get("host", "127.0.0.1")
        port = int(args.get("port", 0))
        # Check, bind, and register under one lock: two concurrent serve
        # calls for the same home must not both bind a server (the loser
        # would leak a listener nobody can reach).
        with self._lock:
            if home in self._serving:
                host, port = self._serving[home]
                return {"host": host, "port": port, "already": True}
            actual = self._wrap(lambda: c.start_server(host, port),
                                "acp serve")
            self._serving[home] = (host, actual)
        return {"host": host, "port": actual, "already": False}

    def _op_identity(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        return {"peer_id": c.peer_id, "handle": c.handle,
                "serving": c.home in self._serving}

    def _op_pair(self, args, passphrase, home):
        """Initiator side: connect and send pair_request. Returns
        immediately — pairing is a multi-step dance by protocol design.
        Poll pair_status until "await_code", then have the responder's
        operator read the code off-band and call pair_confirm."""
        c = self._connector(passphrase, home=home)
        host = args.get("host", "127.0.0.1")
        port = int(args["port"])
        session = self._wrap(lambda: c.pair_initiate(host, port),
                             "acp pair")
        return {"session_id": session.session_id, "status": session.state,
                "note": "poll pair_status; when await_code, read the code "
                        "on the responder's side, then pair_confirm"}

    def _op_pair_status(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        session = c.pairing.get_session(args["session_id"])
        if session is None:
            # sessions also persist in the store; report that view
            row = c.store.get_pairing_session(args["session_id"])
            if row is None:
                raise AcpBridgeError("unknown pairing session")
            return {"session_id": args["session_id"],
                    "status": row.get("state"), "live": False}
        return {"session_id": session.session_id, "status": session.state,
                "peer_pid": session.peer_pid,
                "peer_handle": session.peer_handle, "live": True}

    def _op_pair_requests(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        reqs = self._pair_requests.get(c.home, [])
        live = [s for s in reqs if s.state == "await_accept"
                and not s.expired]
        return {"requests": [
            {"session_id": s.session_id, "peer_pid": s.peer_pid,
             "peer_handle": s.peer_handle, "code": s.code,
             "expires_at": s.expires_at} for s in live]}

    def _op_pair_accept(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        session = c.pairing.get_session(args["session_id"])
        if session is None:
            raise AcpBridgeError("unknown pairing session")
        self._wrap(session.accept, "acp pair_accept")
        return {"session_id": session.session_id, "status": session.state}

    def _op_pair_confirm(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        session = c.pairing.get_session(args["session_id"])
        if session is None:
            raise AcpBridgeError("unknown pairing session")
        self._wrap(lambda: session.confirm(args["code"]),
                   "acp pair_confirm")
        wait_s = float(args.get("wait_s", 60))

        def paired():
            p = c.store.get_peer(session.peer_pid or "")
            return p if p and not p.get("revoked") else None

        self._wait(paired, wait_s, "pairing completion")
        return {"session_id": session.session_id, "status": "done",
                "peer_id": session.peer_pid}

    def _op_message(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        peer = args["peer"]
        text = args.get("text", "")
        if not isinstance(text, str) or not text:
            raise AcpBridgeError("message text must be a non-empty string")
        msg_id = self._wrap(lambda: c.send_message(peer, text),
                            "acp message")
        return {"msg_id": msg_id, "peer": peer, "acked": True}

    def _op_inbox(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        limit = int(args.get("limit", 25))
        msgs = self._wrap(lambda: c.store.list_messages(limit=limit),
                          "acp inbox")
        out = []
        for m in msgs:
            out.append({
                "msg_id": m.get("message_id"),
                "direction": ("out" if m.get("sender_id") == c.peer_id
                              else "in"),
                "peer": (m.get("sender_id") if m.get("sender_id")
                         != c.peer_id else m.get("scope_id")),
                "text": (m.get("text") or "")[:2000],
                "ts": m.get("ts"),
                "status": m.get("status"),
            })
        return {"messages": out}

    def _op_peers(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        peers = self._wrap(c.store.list_peers, "acp peers")
        return {"peers": [
            {"peer_id": p.get("agent_id"),
             "handle": p.get("display_name"),
             "paired_at": p.get("paired_at")} for p in peers]}

    def _op_send_file(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        peer = args["peer"]
        path = os.path.abspath(os.path.expanduser(args["path"]))
        if not os.path.isfile(path):
            raise AcpBridgeError(f"not a file: {args['path']}")
        # Never exfiltrate the runtime's own protected trees (state DB
        # holds checkpoints, the journal, and capability grants).
        try:
            from . import policy as policymod
            ok, reason = policymod.Policy().authorize_path(
                self.cfg.get("base_dir") or "", path)
            if not ok:
                raise AcpBridgeError(f"refusing to send protected path: "
                                     f"{reason}")
        except ImportError:
            pass
        transfer_id = self._wrap(lambda: c.send_file(peer, path),
                                 "acp send_file")
        return {"transfer_id": transfer_id, "peer": peer, "path": path,
                "sha256": self._sha256(path)}

    def _op_market_install(self, args, passphrase, home):
        """Install an ACP capability package into quarantine: verify the
        manifest signature + file hashes, copy to the installs dir, and
        validate a bundled task.json (if any) as a runtime task spec.

        The package is NEVER executed at install time. Running it is a
        separate, explicit local action (submit the validated task spec).
        """
        from acp_marketplace import manifest as manifestmod
        c = self._connector(passphrase, home=home)
        pkg_dir = os.path.abspath(os.path.expanduser(args["package_dir"]))
        man_path = os.path.join(pkg_dir, "manifest.json")
        if not os.path.isfile(man_path):
            raise AcpBridgeError("package_dir must contain manifest.json")
        with open(man_path) as f:
            manifest = json.load(f)
        missing = [k for k in manifestmod.REQUIRED_FIELDS if k not in manifest]
        if missing:
            raise AcpBridgeError(f"manifest missing fields: {missing}")

        def get_pubkey(pid):
            peer = c.store.get_peer(pid)
            if not peer or not peer.get("ed_pub"):
                raise AcpBridgeError(
                    f"publisher {pid[:16]}… is not a trusted peer — "
                    "pair first, then install")
            return bytes.fromhex(peer["ed_pub"])

        self._wrap(lambda: manifestmod.verify_manifest(manifest, get_pubkey),
                   "market manifest signature")
        files = {}
        for entry in manifest["files"]:
            p = entry["path"]
            # same sanitization as the connector's file transfer
            from acp_connector.files import sanitize_filename
            if sanitize_filename(p) != p or "/" in p or "\\" in p:
                raise AcpBridgeError(f"unsafe package path: {p!r}")
            fp = os.path.join(pkg_dir, p)
            if not os.path.isfile(fp):
                raise AcpBridgeError(f"package file missing: {p}")
            with open(fp, "rb") as f:
                files[p] = f.read()
        self._wrap(lambda: manifestmod.verify_package_files(manifest, files),
                   "market package file hashes")
        # The signature proves a trusted peer signed this manifest, not
        # that name/version are safe path components — validate them
        # strictly and keep the install inside the quarantine dir.
        name, version = manifest["name"], manifest["version"]
        if not isinstance(name, str) or not isinstance(version, str) or \
                not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name) or \
                not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", version):
            raise AcpBridgeError("unsafe package name/version")
        installs = os.path.realpath(os.path.join(self.acp_home, "installs"))
        dest = os.path.realpath(os.path.join(installs, f"{name}-{version}"))
        if os.path.commonpath([installs, dest]) != installs:
            raise AcpBridgeError("refusing to install outside installs dir")
        os.makedirs(dest, exist_ok=True)
        for p, data in files.items():
            with open(os.path.join(dest, p), "wb") as f:
                f.write(data)
        with open(os.path.join(dest, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        c.audit.log("market.installed", result="ok",
                    details={"name": manifest["name"],
                             "version": manifest["version"],
                             "publisher": manifest["publisher_id"]})
        result = {"installed": True, "path": dest,
                  "name": manifest["name"], "version": manifest["version"],
                  "capabilities": manifest.get("capabilities", [])}
        # A capability package may ship a vm-agent task spec. Validate it
        # structurally; submitting it stays an explicit local action.
        task_path = os.path.join(dest, "task.json")
        if os.path.isfile(task_path):
            with open(task_path) as f:
                spec = json.load(f)
            valid, errors = self._validate_task_spec(spec)
            result["task_spec"] = {"present": True, "valid": valid,
                                   "errors": errors, "path": task_path}
        else:
            result["task_spec"] = {"present": False}
        return result

    def _op_stop(self, args, passphrase, home):
        c = self._connector(passphrase, home=home)
        home = c.home
        with self._lock:
            self._serving.pop(home, None)
            self._connectors.pop(home, None)
        self._wrap(c.stop, "acp stop")
        return {"stopped": True}

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def _validate_task_spec(cls, spec):
        """Structural validation of a task.json task spec (no execution)."""
        errors = []
        if not isinstance(spec, dict):
            return False, ["spec must be a JSON object"]
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps:
            return False, ["spec.steps must be a non-empty list"]
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"steps[{i}]: must be an object")
                continue
            tool = step.get("tool", "shell")
            if tool not in _KNOWN_TOOLS:
                errors.append(f"steps[{i}]: unknown tool {tool!r}")
            sargs = step.get("args", {})
            if not isinstance(sargs, dict):
                errors.append(f"steps[{i}]: args must be an object")
            for j, chk in enumerate(step.get("verify", []) or []):
                if not isinstance(chk, dict) or \
                        chk.get("check") not in _KNOWN_CHECKS:
                    errors.append(
                        f"steps[{i}].verify[{j}]: unknown check "
                        f"{(chk.get('check') if isinstance(chk, dict) else chk)!r}")
        return (len(errors) == 0), errors


def bridge_for_executor(executor):
    """Attach (or return) the shared AcpBridge for an Executor."""
    b = getattr(executor, "_acp_bridge", None)
    if b is None:
        b = AcpBridge(executor.cfg,
                      journal=lambda event, **kw: executor._log(event, **kw))
        executor._acp_bridge = b
    return b
