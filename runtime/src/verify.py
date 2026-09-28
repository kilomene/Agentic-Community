"""Verification layer: the verifier — not the LLM — decides success.

A step's `verify` block declares observable expectations. The verifier runs
checks against the real world and returns PASS/FAIL with evidence.

Verified state (world_state in the kv store) can only be written by the
verifier, never by agent claims.
"""
import json
import os
import socket


class Verdict:
    def __init__(self, passed, checks=None, evidence=None):
        self.passed = passed
        self.checks = checks or []
        self.evidence = evidence or {}

    def to_dict(self):
        return {"passed": self.passed, "checks": self.checks,
                "evidence": self.evidence}


class Verifier:
    def __init__(self, executor):
        self.ex = executor

    def verify_step(self, step):
        """step: dict with optional 'verify' list. Returns Verdict."""
        checks = step.get("verify", [])
        results, evidence = [], {}
        for c in checks:
            kind = c.get("check")
            try:
                if kind == "file_exists":
                    ok, ev = self._file_exists(c["path"])
                elif kind == "file_contains":
                    ok, ev = self._file_contains(c["path"], c["text"])
                elif kind == "command_ok":
                    ok, ev = self._command_ok(c["command"], c.get("cwd"))
                elif kind == "port_listening":
                    ok, ev = self._port_listening(c.get("host", "127.0.0.1"),
                                                  c["port"])
                elif kind == "http_ok":
                    ok, ev = self._http_ok(c["url"], c.get("contains"))
                elif kind == "process_running":
                    ok, ev = self._process_running(c["pattern"])
                elif kind == "acp":
                    ok, ev = self._acp(c.get("op", ""), c.get("args", {}),
                                       c.get("expect", {}))
                else:
                    ok, ev = False, {"error": f"unknown check: {kind}"}
            except Exception as e:  # noqa: BLE001 - a check must not crash verify
                ok, ev = False, {"error": repr(e)}
            entry = {"check": kind, "passed": ok, **c}
            if kind == "acp":
                # The passphrase may have been resolved from the vault for
                # the check — it must never persist in the stored verdict.
                cargs = entry.get("args")
                if isinstance(cargs, dict) and "passphrase" in cargs:
                    entry["args"] = {**cargs,
                                     "passphrase": "***REDACTED***"}
            results.append(entry)
            evidence[kind] = ev
        passed = all(r["passed"] for r in results) if results else True
        return Verdict(passed, results, evidence)

    # ---- checks (all read-only observations) ----
    @staticmethod
    def _file_exists(path):
        ok = os.path.exists(path)
        return ok, {"path": path, "exists": ok}

    @staticmethod
    def _file_contains(path, text):
        try:
            with open(path) as f:
                data = f.read()
            ok = text in data
            return ok, {"path": path, "found": ok}
        except OSError as e:
            return False, {"path": path, "error": str(e)}

    def _command_ok(self, command, cwd):
        r = self.ex.run("shell", args={"command": command, "cwd": cwd,
                                       "timeout_s": 60})
        ok = r.ok
        return ok, {"command": command, "exit_code": r.exit_code,
                    "tail": (r.stdout or "")[-500:]}

    @staticmethod
    def _port_listening(host, port):
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((host, port))
            return True, {"host": host, "port": port, "listening": True}
        except OSError:
            return False, {"host": host, "port": port, "listening": False}
        finally:
            s.close()

    def _http_ok(self, url, contains=None):
        r = self.ex.run("http_get", args={"url": url, "timeout_s": 30})
        ok = r.ok and (contains is None or contains in (r.stdout or ""))
        return ok, {"url": url, "status": r.exit_code,
                    "contains_match": True if contains is None else (contains in (r.stdout or ""))}

    @staticmethod
    def _process_running(pattern):
        """Check whether any process command line contains the pattern.

        Scans /proc/*/cmdline directly in Python — the pattern is never
        interpolated into a shell string, so a hostile pattern like
        "'; touch /tmp/x; '" is matched literally (or not at all) and
        can have no side effect. Fixed-string semantics (like grep -F).
        """
        sample = []
        try:
            pids = os.listdir("/proc")
        except OSError:
            return False, {"pattern": pattern, "running": False,
                           "error": "/proc unavailable"}
        for pid in pids:
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\0", b" ").decode(
                        "utf-8", "replace").strip()
            except OSError:
                continue  # process exited or unreadable; skip
            if pattern and pattern in cmdline:
                sample.append(f"{pid}: {cmdline[:120]}")
                if len(sample) >= 3:
                    break
        ok = bool(sample)
        return ok, {"pattern": pattern, "running": ok,
                    "sample": "\n".join(sample)[:300]}

    # ---- ACP checks (read-only ops only — verification never sends) ----
    def _acp(self, op, args, expect):
        """{"check": "acp", "op": "identity", "expect": {"handle": "x"}}.

        Runs a read-only bridge op and asserts the result contains every
        key/value in `expect`. Mutating ops (message, pair, send_file…)
        are rejected here: verification observes, it never acts."""
        from . import acp_bridge as acpmod
        if op not in acpmod._READONLY_OPS:
            return False, {"error": f"acp check rejects mutating op: {op!r}"}
        try:
            bridge = acpmod.bridge_for_executor(self.ex)
            # read-only ops need a Connector; the passphrase is not required
            # to already exist for them, so pass through only if given.
            result = bridge.run(op, dict(args or {}))
        except acpmod.AcpBridgeError as e:
            return False, {"error": str(e)}
        except Exception as e:  # noqa: BLE001 - a check must not crash verify
            return False, {"error": repr(e)}
        missing = {k: v for k, v in (expect or {}).items()
                   if result.get(k) != v}
        ok = not missing
        return ok, {"op": op, "result": result, "missing": missing}
