#!/usr/bin/env python3
"""acp-auto-update: the agent updates itself from the repo. Stdlib only.

Once an agent is installed, nobody should ever update it by hand again.
This process watches the Agentic-Community repo and, when bug fixes or
new features land on main, pulls them, re-syncs the installed code,
restarts the relay daemon only when the daemon's own code changed
(never for docs/tests/worker-only pushes — a restart would drop the
relay link and kill live pairings), waits for any in-flight pairing
handshake to finish before restarting, and verifies the daemon came
back healthy — rolling back automatically if it didn't.

    python3 -m acp_auto_update.updater --once     # single check/update cycle
    python3 -m acp_auto_update.updater --daemon   # loop forever (the service)

What it touches: the git checkout and $PREFIX/lib (code only).
What it NEVER touches: identity, passphrase, state, config, databases.

Safety gates (any of these -> skip the cycle, log, try again later):
  - no git checkout found
  - the checkout has uncommitted changes (never destroy local work)
  - the checkout has local commits not on the remote (dev machine guard)
  - the remote can't be reached
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time

REPO_URL = "https://github.com/kilomene/Agentic-Community"
BRANCH = "main"
MANIFEST_REL = os.path.join("services", "acp_auto_update", "lib_manifest.txt")
STATE_NAME = "auto-update.json"


# ------------------------------------------------------------ plumbing

class Cfg:
    def __init__(self, repo=None, prefix=None, remote_url=REPO_URL,
                 branch=BRANCH, interval=900, daemon_ctl=None,
                 log_file=None, health_timeout=75):
        self.repo = repo
        self.prefix = prefix
        self.remote_url = remote_url
        self.branch = branch
        self.interval = interval
        self.daemon_ctl = daemon_ctl  # override for tests
        self.log_file = log_file
        self.health_timeout = health_timeout  # seconds to wait for daemon
        self._log_fh = None

    def log(self, msg):
        line = "%s %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg)
        print(line, flush=True)
        if self.log_file:
            try:
                if self._log_fh is None:
                    self._log_fh = open(self.log_file, "a")
                self._log_fh.write(line + "\n")
                self._log_fh.flush()
            except OSError:
                pass


def _run(args, cwd=None, capture=True):
    """Run a command; return (rc, stdout). Never raises."""
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=capture,
                           text=True, timeout=120)
        return p.returncode, (p.stdout or "").strip()
    except Exception as e:  # missing binary, timeout, ...
        return 127, "error: %s" % e


def _git(cfg, repo, *args):
    return _run(["git", "-C", repo] + list(args))


# ------------------------------------------------------------ resolve

def resolve_repo(cfg):
    """Find the git checkout this install tracks."""
    candidates = []
    if cfg.repo:
        candidates.append(cfg.repo)
    if os.environ.get("ACP_REPO_ROOT"):
        candidates.append(os.environ["ACP_REPO_ROOT"])
    # NB: cfg.prefix is None unless --prefix was passed; resolve it the
    # same way check_once does, or the recorded repo-root is never read
    # and every cycle silently reports "no-repo".
    prefix = cfg.prefix or resolve_prefix(cfg)
    if prefix:
        f = os.path.join(prefix, "config", "repo-root")
        try:
            with open(f) as fh:
                candidates.append(fh.read().strip())
        except OSError:
            pass
    home = os.path.expanduser("~")
    candidates.append(os.path.join(home, "Agentic-Community"))
    for c in candidates:
        if c and os.path.isdir(os.path.join(c, ".git")):
            return c
    return None


def resolve_prefix(cfg):
    if cfg.prefix:
        return cfg.prefix
    if os.environ.get("ACP_HOME"):
        return os.environ["ACP_HOME"]
    return os.path.join(os.path.expanduser("~"), ".acp")


# ------------------------------------------------------------ manifest sync

def parse_manifest(repo):
    """Read lib_manifest.txt -> list of (kind, src, dst)."""
    path = os.path.join(repo, MANIFEST_REL)
    entries = []
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                raise ValueError("manifest %s:%d: want 3 columns, got %r"
                                 % (path, lineno, raw.rstrip()))
            kind, src, dst = parts
            if kind not in ("dir", "opt-dir", "file", "opt-file", "touch"):
                raise ValueError("manifest %s:%d: bad kind %r"
                                 % (path, lineno, kind))
            entries.append((kind, src, dst))
    return entries


def sync_lib(cfg, repo, libdir, clean=False):
    """Replicate the installer's $PREFIX/lib from the repo checkout.

    With clean=True the lib dir is wiped first, so files removed from
    the manifest (or added by a rolled-back update) don't linger.
    """
    if clean and os.path.isdir(libdir):
        shutil.rmtree(libdir, ignore_errors=True)
    os.makedirs(libdir, exist_ok=True)
    for kind, src, dst in parse_manifest(repo):
        src_p = os.path.join(repo, src) if src != "-" else None
        dst_p = os.path.join(libdir, dst)
        if kind in ("dir", "file") or (kind == "opt-dir" and src_p and os.path.isdir(src_p)) \
                or (kind == "opt-file" and src_p and os.path.isfile(src_p)):
            if kind in ("dir", "opt-dir"):
                if os.path.isdir(dst_p) or os.path.islink(dst_p):
                    shutil.rmtree(dst_p, ignore_errors=True)
                shutil.copytree(src_p, dst_p, symlinks=True)
            else:
                parent = os.path.dirname(dst_p)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                if os.path.isfile(dst_p) or os.path.islink(dst_p):
                    os.remove(dst_p)
                shutil.copy2(src_p, dst_p)
            cfg.log("sync: %s -> %s" % (src, dst))
        elif kind == "touch":
            parent = os.path.dirname(dst_p)
            if parent:
                os.makedirs(parent, exist_ok=True)
            open(dst_p, "a").close()
        # opt-* with missing src: skip silently


# ------------------------------------------------------------ daemon health

def daemon_healthy(cfg, prefix, timeout=75):
    """True when the relay daemon is up and connected to the relay."""
    deadline = time.time() + timeout
    pid_f = os.path.join(prefix, "run", "relay-daemon.pid")
    status_f = os.path.join(prefix, "state", "relay-status.json")
    while time.time() < deadline:
        try:
            with open(pid_f) as fh:
                pid = int(fh.read().strip())
            os.kill(pid, 0)
        except (OSError, ValueError):
            time.sleep(2)
            continue
        try:
            with open(status_f) as fh:
                st = json.load(fh)
            if st.get("connected") and abs(time.time() - st.get("now", 0)) < 180:
                return True
        except (OSError, ValueError):
            pass
        time.sleep(2)
    return False


def restart_daemon(cfg, prefix):
    ctl = cfg.daemon_ctl or os.path.join(prefix, "bin", "acp-relay-daemon")
    rc, out = _run([ctl, "restart"])
    cfg.log("daemon restart rc=%d %s" % (rc, out[:200]))
    return rc == 0


QUIESCE_TIMEOUT = 120  # max seconds to wait for pairings to finish
QUIESCE_POLL = 5       # seconds between quiescence checks


def _daemon_lib_paths(repo):
    """Repo-relative paths that land in $PREFIX/lib (from the manifest).

    The running daemon imports only from $PREFIX/lib, so a push that
    touches none of these paths cannot change daemon behavior — and must
    not trigger a restart (a restart would drop the relay link, release
    the pairing code, and kill any live pairing handshake).
    """
    paths = [MANIFEST_REL]
    try:
        for _kind, src, _dst in parse_manifest(repo):
            if src != "-":
                paths.append(src)
    except (OSError, ValueError):
        pass
    return paths


def _daemon_paths_changed(cfg, repo, old_sha, new_sha):
    """True when old_sha..new_sha touches any daemon lib path."""
    paths = _daemon_lib_paths(repo)
    rc, out = _git(cfg, repo, "diff", "--name-only", old_sha, new_sha,
                   "--", *paths)
    if rc != 0:
        # can't tell — err on the side of restarting
        return True
    return bool(out.strip())


def _pairing_active(cfg, prefix):
    """Active (mid-handshake) pairing sessions per the daemon's status
    file, or None when the status is missing/stale (daemon down or old
    code that doesn't report it — treat as unknown, not as busy)."""
    try:
        with open(os.path.join(prefix, "state", "relay-status.json")) as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        return None
    if abs(time.time() - st.get("now", 0)) > 180:
        return None
    v = st.get("pairing_active")
    return int(v) if isinstance(v, (int, float)) else None


def wait_for_pairing_quiescence(cfg, prefix, timeout=QUIESCE_TIMEOUT):
    """Block until no pairing handshake is in flight (or timeout).

    A daemon restart drops the relay link and kills live pairings, so the
    updater holds off while the owner is mid-pairing. Always bounded:
    after `timeout` seconds it gives up waiting and the restart proceeds.
    Returns True when quiescent, False on timeout/unknown.
    """
    deadline = time.time() + timeout
    waited = False
    while time.time() < deadline:
        n = _pairing_active(cfg, prefix)
        if n is None:
            return waited  # daemon down or status unknown: nothing to protect
        if n <= 0:
            if waited:
                cfg.log("pairing quiescent; proceeding with restart")
            return True
        if not waited:
            cfg.log("waiting for %d active pairing(s) to finish before "
                    "restarting daemon (max %ds)" % (n, timeout))
            waited = True
        time.sleep(QUIESCE_POLL)
    cfg.log("WARNING: %d pairing(s) still active after %ds; restarting "
            "anyway" % (_pairing_active(cfg, prefix) or -1, timeout))
    return False


# ------------------------------------------------------------ state

def _state_path(prefix):
    return os.path.join(prefix, "state", STATE_NAME)


def read_state(prefix):
    try:
        with open(_state_path(prefix)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def write_state(prefix, **kw):
    st = read_state(prefix)
    st.update(kw)
    st["updated_at"] = int(time.time())
    tmp = _state_path(prefix) + ".tmp"
    try:
        os.makedirs(os.path.dirname(tmp), exist_ok=True)
        with open(tmp, "w") as fh:
            json.dump(st, fh, indent=2)
        os.replace(tmp, _state_path(prefix))
    except OSError:
        pass


# ------------------------------------------------------------ one cycle

def check_once(cfg):
    """Run a single check/update cycle. Returns a short result string."""
    prefix = resolve_prefix(cfg)
    repo = resolve_repo(cfg)
    now = int(time.time())

    if not repo:
        cfg.log("SKIP: no git checkout found (set ACP_REPO_ROOT or reinstall)")
        write_state(prefix, last_check=now, last_result="no-repo")
        return "no-repo"
    if shutil.which("git") is None:
        cfg.log("SKIP: git not installed")
        write_state(prefix, last_check=now, last_result="no-git")
        return "no-git"

    # --- safety: never destroy local work ---------------------------
    rc, dirty = _git(cfg, repo, "status", "--porcelain")
    if rc == 0 and dirty:
        cfg.log("SKIP: checkout has uncommitted changes; not touching it")
        write_state(prefix, last_check=now, last_result="skipped-dirty",
                    repo=repo)
        return "skipped-dirty"
    rc, ahead = _git(cfg, repo, "rev-list", "HEAD", "--not", "--remotes",
                     "--count")
    if rc == 0 and ahead.strip().isdigit() and int(ahead) > 0:
        cfg.log("SKIP: checkout has %s local commit(s) not on the remote "
                "(dev machine?); not touching it" % ahead.strip())
        write_state(prefix, last_check=now, last_result="skipped-local-commits",
                    repo=repo)
        return "skipped-local-commits"

    rc, local_sha = _git(cfg, repo, "rev-parse", "HEAD")
    if rc != 0:
        cfg.log("SKIP: cannot read local HEAD: %s" % local_sha)
        write_state(prefix, last_check=now, last_result="git-error",
                    error=local_sha[:200])
        return "git-error"

    # --- what does the repo have? ------------------------------------
    cfg.log("fetch %s %s" % (cfg.remote_url, cfg.branch))
    rc, out = _git(cfg, repo, "fetch", "origin", cfg.branch, "--quiet")
    if rc != 0:
        # maybe the remote is named differently; try ls-remote as fallback
        rc2, out2 = _run(["git", "ls-remote", cfg.remote_url, cfg.branch])
        if rc2 != 0 or not out2:
            cfg.log("SKIP: remote unreachable: %s" % (out or out2)[:200])
            write_state(prefix, last_check=now, last_result="fetch-failed",
                        repo=repo, installed_sha=local_sha)
            return "fetch-failed"
        remote_sha = out2.split()[0]
        # fetch the objects so reset works
        _git(cfg, repo, "fetch", cfg.remote_url, cfg.branch, "--quiet")
    else:
        rc, remote_sha = _git(cfg, repo, "rev-parse", "FETCH_HEAD")
        if rc != 0:
            cfg.log("SKIP: cannot read FETCH_HEAD")
            write_state(prefix, last_check=now, last_result="fetch-failed",
                        repo=repo, installed_sha=local_sha)
            return "fetch-failed"

    if remote_sha == local_sha:
        cfg.log("up to date (%s)" % local_sha[:12])
        write_state(prefix, last_check=now, last_result="up-to-date",
                    repo=repo, installed_sha=local_sha)
        return "up-to-date"

    # --- update -------------------------------------------------------
    cfg.log("UPDATE %s -> %s" % (local_sha[:12], remote_sha[:12]))
    rc, out = _git(cfg, repo, "reset", "--hard", remote_sha)
    if rc != 0:
        cfg.log("FAIL: reset failed: %s" % out[:200])
        write_state(prefix, last_check=now, last_result="reset-failed",
                    repo=repo, installed_sha=local_sha, error=out[:200])
        return "reset-failed"

    libdir = os.path.join(prefix, "lib")
    try:
        sync_lib(cfg, repo, libdir, clean=True)
    except Exception as e:
        cfg.log("FAIL: lib sync failed: %s" % e)
        write_state(prefix, last_check=now, last_result="sync-failed",
                    repo=repo, installed_sha=remote_sha, error=str(e)[:200])
        return "sync-failed"

    restart_needed = _daemon_paths_changed(cfg, repo, local_sha, remote_sha)
    if not restart_needed:
        cfg.log("no daemon-relevant changes in %s..%s; lib synced, daemon "
                "left running (pairing code and live sessions untouched)"
                % (local_sha[:12], remote_sha[:12]))
    else:
        # Never restart mid-pairing: wait for handshakes to settle first.
        wait_for_pairing_quiescence(cfg, prefix)
        restart_daemon(cfg, prefix)
    if daemon_healthy(cfg, prefix, timeout=cfg.health_timeout):
        cfg.log("OK: updated to %s, daemon healthy" % remote_sha[:12])
        write_state(prefix, last_check=now,
                    last_result="updated" if restart_needed
                    else "updated-no-restart",
                    repo=repo, installed_sha=remote_sha,
                    previous_sha=local_sha)
        return "updated" if restart_needed else "updated-no-restart"

    # --- roll back ----------------------------------------------------
    cfg.log("FAIL: daemon unhealthy after update; ROLLING BACK to %s"
            % local_sha[:12])
    _git(cfg, repo, "reset", "--hard", local_sha)
    try:
        sync_lib(cfg, repo, libdir, clean=True)
    except Exception as e:
        cfg.log("CRITICAL: rollback lib sync failed: %s" % e)
    restart_daemon(cfg, prefix)
    healthy = daemon_healthy(cfg, prefix, timeout=cfg.health_timeout)
    write_state(prefix, last_check=now, last_result="rolled-back",
                repo=repo, installed_sha=local_sha,
                error="daemon unhealthy after update to %s; rolled back; "
                      "daemon healthy=%s" % (remote_sha[:12], healthy))
    cfg.log("rolled back; daemon healthy=%s" % healthy)
    return "rolled-back"


# ------------------------------------------------------------ daemon loop

def run_loop(cfg):
    prefix = resolve_prefix(cfg)
    pid_f = os.path.join(prefix, "run", "auto-update.pid")
    os.makedirs(os.path.dirname(pid_f), exist_ok=True)
    with open(pid_f, "w") as fh:
        fh.write(str(os.getpid()))

    stop = {"flag": False}

    def _sig(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    cfg.log("auto-update loop started (interval %ss)" % cfg.interval)
    try:
        while not stop["flag"]:
            try:
                check_once(cfg)
            except Exception as e:
                cfg.log("cycle crashed (will retry next interval): %s" % e)
            for _ in range(int(cfg.interval)):
                if stop["flag"]:
                    break
                time.sleep(1)
    finally:
        cfg.log("auto-update loop stopped")
        try:
            os.remove(pid_f)
        except OSError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="self-updating agent stack")
    ap.add_argument("--once", action="store_true",
                    help="run one check/update cycle and exit")
    ap.add_argument("--daemon", action="store_true",
                    help="loop forever, checking every --interval seconds")
    ap.add_argument("--repo", default=None, help="repo checkout path")
    ap.add_argument("--prefix", default=None, help="install prefix ($PREFIX)")
    ap.add_argument("--interval", type=int, default=900,
                    help="seconds between checks in --daemon (default 900)")
    ap.add_argument("--log-file", default=None)
    args = ap.parse_args(argv)

    cfg = Cfg(repo=args.repo, prefix=args.prefix, interval=args.interval,
              log_file=args.log_file)
    if args.daemon:
        if not args.log_file and cfg.prefix:
            cfg.log_file = os.path.join(resolve_prefix(cfg), "logs",
                                        "auto-update.log")
        run_loop(cfg)
    else:
        result = check_once(cfg)
        print("result: %s" % result)


if __name__ == "__main__":
    main()
