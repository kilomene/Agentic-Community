"""Tests for services/acp_supervision (standard self-supervision).

Everything runs in tmp dirs against a stub repo: a fake
`acp_relay_daemon.daemon` (mirrors the real daemon's pidfile semantics:
writes its own PID on boot, removes the pidfile on clean exit only when it
still points at itself) and a fake `acp_auto_update.updater`. The live
machine's crontab and ~/.acp are NEVER touched:

- cron goes through ACP_SUPERVISION_FAKE_CRONTAB (a tmp file)
- the generated wrappers' `pkill -f` cleanup is shadowed by a fake `pkill`
  earlier on PATH that only kills processes whose cmdline contains the tmp
  prefix, so the host's real daemons are untouchable.

Run: python3 -m pytest tests/test_supervision.py -q
"""
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
INSTALL_SH = os.path.join(REPO, "services", "acp_supervision", "install.sh")
CHECK_SH = os.path.join(REPO, "services", "acp_supervision", "supervisor-check.sh")

STUB_DAEMON = '''\
import argparse, os, signal, sys, time

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", required=True)
    ap.add_argument("--passphrase-file", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--pid-file", default=None)
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()
    stop = False
    def _h(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, _h)
    signal.signal(signal.SIGINT, _h)
    pid = str(os.getpid())
    if args.pid_file:
        # mirror the real daemon: it writes its OWN pidfile on boot
        with open(args.pid_file, "w") as fh:
            fh.write(pid)
    try:
        while not stop:
            time.sleep(0.2)
    finally:
        if args.pid_file:
            # ... and only removes it on exit when it still points at itself
            try:
                with open(args.pid_file) as fh:
                    if fh.read().strip() == pid:
                        os.unlink(args.pid_file)
            except OSError:
                pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

STUB_UPDATER = '''\
import argparse, sys, time

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--repo", default=None)
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--interval", type=int, default=900)
    ap.add_argument("--log-file", default=None)
    args = ap.parse_args()
    if args.once:
        print("result: stub-ok")
        return 0
    while True:
        time.sleep(1)

if __name__ == "__main__":
    sys.exit(main())
'''

MANIFEST = """\
dir stubsrc/acp_relay_daemon acp_relay_daemon
dir stubsrc/acp_auto_update acp_auto_update
"""

# fake pkill: only kills processes whose cmdline contains $ONLY_KILL_WITH
# (our tmp prefix), so the host's real daemons can never be matched.
FAKE_PKILL = '''\
#!/usr/bin/env bash
# usage: pkill -f <pattern>  (only pattern form is supported)
pat=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f) pat="$2"; shift 2;;
    *) shift;;
  esac
done
[ -n "$pat" ] || exit 0
for d in /proc/[0-9]*; do
  [ -f "$d/cmdline" ] || continue
  cmd="$(tr '\\0' ' ' < "$d/cmdline" 2>/dev/null)"
  case "$cmd" in
    *"$pat"*)
      case "$cmd" in
        *"$ONLY_KILL_WITH"*) kill "${d#/proc/}" 2>/dev/null || true;;
      esac;;
  esac
done
exit 0
'''


@pytest.fixture()
def t():
    tmp = tempfile.mkdtemp(prefix="supervision-test-")
    yield tmp
    # best-effort cleanup of anything still running from this tmp tree
    for _ in range(3):
        killed = False
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ")
            except OSError:
                continue
            if tmp.encode() in cmd and b"python3 -m acp_" in cmd:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    killed = True
                except OSError:
                    pass
        if not killed:
            break
        time.sleep(0.3)
    shutil.rmtree(tmp, ignore_errors=True)


def _write(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    os.chmod(path, mode)


@pytest.fixture()
def fixture_repo(t):
    """Minimal repo checkout: manifest + stub daemon + stub updater."""
    root = os.path.join(t, "repo")
    _write(os.path.join(root, "services", "acp_auto_update", "lib_manifest.txt"), MANIFEST)
    _write(os.path.join(root, "stubsrc", "acp_relay_daemon", "__init__.py"), "")
    _write(os.path.join(root, "stubsrc", "acp_relay_daemon", "daemon.py"), STUB_DAEMON)
    _write(os.path.join(root, "stubsrc", "acp_auto_update", "__init__.py"), "")
    _write(os.path.join(root, "stubsrc", "acp_auto_update", "updater.py"), STUB_UPDATER)
    return root


@pytest.fixture()
def env(t):
    """Sandboxed env: fake crontab, fake pkill, no ACP_HOME leakage."""
    bindir = os.path.join(t, "fakebin")
    os.makedirs(bindir)
    _write(os.path.join(bindir, "pkill"), FAKE_PKILL, 0o755)
    e = dict(os.environ)
    e.pop("ACP_HOME", None)
    e.pop("ACP_RELAY_URL", None)
    e["PATH"] = bindir + os.pathsep + e["PATH"]
    e["ACP_SUPERVISION_FAKE_CRONTAB"] = os.path.join(t, "crontab")
    e["ONLY_KILL_WITH"] = t
    return e


def _install(t, env, fixture_repo, *extra):
    prefix = os.path.join(t, "acp")
    cmd = ["bash", INSTALL_SH, "--prefix", prefix, "--repo", fixture_repo,
           "--relay", "wss://example.invalid/acp", "--no-start"] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, "install failed:\n%s\n%s" % (p.stdout, p.stderr)
    return prefix


def _run(cmd, env, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=kw.pop("timeout", 60), **kw)


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


def _cmdline(pid):
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as fh:
            return fh.read().replace(b"\0", b" ")
    except OSError:
        return b""


# ---------------------------------------------------------------- install

def test_install_creates_layout(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo)
    for d in ("bin", "lib", "state", "config", "logs", "run"):
        assert os.path.isdir(os.path.join(prefix, d)), d
    for name in ("acp-relay-daemon", "acp-auto-update", "acp-keepalive",
                 "supervisor-check"):
        p = os.path.join(prefix, "bin", name)
        assert os.path.isfile(p), name
        assert os.stat(p).st_mode & stat.S_IXUSR, name + " not executable"
    # lib synced from the manifest
    assert os.path.isfile(os.path.join(prefix, "lib", "acp_relay_daemon", "daemon.py"))
    assert os.path.isfile(os.path.join(prefix, "lib", "acp_auto_update", "updater.py"))
    # repo-root recorded for the updater
    with open(os.path.join(prefix, "config", "repo-root")) as fh:
        assert fh.read().strip() == fixture_repo


def test_install_dry_run_changes_nothing(t, env, fixture_repo):
    prefix = os.path.join(t, "acp")
    p = _run(["bash", INSTALL_SH, "--prefix", prefix, "--repo", fixture_repo,
              "--dry-run"], env)
    assert p.returncode == 0
    assert "dry-run" in p.stdout
    assert not os.path.exists(prefix)


def test_install_unknown_option_fails(env, fixture_repo):
    p = _run(["bash", INSTALL_SH, "--bogus-flag"], env)
    assert p.returncode != 0


def test_no_hardcoded_home_paths(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo)
    home = os.path.expanduser("~")
    for name in ("acp-relay-daemon", "acp-auto-update", "acp-keepalive",
                 "supervisor-check"):
        with open(os.path.join(prefix, "bin", name)) as fh:
            content = fh.read()
        assert "/home/hatch" not in content, name
        assert home not in content, "%s bakes in %s" % (name, home)


# ---------------------------------------------------------------- cron

def _cron_lines(env):
    with open(env["ACP_SUPERVISION_FAKE_CRONTAB"]) as fh:
        return [l.rstrip("\n") for l in fh if l.strip()]


def test_cron_line_content_and_idempotent(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo)
    lines = _cron_lines(env)
    tagged = [l for l in lines if "acp-supervision-keepalive" in l]
    assert len(tagged) == 1, lines
    line = tagged[0]
    assert line.startswith("* * * * * "), line
    assert os.path.join(prefix, "bin", "acp-keepalive") in line
    assert os.path.join(prefix, "logs", "keepalive.log") in line
    # reinstall: still exactly one tagged line (merge, not duplicate)
    _install(t, env, fixture_repo)
    tagged = [l for l in _cron_lines(env) if "acp-supervision-keepalive" in l]
    assert len(tagged) == 1


def test_skip_cron(t, env, fixture_repo):
    _install(t, env, fixture_repo, "--skip-cron")
    assert not os.path.exists(env["ACP_SUPERVISION_FAKE_CRONTAB"]) or \
        _cron_lines(env) == []


# ---------------------------------------------------------------- wrappers

def test_daemon_wrapper_pidfile_semantics(t, env, fixture_repo):
    """start -> daemon writes its OWN pidfile (no `echo $!` race);
    second start is a no-op; stop cleans up; stale pidfile is replaced."""
    prefix = _install(t, env, fixture_repo)
    ctl = os.path.join(prefix, "bin", "acp-relay-daemon")
    pidf = os.path.join(prefix, "run", "relay-daemon.pid")

    # content: daemon self-pidfile, no $! race
    with open(ctl) as fh:
        src = fh.read()
    assert "--pid-file" in src
    assert "echo $!" not in src

    p = _run([ctl, "start"], env)
    assert p.returncode == 0, p.stderr
    assert "started" in p.stdout
    with open(pidf) as fh:
        pid = fh.read().strip()
    assert _pid_alive(pid)
    # the pidfile holds the REAL daemon pid, not a shell's: cmdline check
    assert b"acp_relay_daemon" in _cmdline(pid)
    assert b"install.sh" not in _cmdline(pid)

    # idempotent: second start is a no-op, same pid
    p2 = _run([ctl, "start"], env)
    assert p2.returncode == 0 and "already running" in p2.stdout
    with open(pidf) as fh:
        assert fh.read().strip() == pid

    p3 = _run([ctl, "status"], env)
    assert p3.returncode == 0 and "running" in p3.stdout

    p4 = _run([ctl, "stop"], env)
    assert p4.returncode == 0
    assert not _pid_alive(pid)
    assert not os.path.exists(pidf)
    p5 = _run([ctl, "status"], env)
    assert p5.returncode != 0 and "not running" in p5.stdout

    # stale pidfile (dead pid) -> start launches fresh
    with open(pidf, "w") as fh:
        fh.write("99999999")
    p6 = _run([ctl, "start"], env)
    assert p6.returncode == 0 and "started" in p6.stdout
    with open(pidf) as fh:
        newpid = fh.read().strip()
    assert newpid != "99999999" and _pid_alive(newpid)
    _run([ctl, "stop"], env)


def test_auto_update_wrapper_lifecycle(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo)
    ctl = os.path.join(prefix, "bin", "acp-auto-update")
    pidf = os.path.join(prefix, "run", "auto-update.pid")

    p = _run([ctl, "start"], env)
    assert p.returncode == 0, p.stderr
    with open(pidf) as fh:
        pid = fh.read().strip()
    assert _pid_alive(pid)
    p2 = _run([ctl, "start"], env)
    assert "already running" in p2.stdout
    assert _run([ctl, "status"], env).returncode == 0
    assert _run([ctl, "stop"], env).returncode == 0
    assert not _pid_alive(pid)
    assert not os.path.exists(pidf)

    # check runs a one-shot cycle
    p3 = _run([ctl, "check"], env)
    assert p3.returncode == 0 and "stub-ok" in p3.stdout


def test_no_auto_update_opt_out(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo, "--no-auto-update")
    assert not os.path.exists(os.path.join(prefix, "bin", "acp-auto-update"))
    # keepalive still only manages the daemon
    with open(os.path.join(prefix, "bin", "acp-keepalive")) as fh:
        assert "acp-relay-daemon" in fh.read()


# ---------------------------------------------------------------- keepalive

def test_keepalive_revives_crashed_daemon(t, env, fixture_repo):
    """The core promise: a SIGKILLed daemon is back after one keepalive run."""
    prefix = _install(t, env, fixture_repo)
    daemon = os.path.join(prefix, "bin", "acp-relay-daemon")
    updater = os.path.join(prefix, "bin", "acp-auto-update")
    keepalive = os.path.join(prefix, "bin", "acp-keepalive")
    pidf = os.path.join(prefix, "run", "relay-daemon.pid")
    upidf = os.path.join(prefix, "run", "auto-update.pid")

    assert _run([daemon, "start"], env).returncode == 0
    assert _run([updater, "start"], env).returncode == 0
    with open(pidf) as fh:
        old_dpid = fh.read().strip()
    with open(upidf) as fh:
        upid = fh.read().strip()

    # keepalive on a healthy machine: quiet no-op
    p = _run([keepalive], env)
    assert p.returncode == 0
    assert "started" not in p.stdout

    # crash the daemon (SIGKILL: pidfile stays stale, like a real crash)
    os.kill(int(old_dpid), signal.SIGKILL)
    time.sleep(0.5)
    assert not _pid_alive(old_dpid)

    p2 = _run([keepalive], env)
    assert p2.returncode == 0
    assert "started" in p2.stdout  # it noticed and restarted
    with open(pidf) as fh:
        new_dpid = fh.read().strip()
    assert new_dpid != old_dpid and _pid_alive(new_dpid)

    # auto-update untouched: same pid, still alive
    with open(upidf) as fh:
        assert fh.read().strip() == upid
    assert _pid_alive(upid)

    _run([daemon, "stop"], env)
    _run([updater, "stop"], env)


def test_keepalive_never_touches_tokens(t, env, fixture_repo):
    """Executable keepalive code must not reference tokens/proxy at all."""
    prefix = _install(t, env, fixture_repo)
    with open(os.path.join(prefix, "bin", "acp-keepalive")) as fh:
        code_lines = [l for l in fh if not l.lstrip().startswith("#")]
    code = "\n".join(code_lines).lower()
    assert "token" not in code
    assert "proxy" not in code
    # the design rule is still documented in a comment
    with open(os.path.join(prefix, "bin", "acp-keepalive")) as fh:
        assert "NEVER" in fh.read()


# ---------------------------------------------------------------- supervisor-check

def _check(prefix, env, *extra):
    return _run([os.path.join(prefix, "bin", "supervisor-check"),
                 "--prefix", prefix] + list(extra), env)


def test_supervisor_check_healthy_then_degraded(t, env, fixture_repo):
    prefix = _install(t, env, fixture_repo)
    daemon = os.path.join(prefix, "bin", "acp-relay-daemon")
    updater = os.path.join(prefix, "bin", "acp-auto-update")

    assert _run([daemon, "start"], env).returncode == 0
    assert _run([updater, "start"], env).returncode == 0

    p = _check(prefix, env)
    assert p.returncode == 0, p.stdout
    rep = json.loads(p.stdout)
    assert rep["healthy"] is True
    assert rep["daemon"]["running"] is True
    assert _pid_alive(rep["daemon"]["pid"])
    assert rep["auto_update"]["running"] is True
    assert rep["cron"]["installed"] is True
    assert rep["prefix"] == prefix
    assert "checked_at" in rep

    _run([daemon, "stop"], env)
    p2 = _check(prefix, env)
    assert p2.returncode == 1
    rep2 = json.loads(p2.stdout)
    assert rep2["healthy"] is False
    assert rep2["daemon"]["running"] is False
    assert rep2["auto_update"]["running"] is True  # updater still up

    _run([updater, "stop"], env)
