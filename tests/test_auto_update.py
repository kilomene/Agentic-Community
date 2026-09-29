"""Auto-update tests: the updater pulls repo changes, re-syncs the installed
lib, restarts the relay daemon, verifies health, and rolls back on failure —
all against temp git repos and a stub daemon control script (no network).

Run: python3 -m pytest tests/test_auto_update.py -q
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "services", "acp_auto_update"))

from updater import Cfg, check_once, parse_manifest, read_state, sync_lib  # noqa: E402


TINY_MANIFEST = """\
# tiny test manifest
dir       packages/fakepkg                    fakepkg
file      services/acp_relay_daemon/daemon.py acp_relay_daemon/daemon.py
touch     -                                   acp_relay_daemon/__init__.py
"""

GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@test",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@test",
}


def _git(cwd, *args):
    env = dict(os.environ, **GIT_ENV)
    p = subprocess.run(["git", "-C", cwd] + list(args),
                       capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, "git %s failed: %s" % (args, p.stderr)
    return p.stdout.strip()


@pytest.fixture()
def world(tmp_path):
    """A fake origin repo, a clone (the 'installed checkout'), and a fake
    install prefix with a stub daemon control script."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(str(origin), "init", "-b", "main")
    (origin / "services" / "acp_auto_update").mkdir(parents=True)
    (origin / "services" / "acp_auto_update" / "lib_manifest.txt").write_text(
        TINY_MANIFEST)
    (origin / "packages" / "fakepkg").mkdir(parents=True)
    (origin / "packages" / "fakepkg" / "mod.py").write_text("VERSION = 1\n")
    (origin / "services" / "acp_relay_daemon").mkdir(parents=True)
    (origin / "services" / "acp_relay_daemon" / "daemon.py").write_text(
        "# daemon v1\n")
    _git(str(origin), "add", ".")
    _git(str(origin), "commit", "-m", "v1")

    checkout = tmp_path / "checkout"
    env = dict(os.environ, **GIT_ENV)
    subprocess.run(["git", "clone", "-q", str(origin), str(checkout)],
                   check=True, env=env, timeout=60)

    prefix = tmp_path / "prefix"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "run").mkdir()
    (prefix / "state").mkdir()
    (prefix / "lib").mkdir()
    (prefix / "config").mkdir()
    (prefix / "logs").mkdir()

    # stub daemon control: `./acp-relay-daemon restart` records the call and,
    # when STUB_HEALTHY=1, fakes a healthy daemon (live pid + fresh status)
    stub = prefix / "bin" / "acp-relay-daemon"
    stub.write_text("""#!/usr/bin/env python3
import json, os, sys, time
d = os.environ["STUB_DIR"]
open(os.path.join(d, "restart.log"), "a").write("restart\\n")
if os.environ.get("STUB_HEALTHY") == "1":
    with open(os.path.join(d, "prefix", "run", "relay-daemon.pid"), "w") as fh:
        fh.write(str(os.getppid()))
    with open(os.path.join(d, "prefix", "state", "relay-status.json"), "w") as fh:
        json.dump({"connected": True, "now": time.time(),
                   "since": time.time()}, fh)
""")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    env_patch = {"STUB_DIR": str(tmp_path), "STUB_HEALTHY": "1"}
    (tmp_path / "prefix-link").symlink_to(prefix)  # stable alias
    return {
        "origin": str(origin), "checkout": str(checkout),
        "prefix": str(prefix), "stub": str(stub), "tmp": str(tmp_path),
        "env": env_patch,
    }


def _cfg(world, healthy=True):
    os.environ.update(world["env"])
    os.environ["STUB_HEALTHY"] = "1" if healthy else "0"
    return Cfg(repo=world["checkout"], prefix=world["prefix"],
               daemon_ctl=world["stub"], health_timeout=3,
               log_file=os.path.join(world["prefix"], "logs", "t.log"))


def _restarts(world):
    p = os.path.join(world["tmp"], "restart.log")
    if not os.path.exists(p):
        return 0
    with open(p) as fh:
        return len(fh.read().strip().split())


def test_up_to_date_is_noop(world):
    cfg = _cfg(world)
    assert check_once(cfg) == "up-to-date"
    assert _restarts(world) == 0
    st = read_state(world["prefix"])
    assert st["last_result"] == "up-to-date"
    assert st["installed_sha"]


def test_update_pulls_syncs_restarts(world):
    # v2 lands on the origin: changed file + brand-new package file
    _git(world["origin"], "checkout", "-q", "main")
    with open(os.path.join(world["origin"], "packages", "fakepkg",
                            "mod.py"), "w") as fh:
        fh.write("VERSION = 2\n")
    with open(os.path.join(world["origin"], "packages", "fakepkg",
                            "new.py"), "w") as fh:
        fh.write("# new in v2\n")
    _git(world["origin"], "add", ".")
    _git(world["origin"], "commit", "-q", "-m", "v2")

    cfg = _cfg(world)
    assert check_once(cfg) == "updated"
    assert _restarts(world) == 1
    lib = os.path.join(world["prefix"], "lib")
    with open(os.path.join(lib, "fakepkg", "mod.py")) as fh:
        assert fh.read() == "VERSION = 2\n"
    assert os.path.exists(os.path.join(lib, "fakepkg", "new.py"))
    assert os.path.exists(os.path.join(lib, "acp_relay_daemon",
                                        "__init__.py"))
    st = read_state(world["prefix"])
    assert st["last_result"] == "updated"
    assert st["previous_sha"] != st["installed_sha"]


def test_dirty_checkout_is_skipped(world):
    with open(os.path.join(world["checkout"], "packages", "fakepkg",
                            "mod.py"), "a") as fh:
        fh.write("# local tweak\n")
    cfg = _cfg(world)
    assert check_once(cfg) == "skipped-dirty"
    assert _restarts(world) == 0


def test_local_commits_are_skipped(world):
    with open(os.path.join(world["checkout"], "packages", "fakepkg",
                            "mod.py"), "a") as fh:
        fh.write("# dev work\n")
    _git(world["checkout"], "commit", "-q", "-am", "dev work")
    cfg = _cfg(world)
    assert check_once(cfg) == "skipped-local-commits"
    assert _restarts(world) == 0


def test_rollback_on_unhealthy_daemon(world):
    old_sha = _git(world["checkout"], "rev-parse", "HEAD")
    _git(world["origin"], "checkout", "-q", "main")
    with open(os.path.join(world["origin"], "packages", "fakepkg",
                            "mod.py"), "w") as fh:
        fh.write("VERSION = 99\n")
    _git(world["origin"], "commit", "-q", "-am", "v99")

    cfg = _cfg(world, healthy=False)  # stub restart leaves daemon dead
    assert check_once(cfg) == "rolled-back"
    # checkout is back on the old sha, lib restored to old content
    assert _git(world["checkout"], "rev-parse", "HEAD") == old_sha
    with open(os.path.join(world["prefix"], "lib", "fakepkg",
                            "mod.py")) as fh:
        assert fh.read() == "VERSION = 1\n"
    st = read_state(world["prefix"])
    assert st["last_result"] == "rolled-back"
    assert st["installed_sha"] == old_sha


def test_manifest_bad_kind_raises(tmp_path):
    repo = tmp_path / "r"
    (repo / "services" / "acp_auto_update").mkdir(parents=True)
    (repo / "services" / "acp_auto_update" / "lib_manifest.txt").write_text(
        "bogus packages/x x\n")
    with pytest.raises(ValueError):
        parse_manifest(str(repo))


def test_real_manifest_parses():
    entries = parse_manifest(REPO)
    kinds = {k for k, _, _ in entries}
    assert kinds <= {"dir", "opt-dir", "file", "opt-file", "touch"}
    assert len(entries) >= 10
    # every non-optional src exists in this repo
    for kind, src, _ in entries:
        if kind in ("dir", "file") and src != "-":
            assert os.path.exists(os.path.join(REPO, src)), src


def test_resolve_repo_reads_recorded_repo_root(tmp_path, monkeypatch):
    """Regression: resolve_repo must read <prefix>/config/repo-root even
    when cfg.prefix is None (the normal --daemon loop case — install.sh
    never passes --prefix). Before the fix it only consulted cfg.prefix
    (the raw --prefix arg), so every cycle reported 'no-repo' and the
    agent silently never self-updated."""
    from updater import resolve_repo  # noqa: E402
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    fake_home = tmp_path / "home"
    prefix = fake_home / ".acp"  # the real default layout
    (prefix / "config").mkdir(parents=True)
    (prefix / "config" / "repo-root").write_text(str(checkout))
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("ACP_HOME", raising=False)
    monkeypatch.delenv("ACP_REPO_ROOT", raising=False)
    cfg = Cfg()  # prefix=None, exactly like the installed --daemon loop
    assert resolve_repo(cfg) == str(checkout)
