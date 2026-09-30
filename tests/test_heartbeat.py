"""Tests for workstream A — 5-second fleet heartbeat / presence.

Covers the daemon's 5s heartbeat cadence, the RelayLink heartbeat frame,
the relay worker's presence contract (source-level), and the head-side
roster last_seen + `roster presence` / `roster seen` CLI.

Run: python3 -m pytest tests/test_heartbeat.py -q
"""

import argparse
import json
import os
import struct
import sys
import threading
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon",
                                "autopilot_hooks"))

import fleet_ops  # noqa: E402
import wake  # noqa: E402
import acp_connector.relay_link as relay_link_mod  # noqa: E402
import daemon as daemon_mod  # noqa: E402
from acp_proto import AcpError  # noqa: E402
from daemon import Daemon, HEARTBEAT_INTERVAL, PING_INTERVAL  # noqa: E402


# --------------------------------------------------------------------------
# presence_status thresholds
# --------------------------------------------------------------------------

def test_presence_status_boundaries():
    assert fleet_ops.presence_status(0) == "alive"
    assert fleet_ops.presence_status(14) == "alive"
    assert fleet_ops.presence_status(15) == "idle"
    assert fleet_ops.presence_status(59) == "idle"
    assert fleet_ops.presence_status(60) == "stale"
    assert fleet_ops.presence_status(3600) == "stale"
    assert fleet_ops.presence_status(None) == "stale"  # never seen


# --------------------------------------------------------------------------
# roster last_seen + CLI (roster seen / roster presence)
# --------------------------------------------------------------------------

def _roster_with_agents(path, handles):
    roster = fleet_ops.blank_roster()
    for h in handles:
        roster["agents"][h] = {"agent_id": "pid-%s" % h,
                              "display_name": h.title(),
                              "position": None, "responsibilities": [],
                              "instructions": None, "capabilities": [],
                              "status": "active"}
    fleet_ops.save_roster(path, roster)
    return roster


def test_roster_seen_records_now(tmp_path, capsys):
    path = str(tmp_path / "fleet.json")
    _roster_with_agents(path, ["tobi"])
    before = int(time.time())
    fleet_ops.main(["roster", "seen", "--roster", path, "--handle", "tobi"])
    out = capsys.readouterr().out
    assert "marked @tobi seen" in out
    roster = fleet_ops.load_roster(path)
    seen = roster["agents"]["tobi"]["last_seen"]
    assert isinstance(seen, int)
    assert before <= seen <= int(time.time())


def test_roster_seen_at_override(tmp_path):
    path = str(tmp_path / "fleet.json")
    _roster_with_agents(path, ["tobi"])
    fleet_ops.main(["roster", "seen", "--roster", path,
                    "--handle", "TOBI", "--at", "1759212345"])
    roster = fleet_ops.load_roster(path)
    assert roster["agents"]["tobi"]["last_seen"] == 1759212345


def test_roster_seen_unknown_handle(tmp_path):
    path = str(tmp_path / "fleet.json")
    _roster_with_agents(path, ["tobi"])
    with pytest.raises(SystemExit):
        fleet_ops.main(["roster", "seen", "--roster", path,
                        "--handle", "zenas"])


def test_last_seen_validation(tmp_path):
    path = str(tmp_path / "fleet.json")
    roster = _roster_with_agents(path, ["tobi"])
    roster["agents"]["tobi"]["last_seen"] = "yesterday"
    with pytest.raises(ValueError):
        fleet_ops.save_roster(path, roster)
    roster["agents"]["tobi"]["last_seen"] = 1759212345
    fleet_ops.save_roster(path, roster)  # integer epoch is fine
    assert fleet_ops.load_roster(path)["agents"]["tobi"][
        "last_seen"] == 1759212345


def test_cli_presence_output(tmp_path, capsys):
    path = str(tmp_path / "fleet.json")
    _roster_with_agents(path, ["alive1", "idle1", "stale1", "never1"])
    now = int(time.time())
    fleet_ops.main(["roster", "seen", "--roster", path,
                    "--handle", "alive1", "--at", str(now - 3)])
    fleet_ops.main(["roster", "seen", "--roster", path,
                    "--handle", "idle1", "--at", str(now - 30)])
    fleet_ops.main(["roster", "seen", "--roster", path,
                    "--handle", "stale1", "--at", str(now - 120)])
    fleet_ops.main(["roster", "presence", "--roster", path])
    out = capsys.readouterr().out
    lines = {l.split()[0]: l for l in out.strip().splitlines()}
    assert "alive" in lines["@alive1"]
    assert "idle" in lines["@idle1"]
    assert "stale" in lines["@stale1"]
    assert "stale" in lines["@never1"] and "never seen" in lines["@never1"]
    assert "seen 3s ago" in lines["@alive1"]
    assert "seen 2m ago" in lines["@stale1"]


def test_cli_presence_empty_roster(tmp_path, capsys):
    path = str(tmp_path / "fleet.json")
    fleet_ops.main(["roster", "presence", "--roster", path])
    assert "(roster empty)" in capsys.readouterr().out


def test_seen_updates_wake_presence_store(tmp_path):
    # Workstream C bridge: --presence keeps the wake store in agreement.
    path = str(tmp_path / "fleet.json")
    ppath = str(tmp_path / "presence.json")
    _roster_with_agents(path, ["tobi"])
    fleet_ops.main(["roster", "seen", "--roster", path,
                    "--handle", "tobi", "--at", "1759212345",
                    "--presence", ppath])
    assert wake.read_presence(ppath) == {"tobi": 1759212345.0}


# --------------------------------------------------------------------------
# RelayLink heartbeat frame
# --------------------------------------------------------------------------

class _FakeWs:
    def __init__(self):
        self.closed = False
        self.sent = []

    def send_raw(self, frame_bytes):
        ln = struct.unpack(">I", bytes(frame_bytes)[:4])[0]
        self.sent.append(
            json.loads(bytes(frame_bytes)[4:4 + ln].decode("utf-8")))


def _link_with_fake_ws():
    ws = _FakeWs()
    link = relay_link_mod.RelayLink.__new__(relay_link_mod.RelayLink)
    link._ws = ws
    link._closed = False
    link._c = None
    return link, ws


def test_send_heartbeat_frame():
    link, ws = _link_with_fake_ws()
    before = int(time.time())
    link.send_heartbeat()
    assert len(ws.sent) == 1
    obj = ws.sent[0]
    assert set(obj) == {"heartbeat"}
    ts = obj["heartbeat"]["ts"]
    assert isinstance(ts, int)
    assert before <= ts <= int(time.time())


def test_send_heartbeat_closed_raises():
    link, ws = _link_with_fake_ws()
    ws.closed = True  # send_raw gates on the underlying socket
    with pytest.raises(AcpError):
        link.send_heartbeat()
    assert ws.sent == []


# --------------------------------------------------------------------------
# relay worker presence contract (source-level)
# --------------------------------------------------------------------------

def test_worker_heartbeat_presence_contract():
    src = open(os.path.join(REPO, "worker", "acp-relay", "src",
                            "relay-do.js"), encoding="utf-8").read()
    # Records last_heartbeat per pid on a heartbeat control frame...
    assert '"heartbeat" in obj' in src
    assert "this.heartbeats.set(conn.pid" in src
    # ...acks the beat...
    assert "heartbeat_ack" in src
    # ...exposes a presence listing...
    assert '"presence" in obj' in src
    assert "last_heartbeat" in src
    # ...and drops the record when the peer disconnects.
    assert "this.heartbeats.delete(conn.pid)" in src


# --------------------------------------------------------------------------
# daemon serve loop: 5s heartbeat + untouched 30s ping
# --------------------------------------------------------------------------

def test_heartbeat_interval_constant():
    assert HEARTBEAT_INTERVAL == 5
    assert PING_INTERVAL == 30


class _FakeLink:
    def __init__(self):
        self._closed = False
        self.heartbeats = 0
        self.pings = 0

    @property
    def closed(self):
        return self._closed

    def send_heartbeat(self):
        if self._closed:
            raise AcpError("INTERNAL", "link closed")
        self.heartbeats += 1

    def send_ping(self):
        if self._closed:
            raise AcpError("INTERNAL", "link closed")
        self.pings += 1

    def close(self):
        self._closed = True


def _daemon(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    args = argparse.Namespace(
        home=str(home), passphrase_file=str(tmp_path / "pw"),
        url="wss://fake/acp", state_dir=str(state),
        pid_file=None, log_level="CRITICAL")
    return Daemon(args)


def test_daemon_serve_heartbeat_cadence(tmp_path, monkeypatch):
    # Accelerate the 5s beat to 0.3s to prove the cadence without a 10s
    # test; the 30s ping still fires on loop entry.
    monkeypatch.setattr(daemon_mod, "HEARTBEAT_INTERVAL", 0.3)
    d = _daemon(tmp_path)
    link = _FakeLink()
    t = threading.Thread(target=d._serve_until_drop, args=(link,))
    t.start()
    time.sleep(1.1)
    link.close()
    t.join(timeout=5)
    assert not t.is_alive()
    assert link.heartbeats >= 3, "expected ~3 beats at 0.3s cadence"
    assert link.pings >= 1, "the 30s WS ping must still be sent"


def test_daemon_heartbeat_is_best_effort(tmp_path, monkeypatch):
    # A heartbeat that raises AcpError (dead link) must not crash the
    # serve loop; the loop keeps supervising until the link drops.
    monkeypatch.setattr(daemon_mod, "HEARTBEAT_INTERVAL", 0.2)

    class _FlakyLink(_FakeLink):
        def send_heartbeat(self):
            raise AcpError("INTERNAL", "link closed")

    d = _daemon(tmp_path)
    link = _FlakyLink()
    t = threading.Thread(target=d._serve_until_drop, args=(link,))
    t.start()
    time.sleep(0.5)
    assert t.is_alive(), "serve loop died on a failed heartbeat"
    link.close()
    t.join(timeout=5)
    assert not t.is_alive()
