"""Daemon tests: the relay daemon connects, claims a pairing code, publishes
state files, refreshes the code before expiry, and releases on shutdown —
all against a fake in-process relay (no network).

Run: python3 -m pytest tests/test_relay_daemon.py -q
"""
import argparse
import json
import os
import queue
import struct
import sys
import tempfile
import threading
import time

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

from acp_connector import Connector  # noqa: E402
import acp_connector.relay_link as relay_link_mod  # noqa: E402
from daemon import Daemon, PAIR_CODE_TTL  # noqa: E402


# ------------------------------------------------------------ fake relay

class FakeWs:
    """Stands in for WsConn: answers hello silently, claims/releases
    pairing codes, routes nothing else."""

    def __init__(self):
        self._q = queue.Queue()
        self._closed = False
        self.sent = []

    @property
    def closed(self):
        return self._closed

    def send_env(self, env):
        self.send_raw(struct.pack(">I", 0) + b"{}")

    def send_raw(self, frame_bytes):
        if self._closed:
            raise RuntimeError("link closed")
        ln = struct.unpack(">I", bytes(frame_bytes)[:4])[0]
        obj = json.loads(bytes(frame_bytes)[4:4 + ln].decode("utf-8"))
        self.sent.append(obj)
        if "pair_code_claim" in obj:
            body = obj["pair_code_claim"]
            code = body["code"]
            self._q.put({"pair_code_claimed": {"code": code,
                                               "req": body["req"]}})
        elif "pair_code_release" in obj:
            body = obj["pair_code_release"]
            self._q.put({"pair_code_released": {"code": body["code"],
                                                "req": body["req"]}})

    def read_loop(self, on_frame, on_error=None):
        while not self._closed:
            try:
                obj = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                on_frame(obj)
            except Exception as e:  # noqa: BLE001
                if on_error:
                    on_error(e)

    def close(self):
        self._closed = True


@pytest.fixture()
def fakes():
    made = []

    def _wss_connect(url):
        ws = FakeWs()
        made.append(ws)
        return ws

    orig = relay_link_mod.wss_connect
    relay_link_mod.wss_connect = _wss_connect
    try:
        yield made
    finally:
        relay_link_mod.wss_connect = orig


@pytest.fixture()
def daemon_env(tmp_path):
    home = tmp_path / "acp-home"
    home.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    conn = Connector(str(home), "test-passphrase", "daemon-test")
    args = argparse.Namespace(
        home=str(home), passphrase_file=str(tmp_path / "pw"),
        url="wss://fake-relay/acp", state_dir=str(state),
        pid_file=str(tmp_path / "daemon.pid"), log_level="CRITICAL")
    d = Daemon(args)
    d.conn = conn  # skip passphrase-file loading
    try:
        yield d, tmp_path
    finally:
        try:
            if d.link is not None:
                d.link.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            conn.stop()
        except Exception:  # noqa: BLE001
            pass


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def test_connect_claims_code_and_publishes_state(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        assert not link.closed
        assert d.code and len(d.code) == 6

        pair = _read_json(tmp / "state" / "pair-code.json")
        assert pair["code"] == d.code
        assert pair["expires_at"] > time.time()

        status = _read_json(tmp / "state" / "relay-status.json")
        assert status["connected"] is True
        assert status["code"] == d.code
        assert status["peer_id"] == d.conn.peer_id
        assert status["handle"] == "daemon-test"
    finally:
        d._release_code()
        link.close()


def test_release_code_sends_release_frame(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    code = d.code
    d._release_code()
    link.close()
    assert d.code is None
    releases = [o for o in fakes[0].sent if "pair_code_release" in o]
    assert releases and releases[0]["pair_code_release"]["code"] == code


def test_refresh_reclaims_near_expiry(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        old = d.code
        # pretend the code is about to expire
        with d._code_lock:
            d.code_expires_at = int(time.time()) + 60
        d._refresh_code_if_needed()
        pair = _read_json(tmp / "state" / "pair-code.json")
        assert pair["code"] == d.code
        assert d.code_expires_at > time.time() + 3000
        # old code was released on the relay
        releases = [o for o in fakes[0].sent if "pair_code_release" in o]
        assert any(r["pair_code_release"]["code"] == old for r in releases)
    finally:
        d._release_code()
        link.close()


def test_no_refresh_when_code_fresh(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    try:
        before = fakes[0].sent[:]
        d._refresh_code_if_needed()
        claims = [o for o in fakes[0].sent[len(before):]
                  if "pair_code_claim" in o]
        assert not claims
    finally:
        d._release_code()
        link.close()


def test_status_reflects_disconnect(fakes, daemon_env):
    d, tmp = daemon_env
    link = d._connect_once()
    d._release_code()
    link.close()
    d.link = None
    d.connected_since = 0
    d._publish()
    status = _read_json(tmp / "state" / "relay-status.json")
    assert status["connected"] is False
    assert status["code"] is None
