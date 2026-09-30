"""Tests for wake-on-task (workstream C): wake.py validation, the
fleet_ops.assign_task path, and the daemon outbox direct_msg kind.

A stdlib http.server mock wake endpoint records every POST. Dummy
secret refs only — no real credentials anywhere.
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon",
                                "autopilot_hooks"))

import fleet_ops  # noqa: E402
import wake  # noqa: E402


# --------------------------------------------------------- mock endpoint

class _Recorder:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = []  # (path, body, headers)

    def record(self, path, body, headers):
        with self.lock:
            self.hits.append((path, body, dict(headers)))


class _WakeHandler(BaseHTTPRequestHandler):
    recorder = None
    fail = False

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self.recorder.record(self.path, body, self.headers)
        if self.fail:
            self.send_response(503)
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):  # silence test output
        pass


@pytest.fixture()
def wake_server():
    recorder = _Recorder()
    handler = type("H", (_WakeHandler,), {})
    handler.recorder = recorder
    handler.fail = False
    srv = HTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv, recorder, port
    srv.shutdown()
    th.join()


def _roster(tmp_path, wake_cfg):
    agents = {"instinct": {"agent_id": "pid-instinct-001",
                          "display_name": "instinct",
                          "position": None,
                          "responsibilities": [],
                          "instructions": None,
                          "capabilities": [],
                          "status": "active"}}
    if wake_cfg is not None:
        agents["instinct"]["wake"] = wake_cfg
    path = str(tmp_path / "fleet.json")
    fleet_ops.save_roster(path, {"version": 1, "agents": agents})
    return path


def _presence(tmp_path, last_seen):
    path = str(tmp_path / "presence.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"instinct": last_seen}, fh)
    return path


def _resolver(secret_ref):
    assert secret_ref == "DUMMY_WAKE_REF"
    return "dummy-secret-value"


# ------------------------------------------------- wake config parsing

def test_parse_wake_config_ok():
    cfg = wake.parse_wake_config(
        {"url": "https://example.com/wake", "secret_ref": "R"})
    assert cfg["method"] == "POST"
    assert cfg["timeout_s"] == 5
    assert cfg["secret_ref"] == "R"


def test_parse_wake_config_none_is_no_wake():
    assert wake.parse_wake_config(None) is None


def test_parse_wake_config_rejects_bad():
    with pytest.raises(ValueError):
        wake.parse_wake_config({"url": "", "secret_ref": "R"})
    with pytest.raises(ValueError):
        wake.parse_wake_config({"url": "https://x", "secret_ref": ""})
    with pytest.raises(ValueError):
        wake.parse_wake_config({"url": "https://x", "secret_ref": "R",
                                "timeout_s": 999})


def test_url_policy():
    cfg = {"url": "https://example.com/w", "method": "POST",
           "timeout_s": 5, "secret_ref": "R"}
    wake.validate_wake_url(cfg)  # https always ok
    http = dict(cfg, url="http://127.0.0.1:9/w")
    with pytest.raises(ValueError):
        wake.validate_wake_url(http)  # not allowed without the flag
    wake.validate_wake_url(http, allow_insecure=True)  # tests only
    with pytest.raises(ValueError):
        wake.validate_wake_url(dict(cfg, url="http://example.com/w"),
                               allow_insecure=True)  # non-loopback http no


def test_roster_validation_accepts_and_rejects_wake(tmp_path):
    good = {"url": "https://example.com/w", "secret_ref": "R"}
    p = _roster(tmp_path, good)
    assert "instinct" in fleet_ops.load_roster(p)["agents"]
    bad = {"version": 1, "agents": {"instinct": {
        "agent_id": "x", "status": "active",
        "wake": {"url": "https://example.com/w"}}}}
    bad_path = str(tmp_path / "bad-fleet.json")
    with open(bad_path, "w", encoding="utf-8") as fh:
        json.dump(bad, fh)
    with pytest.raises(ValueError):
        fleet_ops.load_roster(bad_path)


# ------------------------------------------------------------- fire path

def test_fires_only_when_stale_and_configured(tmp_path, wake_server):
    srv, recorder, port = wake_server
    url = "http://127.0.0.1:%d/wake" % port
    roster = _roster(tmp_path, {"url": url, "secret_ref": "DUMMY_WAKE_REF"})
    presence = _presence(tmp_path, time.time() - 3600)  # stale
    outbox = str(tmp_path / "outbox")
    audit = str(tmp_path / "audit.jsonl")
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe the relay", "do the thing",
        task_id="t1", presence_path=presence, stale_after_s=300,
        outbox_dir=outbox, audit_path=audit,
        secret_resolver=_resolver, allow_insecure_wake=True)
    assert res["stale"] is True
    assert res["wake"] is not None and res["wake"]["fired"] is True
    assert res["wake"]["status"] == 200
    assert len(recorder.hits) == 1
    path, body, headers = recorder.hits[0]
    assert path == "/wake"
    assert json.loads(body.decode())["task_id"] == "t1"
    assert headers["Authorization"] == "Bearer dummy-secret-value"
    # secret itself must not leak into the audit trail
    audit_text = open(audit, encoding="utf-8").read()
    assert "dummy-secret-value" not in audit_text
    events = [json.loads(line)["event"] for line in
              audit_text.splitlines()]
    assert "wake_attempted" in events
    assert "wake_fired" in events
    assert "task_queued" in events
    # task queued for the relay mailbox via the outbox
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    queued = json.load(open(res["outbox_path"], encoding="utf-8"))
    assert queued["kind"] == "direct_msg"
    assert queued["to_pid"] == "pid-instinct-001"
    assert queued["task_id"] == "t1"


def test_no_wake_when_agent_alive(tmp_path, wake_server):
    srv, recorder, port = wake_server
    url = "http://127.0.0.1:%d/wake" % port
    roster = _roster(tmp_path, {"url": url, "secret_ref": "DUMMY_WAKE_REF"})
    presence = _presence(tmp_path, time.time() - 10)  # fresh
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="t2",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        secret_resolver=_resolver, allow_insecure_wake=True)
    assert res["stale"] is False
    assert res["wake"] is None
    assert len(recorder.hits) == 0
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    assert "wake_attempted" not in [e["event"] for e in res["events"]]


def test_no_wake_when_not_configured(tmp_path, wake_server):
    srv, recorder, port = wake_server
    roster = _roster(tmp_path, None)  # no wake block
    presence = _presence(tmp_path, time.time() - 3600)  # stale
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="t3",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        secret_resolver=_resolver)
    assert res["stale"] is True
    assert res["wake"] is None
    assert len(recorder.hits) == 0
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    events = [e["event"] for e in res["events"]]
    assert "wake_skipped" in events
    assert "task_queued" in events


def test_wake_failure_never_blocks_queueing(tmp_path, wake_server):
    srv, recorder, port = wake_server
    srv.RequestHandlerClass.fail = True  # endpoint returns 503
    url = "http://127.0.0.1:%d/wake" % port
    roster = _roster(tmp_path, {"url": url, "secret_ref": "DUMMY_WAKE_REF"})
    presence = _presence(tmp_path, time.time() - 3600)
    audit = str(tmp_path / "audit.jsonl")
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="t4",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        audit_path=audit, secret_resolver=_resolver,
        allow_insecure_wake=True)
    assert res["wake"] is not None and res["wake"]["fired"] is False
    assert len(recorder.hits) == 1  # attempted, even though it failed
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    events = [json.loads(line)["event"] for line in
              open(audit, encoding="utf-8").read().splitlines()]
    assert "wake_failed" in events
    assert "task_queued" in events


def test_wake_unreachable_endpoint_still_queues(tmp_path):
    # port almost certainly closed; connect must fail fast-ish and the
    # assignment must still go through
    url = "http://127.0.0.1:9/wake"
    roster = _roster(tmp_path, {"url": url, "secret_ref": "DUMMY_WAKE_REF",
                                "timeout_s": 1})
    presence = _presence(tmp_path, time.time() - 3600)
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="t5",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        secret_resolver=_resolver, allow_insecure_wake=True)
    assert res["wake"]["fired"] is False
    assert res["wake"]["error"]
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])


# ------------------------------------------------- email wake channel

def test_parse_wake_config_email_ok():
    cfg = wake.parse_wake_config(
        {"channel": "email", "to": "novaagent@mail.instinct.com"})
    assert cfg == {"channel": "email",
                   "to": "novaagent@mail.instinct.com"}
    # channel defaults to webhook when omitted
    assert wake.parse_wake_config(
        {"url": "https://example.com/w", "secret_ref": "R"})["channel"] \
        == "webhook"


def test_parse_wake_config_rejects_bad_email():
    with pytest.raises(ValueError):
        wake.parse_wake_config({"channel": "email", "to": "not-an-email"})
    with pytest.raises(ValueError):
        wake.parse_wake_config({"channel": "email"})
    with pytest.raises(ValueError):
        wake.parse_wake_config({"channel": "smoke-signal",
                                "to": "a@b.com"})


def test_roster_validation_accepts_email_wake(tmp_path):
    p = _roster(tmp_path, {"channel": "email",
                           "to": "novaagent@mail.instinct.com"})
    assert (fleet_ops.load_roster(p)["agents"]["instinct"]["wake"]
            ["channel"] == "email")


def _email_wake_roster(tmp_path):
    return _roster(tmp_path, {"channel": "email",
                              "to": "novaagent@mail.instinct.com"})


def test_build_wake_email_shape():
    cfg = {"channel": "email", "to": "novaagent@mail.instinct.com"}
    subject, body = wake.build_wake_email(
        cfg, {"to": "instinct", "task_id": "e1",
              "title": "Probe the relay",
              "instructions": "do the thing"})
    assert subject == "[fleet task] Probe the relay"
    assert "e1" in body
    assert "do the thing" in body
    assert "relay" in body.lower()
    assert "task_ack" in body


def test_email_wake_fires_when_stale(tmp_path):
    sent = []

    def fake_send(to, subject, body):
        sent.append((to, subject, body))
        return {"sent": True, "error": None}

    roster = _email_wake_roster(tmp_path)
    presence = _presence(tmp_path, time.time() - 3600)  # stale
    outbox = str(tmp_path / "outbox")
    audit = str(tmp_path / "audit.jsonl")
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe the relay", "do the thing",
        task_id="e1", presence_path=presence, stale_after_s=300,
        outbox_dir=outbox, audit_path=audit,
        email_sender=fake_send)
    assert res["stale"] is True
    assert res["wake"] is not None and res["wake"]["fired"] is True
    assert len(sent) == 1
    to, subject, body = sent[0]
    assert to == "novaagent@mail.instinct.com"
    assert subject == "[fleet task] Probe the relay"
    assert "e1" in body
    events = [json.loads(line) for line in
              open(audit, encoding="utf-8").read().splitlines()]
    kinds = [e["event"] for e in events]
    assert "wake_attempted" in kinds
    assert "wake_fired" in kinds
    assert "task_queued" in kinds
    attempted = next(e for e in events
                     if e["event"] == "wake_attempted")
    assert attempted["channel"] == "email"
    assert attempted["to"] == "novaagent@mail.instinct.com"
    assert "url" not in attempted
    # relay fallback still queued
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    queued = json.load(open(res["outbox_path"], encoding="utf-8"))
    assert queued["kind"] == "direct_msg"
    assert queued["to_pid"] == "pid-instinct-001"


def test_email_wake_failure_still_queues(tmp_path):
    def fake_send(to, subject, body):
        return {"sent": False, "error": "smtp exploded"}

    roster = _email_wake_roster(tmp_path)
    presence = _presence(tmp_path, time.time() - 3600)
    audit = str(tmp_path / "audit.jsonl")
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="e2",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        audit_path=audit, email_sender=fake_send)
    assert res["wake"]["fired"] is False
    assert res["wake"]["error"] == "smtp exploded"
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])
    kinds = [e["event"] for e in res["events"]]
    assert "wake_failed" in kinds
    assert "task_queued" in kinds


def test_email_wake_never_raises(tmp_path):
    def bad_send(to, subject, body):
        raise RuntimeError("boom")

    roster = _email_wake_roster(tmp_path)
    presence = _presence(tmp_path, time.time() - 3600)
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="e3",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        email_sender=bad_send)
    assert res["wake"]["fired"] is False
    assert "boom" in res["wake"]["error"]
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])


def test_no_email_when_agent_alive(tmp_path):
    sent = []

    def fake_send(to, subject, body):
        sent.append((to, subject, body))
        return {"sent": True, "error": None}

    roster = _email_wake_roster(tmp_path)
    presence = _presence(tmp_path, time.time() - 10)  # fresh
    res = fleet_ops.assign_task(
        roster, "instinct", "Probe", "do it", task_id="e4",
        presence_path=presence, outbox_dir=str(tmp_path / "outbox"),
        email_sender=fake_send)
    assert res["stale"] is False
    assert res["wake"] is None
    assert sent == []
    assert res["outbox_path"] and os.path.isfile(res["outbox_path"])


def test_default_email_sender_argv_and_failure():
    import subprocess as _sp
    from unittest import mock
    with mock.patch.object(wake.subprocess, "run") as run:
        run.return_value = mock.Mock(returncode=0, stdout="",
                                     stderr="")
        out = wake.default_email_sender("a@b.com", "subj", "body")
        assert out == {"sent": True, "error": None}
        argv = run.call_args[0][0]
        assert argv[:4] == ["hatch_gws_cli", "gmail", "+send", "--to"]
        assert "--subject" in argv and "--body" in argv
        assert "a@b.com" in argv and "subj" in argv
    with mock.patch.object(wake.subprocess, "run") as run:
        run.return_value = mock.Mock(returncode=1, stdout="",
                                     stderr="nope")
        out = wake.default_email_sender("a@b.com", "subj", "body")
        assert out["sent"] is False and "nope" in out["error"]
    with mock.patch.object(wake.subprocess, "run",
                           side_effect=_sp.TimeoutExpired("x", 1)):
        out = wake.default_email_sender("a@b.com", "subj", "body")
        assert out["sent"] is False and out["error"]


# ------------------------------------------------- daemon outbox direct_msg

def test_daemon_outbox_direct_msg(tmp_path):
    """The daemon's _drain_outbox must send direct_msg through the live
    relay link (the relay then mailboxes it for the offline agent)."""
    sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))
    import daemon as daemon_mod  # noqa: E402

    class _Args:
        state_dir = str(tmp_path)
        home = str(tmp_path)

    d = daemon_mod.Daemon(_Args())
    sent = []

    class _Conn:
        def send_message(self, pid, text, **kw):
            sent.append((pid, text))

    d.conn = _Conn()
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    (outbox / "task-instinct-aa.json").write_text(json.dumps(
        {"kind": "direct_msg", "to": "instinct",
         "to_pid": "pid-instinct-001", "task_id": "aa",
         "text": "card body"}), encoding="utf-8")
    d._drain_outbox()
    assert sent == [("pid-instinct-001", "card body")]
    assert not list(outbox.glob("task-*.json"))  # consumed on success
