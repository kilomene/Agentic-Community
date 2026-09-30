"""Tests for the work ledger (workstream H): append-only SQLite
diligence record of the fleet task lifecycle.

The ledger must NEVER touch the live ~/.acp/state directory —
every test uses a tmp db path.
"""

import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))

import fleet_ops  # noqa: E402
import work_ledger  # noqa: E402
from work_ledger import WorkLedger  # noqa: E402


def make_ledger(tmp_path):
    return WorkLedger(path=str(tmp_path / "work_ledger.db"))


# --------------------------------------------------------------------------
# basic lifecycle
# --------------------------------------------------------------------------

def test_full_event_lifecycle(tmp_path):
    L = make_ledger(tmp_path)
    L.record_event("t1", "tobi", "assigned", detail="Probe relay", ts=1000.0)
    L.record_event("t1", "tobi", "acked", detail="accepted", ts=1010.0)
    L.record_event("t1", "tobi", "in_progress", ts=1020.0)
    L.record_event("t1", "tobi", "done", detail="ok", ts=1100.0)
    events = L.events_for_task("t1")
    assert [e["event"] for e in events] == [
        "assigned", "acked", "in_progress", "done"]
    assert all(e["task_id"] == "t1" for e in events)
    assert events[0]["detail"] == "Probe relay"
    L.close()


def test_failed_lifecycle_records_reason(tmp_path):
    L = make_ledger(tmp_path)
    L.record_event("t9", "tobi", "assigned", ts=1.0)
    L.record_event("t9", "tobi", "failed", detail="relay timed out",
                   ts=2.0)
    events = L.events_for_task("t9")
    assert events[-1]["event"] == "failed"
    assert events[-1]["detail"] == "relay timed out"
    s = L.summary_for_agent("tobi")
    assert s["tasks_failed"] == 1
    assert s["tasks_completed"] == 0
    L.close()


def test_blocked_event(tmp_path):
    L = make_ledger(tmp_path)
    L.record_event("t7", "tobi", "assigned", ts=1.0)
    L.record_event("t7", "tobi", "blocked",
                   detail="waiting on head", ts=2.0)
    assert L.events_for_task("t7")[-1]["event"] == "blocked"
    assert L.summary_for_agent("tobi")["counts"]["blocked"] == 1
    L.close()


def test_invalid_event_rejected(tmp_path):
    L = make_ledger(tmp_path)
    with pytest.raises(ValueError):
        L.record_event("t1", "tobi", "nonsense")
    L.close()


def test_handles_normalized(tmp_path):
    L = make_ledger(tmp_path)
    L.record_event("t1", "@Tobi", "assigned", ts=1.0)
    assert L.events_for_agent("tobi") == L.events_for_agent("@TOBI")
    L.close()


# --------------------------------------------------------------------------
# summary math
# --------------------------------------------------------------------------

def test_summary_latency_math(tmp_path):
    L = make_ledger(tmp_path)
    # task A: assigned at 1000, acked at 1010 (latency 10), done at 1100
    #         (completion from ack: 90)
    L.record_event("A", "tobi", "assigned", ts=1000.0)
    L.record_event("A", "tobi", "acked", ts=1010.0)
    L.record_event("A", "tobi", "done", ts=1100.0)
    # task B: assigned at 2000, acked at 2060 (latency 60), done at 2240
    #         (completion from ack: 180)
    L.record_event("B", "tobi", "assigned", ts=2000.0)
    L.record_event("B", "tobi", "acked", ts=2060.0)
    L.record_event("B", "tobi", "done", ts=2240.0)
    s = L.summary_for_agent("tobi")
    assert s["counts"]["assigned"] == 2
    assert s["counts"]["done"] == 2
    assert s["tasks_completed"] == 2
    assert s["avg_ack_latency_s"] == pytest.approx(35.0)
    assert s["avg_completion_time_s"] == pytest.approx(135.0)
    L.close()


def test_summary_completion_falls_back_to_assigned(tmp_path):
    # task done without an ack: completion measured from assigned
    L = make_ledger(tmp_path)
    L.record_event("C", "tobi", "assigned", ts=1000.0)
    L.record_event("C", "tobi", "done", ts=1200.0)
    s = L.summary_for_agent("tobi")
    assert s["avg_ack_latency_s"] is None
    assert s["avg_completion_time_s"] == pytest.approx(200.0)
    L.close()


def test_summary_empty_agent(tmp_path):
    L = make_ledger(tmp_path)
    s = L.summary_for_agent("nobody")
    assert s["tasks_completed"] == 0
    assert s["avg_ack_latency_s"] is None
    assert all(n == 0 for n in s["counts"].values())
    L.close()


# --------------------------------------------------------------------------
# append-only enforcement
# --------------------------------------------------------------------------

def test_no_update_or_delete_api(tmp_path):
    L = make_ledger(tmp_path)
    L.record_event("t1", "tobi", "assigned", ts=1.0)
    with pytest.raises(TypeError):
        L.update("t1", event="done")
    with pytest.raises(TypeError):
        L.delete("t1")
    # rows are untouched
    assert len(L.events_for_task("t1")) == 1
    L.close()


# --------------------------------------------------------------------------
# dedupe (repeat room scans must not duplicate rows)
# --------------------------------------------------------------------------

def test_dedupe_key_skips_repeats(tmp_path):
    L = make_ledger(tmp_path)
    first = L.record_event("t1", "tobi", "done", detail="ok",
                           dedupe_key="done:t1")
    second = L.record_event("t1", "tobi", "done", detail="ok",
                            dedupe_key="done:t1")
    assert first is not None
    assert second is None
    assert len(L.events_for_task("t1")) == 1
    L.close()


# --------------------------------------------------------------------------
# fleet_ops hook points (workstream H)
# --------------------------------------------------------------------------

def _blocks(room_text):
    return fleet_ops.scan_text(room_text)


def _block(kind, **kw):
    payload = {"kind": kind}
    payload.update(kw)
    return fleet_ops.fleet_blocks.make_block(payload)


def test_record_block_events_full_lifecycle(tmp_path):
    L = make_ledger(tmp_path)
    room = "\n".join([
        "@tobi new task",
        _block("task_assign", task_id="a1", to="tobi",
               title="Probe", instructions="do it"),
        _block("task_ack", task_id="a1", by="tobi",
               status="accepted"),
        _block("task_done", task_id="a1", by="tobi", note="rtt 40ms"),
        _block("task_failed", task_id="b2", by="tobi",
               note="crashed"),
        _block("role_assign", to="tobi", position="Scout",
               responsibilities=["x"]),
    ])
    fleet_ops.record_block_events(_blocks(room), L)
    # rescan must not duplicate
    fleet_ops.record_block_events(_blocks(room), L)
    evs = L.events_for_task("a1")
    assert [e["event"] for e in evs] == ["assigned", "acked", "done"]
    assert evs[0]["detail"] == "Probe"
    assert evs[1]["detail"] == "accepted"
    assert evs[2]["detail"] == "rtt 40ms"
    failed = L.events_for_task("b2")
    assert [e["event"] for e in failed] == ["failed"]
    assert failed[0]["detail"] == "crashed"
    # role_assign is not a lifecycle event
    assert L.events_for_agent("tobi")
    assert all(e["event"] in work_ledger.VALID_EVENTS
               for e in L.events_for_agent("tobi"))
    L.close()


def test_cli_ledger_agent_summary(tmp_path, capsys):
    L = make_ledger(tmp_path)
    L.record_event("a1", "tobi", "assigned", ts=1000.0)
    L.record_event("a1", "tobi", "acked", ts=1010.0)
    L.record_event("a1", "tobi", "done", ts=1100.0)
    L.close()
    p = fleet_ops.build_parser()
    args = p.parse_args(["ledger", "--agent", "@tobi",
                         "--db", str(tmp_path / "work_ledger.db")])
    args.fn(args)
    out = capsys.readouterr().out
    assert "tasks completed: 1" in out
    assert "avg ack latency: 10.0s" in out
    assert "avg completion time: 90.0s" in out


def test_cli_ledger_task_history(tmp_path, capsys):
    L = make_ledger(tmp_path)
    L.record_event("a1", "tobi", "assigned", detail="Probe", ts=1000.0)
    L.record_event("a1", "tobi", "failed", detail="timeout", ts=1100.0)
    L.close()
    p = fleet_ops.build_parser()
    args = p.parse_args(["ledger", "--task", "a1",
                         "--db", str(tmp_path / "work_ledger.db")])
    args.fn(args)
    out = capsys.readouterr().out
    assert "@tobi" in out and "assigned" in out and "failed" in out
    assert "timeout" in out
