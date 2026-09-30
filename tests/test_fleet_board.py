"""Tests for the shared fleet task board (workstream E): fleet_board
SQLite module plus the fleet_ops wiring (render records, scan syncs,
unblock notifies via the daemon outbox pattern).

Never touches the live ~/.acp/state: every test sets ACP_STATE_DIR to a
tmp dir or passes an explicit db path.
"""

import json
import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SVC = os.path.join(REPO, "services", "acp_relay_daemon")
HOOKS_SRC = os.path.join(SVC, "autopilot_hooks")
sys.path.insert(0, SVC)
sys.path.insert(0, HOOKS_SRC)

import fleet_blocks  # noqa: E402
import fleet_board  # noqa: E402
import fleet_ops  # noqa: E402


@pytest.fixture
def tmp_state(tmp_path, monkeypatch):
    """Isolated fake state dir; keeps every default path off the live one."""
    d = str(tmp_path / "state")
    os.makedirs(d, exist_ok=True)
    monkeypatch.setenv("ACP_STATE_DIR", d)
    return d


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "board.db")


@pytest.fixture
def board(db, tmp_state):
    b = fleet_board.FleetBoard(db)
    yield b
    b.close()


# --------------------------------------------------------------------------
# fleet_board: lifecycle
# --------------------------------------------------------------------------

def test_create_get_list(board):
    t = board.create("a1", "Probe relay", assignee="tobi",
                     due="2026-10-01T00:00:00+00:00")
    assert t["id"] == "a1"
    assert t["state"] == "open"
    assert t["assignee"] == "tobi"
    assert t["due"] == "2026-10-01T00:00:00+00:00"
    assert t["blocked_by"] == []
    assert t["created_at"] and t["updated_at"]
    got = board.get("a1")
    assert got["title"] == "Probe relay"
    assert got["dependents"] == []
    assert board.get("nope") is None
    assert len(board.list()) == 1
    assert board.list(state="open")[0]["id"] == "a1"
    assert board.list(state="done") == []
    assert board.list(assignee="tobi")[0]["id"] == "a1"


def test_create_duplicate_rejected(board):
    board.create("a1", "one")
    with pytest.raises(ValueError):
        board.create("a1", "two")


def test_default_db_path_uses_env(tmp_state):
    b = fleet_board.FleetBoard()  # no explicit path
    try:
        assert b.db_path == os.path.join(tmp_state, "fleet_board.db")
        b.create("x1", "hello")
        assert os.path.isfile(b.db_path)
    finally:
        b.close()


def test_assign(board):
    board.create("a1", "Probe relay")
    t = board.assign("a1", "@Tobi")
    assert t["assignee"] == "tobi"  # normalized
    assert t["state"] == "assigned"
    with pytest.raises(ValueError):
        board.assign("missing", "tobi")


def test_full_state_machine(board):
    board.create("a1", "task")
    assert board.set_state("a1", "assigned") is True
    assert board.set_state("a1", "assigned") is False  # idempotent
    assert board.set_state("a1", "acked") is True
    assert board.set_state("a1", "in_progress") is True
    assert board.set_state("a1", "done") is True
    assert board.get("a1")["state"] == "done"


def test_illegal_transitions_rejected(board):
    board.create("a1", "task")
    board.set_state("a1", "done")
    with pytest.raises(ValueError):
        board.set_state("a1", "open")  # terminal is locked
    with pytest.raises(ValueError):
        board.set_state("a1", "in_progress")
    board.create("b1", "task")
    with pytest.raises(ValueError):
        board.set_state("b1", "in_progress")  # open -> in_progress illegal
    with pytest.raises(ValueError):
        board.set_state("b1", "bogus")
    with pytest.raises(ValueError):
        board.set_state("missing", "done")
    # ...unless the operator forces it
    assert board.set_state("a1", "assigned", force=True) is True


# --------------------------------------------------------------------------
# dependencies / unblocking
# --------------------------------------------------------------------------

def test_add_dependency_blocks_task(board):
    board.create("a", "first")
    board.create("b", "second")
    assert board.add_dependency("b", "a") is True
    assert board.add_dependency("b", "a") is False  # idempotent
    t = board.get("b")
    assert t["state"] == "blocked"
    assert t["blocked_by"] == ["a"]
    assert t["resume_state"] == "open"
    assert board.get("a")["dependents"] == ["b"]
    assert board.unblock_check("b") is False
    assert [x["id"] for x in board.ready_tasks()] == ["a"]


def test_auto_unblock_on_blocker_done(board):
    board.create("a", "first")
    board.create("b", "second")
    board.assign("b", "tobi")
    board.add_dependency("b", "a")  # b: assigned -> blocked
    assert board.get("b")["state"] == "blocked"
    board.set_state("a", "done")
    unblocked = board.on_blocker_done("a")
    assert [u["id"] for u in unblocked] == ["b"]
    t = board.get("b")
    assert t["state"] == "assigned"  # resume_state restored
    assert board.unblock_check("b") is True
    assert {x["id"] for x in board.ready_tasks()} == {"b"}


def test_chained_dependencies_unblock_in_order(board):
    for tid in ("a", "b", "c"):
        board.create(tid, "task " + tid)
    board.add_dependency("b", "a")
    board.add_dependency("c", "b")
    board.set_state("a", "done")
    assert [u["id"] for u in board.on_blocker_done("a")] == ["b"]
    assert board.get("c")["state"] == "blocked"  # b not done yet
    board.set_state("b", "done")
    assert [u["id"] for u in board.on_blocker_done("b")] == ["c"]


def test_failed_blocker_keeps_dependent_blocked(board):
    # Documented choice: a failed blocker never auto-unblocks; the
    # dependent stays blocked until the head intervenes.
    board.create("a", "first")
    board.create("b", "second")
    board.add_dependency("b", "a")
    board.set_state("a", "failed")
    assert board.on_blocker_done("a") == []
    t = board.get("b")
    assert t["state"] == "blocked"
    assert board.unblock_check("b") is False
    assert "b" not in {x["id"] for x in board.ready_tasks()}
    # Operator recovery: drop the failed dep -> task becomes workable.
    assert board.remove_dependency("b", "a") is True
    assert board.get("b")["state"] == "open"
    assert "b" in {x["id"] for x in board.ready_tasks()}


def test_dependency_on_done_blocker_does_not_block(board):
    board.create("a", "first")
    board.set_state("a", "done")
    board.create("b", "second", state="assigned")
    assert board.add_dependency("b", "a") is True
    assert board.get("b")["state"] == "assigned"  # blocker already done
    assert board.unblock_check("b") is True


def test_self_dependency_and_cycles_rejected(board):
    for tid in ("a", "b"):
        board.create(tid, "task " + tid)
    with pytest.raises(ValueError):
        board.add_dependency("a", "a")
    board.add_dependency("b", "a")
    with pytest.raises(ValueError):
        board.add_dependency("a", "b")  # would close a loop
    with pytest.raises(ValueError):
        board.add_dependency("a", "nope")
    with pytest.raises(ValueError):
        board.add_dependency("nope", "a")
    board.set_state("a", "done")
    with pytest.raises(ValueError):
        board.add_dependency("a", "b")  # terminal task takes no deps


def test_ready_tasks_skips_terminal(board):
    board.create("a", "done task")
    board.create("b", "live task")
    board.set_state("a", "done")
    assert [x["id"] for x in board.ready_tasks()] == ["b"]


# --------------------------------------------------------------------------
# fleet_ops wiring: render records, scan syncs, unblock notifies
# --------------------------------------------------------------------------

def _room_text(*blocks):
    return "\n".join("agent msg\n" + fleet_blocks.make_block(b)
                     for b in blocks)


def test_task_render_records_board_entry(db, tmp_state, tmp_path, capsys):
    roster_path = str(tmp_path / "fleet.json")
    with open(roster_path, "w") as fh:
        json.dump({"version": 1, "agents": {}}, fh)
    board_path = db  # local alias: the Args class body would shadow `db`

    class Args:
        to = "tobi"
        title = "Probe relay"
        instructions = "measure rtt"
        due = None
        task_id = "aa11bb"
        roster = roster_path
        board_db = board_path

    fleet_ops.cmd_task_render(Args())
    out = capsys.readouterr().out
    assert "aa11bb" in out  # same id in the card and the board
    b = fleet_board.FleetBoard(db)
    try:
        t = b.get("aa11bb")
        assert t["title"] == "Probe relay"
        assert t["assignee"] == "tobi"
        assert t["state"] == "assigned"
    finally:
        b.close()


def test_scan_sync_lifecycle_and_idempotent(db, tmp_state):
    room = _room_text(
        {"kind": "task_assign", "task_id": "t1", "to": "tobi",
         "title": "Probe", "instructions": "do it"},
        {"kind": "task_ack", "task_id": "t1", "by": "tobi",
         "status": "accepted"},
        {"kind": "task_done", "task_id": "t1", "by": "tobi",
         "note": "all good"},
    )
    blocks = fleet_ops.scan_text(room)
    unblocked = fleet_ops._board_sync_scan(blocks, db)
    assert unblocked == {}
    b = fleet_board.FleetBoard(db)
    try:
        t = b.get("t1")
        assert t["state"] == "done"
        assert t["assignee"] == "tobi"
    finally:
        b.close()
    # Re-scanning the same room text is a no-op: no state churn, no
    # duplicate notifies (outbox stays empty).
    fleet_ops._board_sync_scan(blocks, db)
    outbox = os.path.join(tmp_state, "outbox")
    assert not os.path.isdir(outbox) or \
        [n for n in os.listdir(outbox) if n.endswith(".json")] == []


def test_scan_sync_unblock_queues_room_notify(db, tmp_state):
    with open(os.path.join(tmp_state, "fleet.json"), "w") as fh:
        json.dump({"group_id": "fleet-group-1"}, fh)
    b = fleet_board.FleetBoard(db)
    b.create("a", "first leg")
    b.create("b", "second leg")
    b.assign("b", "tobi")
    b.add_dependency("b", "a")
    b.close()

    room = _room_text(
        {"kind": "task_done", "task_id": "a", "by": "phoenix",
         "note": "done"},
    )
    unblocked = fleet_ops._board_sync_scan(
        fleet_ops.scan_text(room), db)
    assert list(unblocked) == ["tobi"]

    b = fleet_board.FleetBoard(db)
    try:
        assert b.get("b")["state"] == "assigned"
    finally:
        b.close()

    outbox = os.path.join(tmp_state, "outbox")
    names = [n for n in os.listdir(outbox) if n.endswith(".json")]
    assert len(names) == 1  # exactly one notify, batched per assignee
    with open(os.path.join(outbox, names[0])) as fh:
        msg = json.load(fh)
    assert msg["kind"] == "group_msg"
    assert msg["group_id"] == "fleet-group-1"
    assert "@tobi" in msg["text"] and "unblocked" in msg["text"]
    # No `acp` CLI involved: the message is a queued file for the daemon.
    assert "text" in msg and isinstance(msg["text"], str)


def test_scan_sync_failed_blocker_no_notify_stays_blocked(db, tmp_state,
                                                           capsys):
    with open(os.path.join(tmp_state, "fleet.json"), "w") as fh:
        json.dump({"group_id": "fleet-group-1"}, fh)
    b = fleet_board.FleetBoard(db)
    b.create("a", "first leg")
    b.create("b", "second leg")
    b.assign("b", "tobi")
    b.add_dependency("b", "a")
    b.close()

    room = _room_text(
        {"kind": "task_failed", "task_id": "a", "by": "tobi",
         "note": "relay down"},
    )
    unblocked = fleet_ops._board_sync_scan(
        fleet_ops.scan_text(room), db)
    assert unblocked == {}
    b = fleet_board.FleetBoard(db)
    try:
        assert b.get("a")["state"] == "failed"
        assert b.get("b")["state"] == "blocked"
    finally:
        b.close()
    outbox = os.path.join(tmp_state, "outbox")
    assert not os.path.isdir(outbox) or \
        [n for n in os.listdir(outbox) if n.endswith(".json")] == []
    assert "stay blocked" in capsys.readouterr().out


def test_scan_sync_declined_ack_marks_failed(db, tmp_state):
    room = _room_text(
        {"kind": "task_assign", "task_id": "t9", "to": "tobi",
         "title": "Probe", "instructions": "do it"},
        {"kind": "task_ack", "task_id": "t9", "by": "tobi",
         "status": "declined", "note": "no capacity"},
    )
    fleet_ops._board_sync_scan(fleet_ops.scan_text(room), db)
    b = fleet_board.FleetBoard(db)
    try:
        assert b.get("t9")["state"] == "failed"
    finally:
        b.close()


def test_board_cli_end_to_end(db, tmp_state, capsys):
    def run_board(*a):
        fleet_ops.main(["board", a[0]] + ["--board-db", db] + list(a[1:]))

    run_board("list")
    assert "(board empty)" in capsys.readouterr().out

    b = fleet_board.FleetBoard(db)
    b.create("c1", "write docs")
    b.assign("c1", "mary")
    b.create("c2", "review docs")
    b.close()

    run_board("dep", "c2", "c1")
    assert "blocked" in capsys.readouterr().out

    run_board("show", "c2")
    out = capsys.readouterr().out
    assert "blocked" in out and "c1" in out

    run_board("states")
    out = capsys.readouterr().out
    assert "assigned" in out and "blocked" in out

    run_board("list", "--state", "blocked")
    out = capsys.readouterr().out
    assert "c2" in out
    assert not any(line.startswith("c1 ") or line.startswith("c1|")
                   for line in out.splitlines())
