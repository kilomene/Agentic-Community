"""Tests for fleet operations: fleet_blocks wire format, fleet_ops
head-side tooling, and the reference autopilot hook template."""

import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
HOOKS_SRC = os.path.join(REPO, "services", "acp_relay_daemon",
                         "autopilot_hooks")
sys.path.insert(0, os.path.join(REPO, "services", "acp_relay_daemon"))
sys.path.insert(0, HOOKS_SRC)

import fleet_blocks  # noqa: E402
import fleet_ops  # noqa: E402


# --------------------------------------------------------------------------
# fleet_blocks
# --------------------------------------------------------------------------

def test_block_round_trip():
    payload = {"kind": "task_assign", "task_id": "a3f9c2",
               "to": "tobi", "title": "Probe",
               "instructions": "do the thing"}
    text = "hey @tobi\n" + fleet_blocks.make_block(payload) + "\ntrailer"
    blocks = fleet_blocks.extract_blocks(text)
    assert blocks == [payload]


def test_multiple_blocks_each_parse():
    b1 = {"kind": "task_ack", "task_id": "aa", "by": "tobi",
          "status": "accepted"}
    b2 = {"kind": "task_done", "task_id": "aa", "by": "tobi",
          "note": "done"}
    text = fleet_blocks.make_block(b1) + "\n" + fleet_blocks.make_block(b2)
    assert fleet_blocks.extract_blocks(text) == [b1, b2]


def test_malformed_blocks_skipped():
    good = {"kind": "task_ack", "task_id": "aa", "by": "tobi",
            "status": "declined"}
    text = ("\n".join([
        "```fleet\n{not json```",
        "```fleet\n{\"kind\": \"nope\"}\n```",
        "```fleet\n{\"kind\": \"task_assign\", \"task_id\": \"x\"}\n```",
        fleet_blocks.make_block(good),
    ]))
    assert fleet_blocks.extract_blocks(text) == [good]


def test_validate_rejects_bad_fields():
    base = {"kind": "task_assign", "task_id": "ok1", "to": "tobi",
            "title": "t", "instructions": "i"}
    bad_ids = dict(base, task_id="has space!")
    assert not fleet_blocks.validate_block(bad_ids, _raise=False)
    bad_ack = {"kind": "task_ack", "task_id": "ok1", "by": "tobi",
               "status": "maybe"}
    assert not fleet_blocks.validate_block(bad_ack, _raise=False)
    bad_role = {"kind": "role_assign", "to": "tobi",
                "position": "Scout", "responsibilities": "notalist"}
    assert not fleet_blocks.validate_block(bad_role, _raise=False)
    with pytest.raises(ValueError):
        fleet_blocks.make_block(dict(base, task_id="bad id"))


def test_find_mentions():
    assert fleet_blocks.find_mentions("@tobi please") == ["tobi"]
    assert fleet_blocks.find_mentions("hey @Tobi, and @tobi!") == ["tobi"]
    assert fleet_blocks.find_mentions("mail me at a@tobi.com") == []
    assert fleet_blocks.find_mentions("@tobix") == ["tobix"]
    assert fleet_blocks.find_mentions("no mentions") == []


def test_is_mentioned_matches_handle_and_display_name():
    assert fleet_blocks.is_mentioned("@TOBI go", ["tobi", "Tobi"])
    assert fleet_blocks.is_mentioned("hey @tobix", ["tobi"]) is False
    assert fleet_blocks.is_mentioned("nothing", ["tobi"]) is False


def test_blocks_for_targets_only_addressee():
    task = {"kind": "task_assign", "task_id": "t1", "to": "Tobi",
            "title": "t", "instructions": "i"}
    other = {"kind": "task_assign", "task_id": "t2", "to": "zenas",
             "title": "t", "instructions": "i"}
    ack = {"kind": "task_ack", "task_id": "t1", "by": "tobi",
           "status": "accepted"}
    text = "\n".join(fleet_blocks.make_block(b)
                     for b in (task, other, ack))
    assert fleet_blocks.blocks_for(text, "tobi") == [task]
    assert fleet_blocks.blocks_for(text, "zenas") == [other]


def test_latest_status_newest_wins():
    seq = [
        {"kind": "task_assign", "task_id": "t1", "to": "tobi",
         "title": "t", "instructions": "i"},
        {"kind": "task_ack", "task_id": "t1", "by": "tobi",
         "status": "accepted"},
        {"kind": "task_done", "task_id": "t1", "by": "tobi",
         "note": "fin"},
    ]
    state = fleet_blocks.latest_status(seq)
    assert state["t1"][0] == "task_done"


# --------------------------------------------------------------------------
# fleet_ops
# --------------------------------------------------------------------------

def test_render_task_assign_round_trip():
    msg = fleet_ops.render_task_assign(
        "tobi", "Probe latency", "Measure 100 round-trips.",
        due="2026-09-30T12:00:00Z", task_id="abc123")
    assert "@tobi" in msg
    blocks = fleet_blocks.extract_blocks(msg)
    assert len(blocks) == 1
    b = blocks[0]
    assert (b["kind"], b["task_id"], b["to"], b["title"]) == (
        "task_assign", "abc123", "tobi", "Probe latency")
    assert b["due"] == "2026-09-30T12:00:00Z"


def test_render_role_assign_round_trip():
    msg = fleet_ops.render_role_assign(
        "tobi", "Scout", ["Probe relays", "Report findings"],
        instructions="Report in the room.")
    assert "@tobi" in msg and "Scout" in msg
    blocks = fleet_blocks.extract_blocks(msg)
    assert len(blocks) == 1
    b = blocks[0]
    assert b["kind"] == "role_assign"
    assert b["responsibilities"] == ["Probe relays", "Report findings"]


def test_roster_add_set_validate(tmp_path):
    path = str(tmp_path / "fleet.json")
    roster = fleet_ops.load_roster(path)  # missing -> blank
    assert roster["agents"] == {}
    roster["agents"]["tobi"] = {
        "agent_id": "abc", "display_name": "Tobi", "position": None,
        "responsibilities": [], "instructions": None,
        "capabilities": ["code-exec"], "status": "active"}
    fleet_ops.save_roster(path, roster)
    again = fleet_ops.load_roster(path)
    assert again["agents"]["tobi"]["capabilities"] == ["code-exec"]
    bad = dict(again)
    bad["agents"]["tobi"]["status"] = "sleeping"
    with pytest.raises(ValueError):
        fleet_ops.save_roster(path, bad)


def test_task_states_reduce():
    blocks = [
        {"kind": "task_assign", "task_id": "t1", "to": "tobi",
         "title": "T", "instructions": "I"},
        {"kind": "task_ack", "task_id": "t1", "by": "tobi",
         "status": "accepted"},
        {"kind": "task_failed", "task_id": "t1", "by": "tobi",
         "note": "relay down"},
    ]
    states = fleet_ops.task_states(blocks)
    assert states["t1"]["state"] == "task_failed"
    assert states["t1"]["note"] == "relay down"


def test_cli_task_render(capsys, tmp_path):
    path = str(tmp_path / "fleet.json")
    fleet_ops.main(["task", "render", "--roster", path, "--to", "tobi",
                    "--title", "T", "--instructions", "I",
                    "--task-id", "z9"])
    out = capsys.readouterr().out
    assert '"task_id":"z9"' in out.replace(" ", "")


# --------------------------------------------------------------------------
# reference hook template, run exactly like the daemon runs it
# --------------------------------------------------------------------------

@pytest.fixture()
def hook_dir(tmp_path):
    d = tmp_path / "hooks"
    d.mkdir()
    for fn in ("default.py", "fleet_blocks.py"):
        shutil.copy(os.path.join(HOOKS_SRC, fn), str(d / fn))
    (d / "agent_identity.json").write_text(
        json.dumps({"handle": "tobi", "display_name": "Tobi"}))
    return d


def run_hook(hook_dir, event):
    proc = subprocess.run(
        [sys.executable, str(hook_dir / "default.py")],
        input=(json.dumps(event) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(hook_dir), timeout=20,
        env={"ACP_EVENT_KIND": event.get("kind", "")})
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout.decode().strip()
    return json.loads(out)["reply"] if out else None


def _group_event(text):
    return {"kind": "group_message", "sender": "head",
            "text": text, "msg_id": "m1", "reply_to": None,
            "auto": False, "group_id": "g-x", "channel": None}


def test_hook_acks_task_assign(hook_dir):
    task = {"kind": "task_assign", "task_id": "t42", "to": "tobi",
            "title": "Probe", "instructions": "measure things"}
    reply = run_hook(hook_dir, _group_event(
        "@tobi new work\n" + fleet_blocks.make_block(task)))
    assert reply is not None
    blocks = fleet_blocks.extract_blocks(reply)
    assert len(blocks) == 1
    ack = blocks[0]
    assert ack["kind"] == "task_ack" and ack["task_id"] == "t42"
    assert ack["by"] == "tobi" and ack["status"] == "accepted"
    stored = json.loads((hook_dir / "tasks_pending" / "t42.json")
                        .read_text())
    assert stored["title"] == "Probe"


def test_hook_ignores_tasks_for_others(hook_dir):
    task = {"kind": "task_assign", "task_id": "t7", "to": "zenas",
            "title": "X", "instructions": "y"}
    reply = run_hook(hook_dir, _group_event(
        "@zenas\n" + fleet_blocks.make_block(task)))
    assert reply is None
    assert not (hook_dir / "tasks_pending").exists()


def test_hook_stores_role(hook_dir):
    role = {"kind": "role_assign", "to": "tobi", "position": "Scout",
            "responsibilities": ["Probe", "Report"],
            "instructions": "Be diligent."}
    reply = run_hook(hook_dir, _group_event(
        "@tobi\n" + fleet_blocks.make_block(role)))
    assert reply is not None and "Scout" in reply
    stored = json.loads((hook_dir / "my_role.json").read_text())
    assert stored["position"] == "Scout"
    assert stored["responsibilities"] == ["Probe", "Report"]


def test_hook_silent_without_identity(tmp_path):
    d = tmp_path / "hooks2"
    d.mkdir()
    for fn in ("default.py", "fleet_blocks.py"):
        shutil.copy(os.path.join(HOOKS_SRC, fn), str(d / fn))
    task = {"kind": "task_assign", "task_id": "t1", "to": "tobi",
            "title": "T", "instructions": "I"}
    proc = subprocess.run(
        [sys.executable, str(d / "default.py")],
        input=(json.dumps(_group_event(fleet_blocks.make_block(task)))
               + "\n").encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(d), timeout=20, env={"ACP_EVENT_KIND": "group_message"})
    assert proc.returncode == 0
    assert proc.stdout.decode().strip() == ""


def test_hook_silent_on_unaddressed_chatter(hook_dir):
    assert run_hook(hook_dir, _group_event("hello everyone")) is None
    dm = dict(_group_event("hi"), kind="message")
    assert run_hook(hook_dir, dm) is None
