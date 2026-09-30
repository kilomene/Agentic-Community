"""Fleet operations — head-side tooling for running the fleet.

The head (Phoenix) keeps a roster of every fleet agent — handle,
position, responsibilities, standing instructions, capabilities —
and tasks the fleet by posting mention + fleet-block messages into
the fleet room. Agents running the reference hook
(``autopilot_hooks/default.py``) parse those blocks, acknowledge,
and report back; this module renders the outbound cards and scans
room text for the inbound acks / completions.

Roster file (``fleet.json``)::

    {"agents": {
       "tobi": {"agent_id": "oQIV0...",
                "display_name": "Tobi",
                "position": "Scout",
                "responsibilities": ["Probe new relays", "..."],
                "instructions": "Report findings in the room.",
                "capabilities": ["code-exec", "web"],
                "status": "active"}}}

``status`` is ``active`` | ``quiet`` | ``retired``. ``position``,
``responsibilities`` and ``instructions`` start empty and are filled
in when the head assigns roles — the mechanism ships now, the
assignments happen when the project starts.

CLI::

    python3 fleet_ops.py roster show
    python3 fleet_ops.py roster add --handle tobi --agent-id oQIV0... --display-name Tobi
    python3 fleet_ops.py roster set --handle tobi --position Scout \\
        --responsibilities "Probe relays" "Report findings" \\
        --instructions "..." --capabilities code-exec web
    python3 fleet_ops.py task render --to tobi --title "..." --instructions "..." [--due ...]
    python3 fleet_ops.py role render --to tobi --position Scout \\
        --responsibilities "..." [--instructions "..."]
    python3 fleet_ops.py scan < room-export.txt   # list parsed blocks / task states

Stdlib only.
"""

import argparse
import datetime
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "autopilot_hooks"))
import fleet_blocks  # noqa: E402

ROSTER_VERSION = 1
_VALID_STATUS = ("active", "quiet", "retired")


def blank_roster():
    return {"version": ROSTER_VERSION, "agents": {}}


def load_roster(path):
    """Load and validate a roster file. Missing file -> blank roster."""
    if not os.path.isfile(path):
        return blank_roster()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return validate_roster(data)


def validate_roster(data):
    if not isinstance(data, dict) or not isinstance(
            data.get("agents"), dict):
        raise ValueError("roster must be an object with an 'agents' object")
    for handle, agent in data["agents"].items():
        if not isinstance(agent, dict):
            raise ValueError("agent %r must be an object" % handle)
        status = agent.get("status", "active")
        if status not in _VALID_STATUS:
            raise ValueError("agent %r: bad status %r"
                             % (handle, status))
        for field in ("responsibilities", "capabilities"):
            if field in agent and not isinstance(agent[field], list):
                raise ValueError("agent %r: %r must be a list"
                                 % (handle, field))
    return data


def save_roster(path, roster):
    validate_roster(roster)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(roster, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def new_task_id():
    return "%06x" % random.getrandbits(24)


def render_task_assign(handle, title, instructions, due=None,
                       task_id=None, display_name=None):
    """Full room message assigning a task to @handle."""
    who = "@" + (display_name or handle)
    block = {"kind": "task_assign",
             "task_id": task_id or new_task_id(),
             "to": handle, "title": title,
             "instructions": instructions}
    if due:
        # Accept datetime or ISO string; normalize to ISO-8601.
        if isinstance(due, datetime.datetime):
            due = due.isoformat()
        block["due"] = str(due)
    head = "%s new task for you: **%s**" % (who, title)
    if due:
        head += " (due %s)" % block["due"]
    return "%s\n\nDetails:\n%s" % (head, fleet_blocks.make_block(block))


def render_role_assign(handle, position, responsibilities,
                       instructions=None, display_name=None):
    """Full room message giving @handle its position, responsibilities
    and standing instructions."""
    who = "@" + (display_name or handle)
    block = {"kind": "role_assign", "to": handle,
             "position": position,
             "responsibilities": list(responsibilities)}
    if instructions:
        block["instructions"] = instructions
    lines = ["%s you are now **%s**." % (who, position),
             "", "Responsibilities:"]
    lines += ["- %s" % r for r in responsibilities]
    if instructions:
        lines += ["", "Standing instructions:", instructions]
    lines += ["", fleet_blocks.make_block(block)]
    return "\n".join(lines)


def scan_text(text):
    """Parse every fleet block in room text; returns the list of
    validated block dicts, oldest-first."""
    return fleet_blocks.extract_blocks(text)


def task_states(blocks):
    """``{task_id: {"state": ..., "by": ..., "note": ...}}`` reduced
    from a block list (oldest-first)."""
    states = {}
    for b in blocks:
        kind = b["kind"]
        if kind not in ("task_assign", "task_ack",
                        "task_done", "task_failed"):
            continue
        tid = str(b["task_id"])
        states[tid] = {"state": kind, "by": b.get("by"),
                       "note": b.get("note"),
                       "title": b.get("title")}
    return states


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _add_roster_common(sp):
    sp.add_argument("--roster", default="fleet.json")


def cmd_roster_show(args):
    roster = load_roster(args.roster)
    agents = roster["agents"]
    if not agents:
        print("(roster empty)")
        return
    for handle in sorted(agents):
        a = agents[handle]
        pos = a.get("position") or "-"
        print("@%s — %s — %s — %s"
              % (handle, a.get("display_name", handle),
                 pos, a.get("status", "active")))


def cmd_roster_add(args):
    roster = load_roster(args.roster)
    handle = args.handle.lower()
    if handle in roster["agents"]:
        raise SystemExit("agent @%s already in roster" % handle)
    roster["agents"][handle] = {
        "agent_id": args.agent_id,
        "display_name": args.display_name or args.handle,
        "position": None, "responsibilities": [],
        "instructions": None,
        "capabilities": args.capabilities or [],
        "status": "active",
    }
    save_roster(args.roster, roster)
    print("added @%s" % handle)


def cmd_roster_set(args):
    roster = load_roster(args.roster)
    handle = args.handle.lower()
    if handle not in roster["agents"]:
        raise SystemExit("unknown agent @%s" % handle)
    agent = roster["agents"][handle]
    if args.position is not None:
        agent["position"] = args.position
    if args.responsibilities is not None:
        agent["responsibilities"] = args.responsibilities
    if args.instructions is not None:
        agent["instructions"] = args.instructions
    if args.capabilities is not None:
        agent["capabilities"] = args.capabilities
    if args.status is not None:
        agent["status"] = args.status
    save_roster(args.roster, roster)
    print("updated @%s" % handle)


def cmd_task_render(args):
    roster = load_roster(args.roster)
    handle = args.to.lower()
    display = (roster["agents"].get(handle, {}).get("display_name")
               if args.roster else None)
    print(render_task_assign(handle, args.title, args.instructions,
                             due=args.due, task_id=args.task_id,
                             display_name=display or args.to))


def cmd_role_render(args):
    roster = load_roster(args.roster)
    handle = args.to.lower()
    display = (roster["agents"].get(handle, {}).get("display_name")
               if args.roster else None)
    print(render_role_assign(handle, args.position,
                             args.responsibilities,
                             instructions=args.instructions,
                             display_name=display or args.to))


def cmd_scan(args):
    text = sys.stdin.read()
    blocks = scan_text(text)
    if not blocks:
        print("(no fleet blocks found)")
        return
    for b in blocks:
        print(json.dumps(b, ensure_ascii=False))
    print("--- task states ---")
    for tid, st in sorted(task_states(blocks).items()):
        print("%s: %s by=%s note=%s"
              % (tid, st["state"], st["by"], st["note"]))


def build_parser():
    p = argparse.ArgumentParser(prog="fleet_ops.py",
                                description="Fleet operations tooling")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("roster", help="manage the fleet roster")
    rsub = r.add_subparsers(dest="rcmd", required=True)
    s = rsub.add_parser("show"); _add_roster_common(s)
    s.set_defaults(fn=cmd_roster_show)
    a = rsub.add_parser("add"); _add_roster_common(a)
    a.add_argument("--handle", required=True)
    a.add_argument("--agent-id", required=True)
    a.add_argument("--display-name")
    a.add_argument("--capabilities", nargs="*")
    a.set_defaults(fn=cmd_roster_add)
    st = rsub.add_parser("set"); _add_roster_common(st)
    st.add_argument("--handle", required=True)
    st.add_argument("--position")
    st.add_argument("--responsibilities", nargs="*")
    st.add_argument("--instructions")
    st.add_argument("--capabilities", nargs="*")
    st.add_argument("--status", choices=_VALID_STATUS)
    st.set_defaults(fn=cmd_roster_set)

    t = sub.add_parser("task", help="task cards")
    tsub = t.add_subparsers(dest="tcmd", required=True)
    tr = tsub.add_parser("render"); _add_roster_common(tr)
    tr.add_argument("--to", required=True)
    tr.add_argument("--title", required=True)
    tr.add_argument("--instructions", required=True)
    tr.add_argument("--due")
    tr.add_argument("--task-id")
    tr.set_defaults(fn=cmd_task_render)

    ro = sub.add_parser("role", help="role cards")
    rosub = ro.add_subparsers(dest="ocmd", required=True)
    rr = rosub.add_parser("render"); _add_roster_common(rr)
    rr.add_argument("--to", required=True)
    rr.add_argument("--position", required=True)
    rr.add_argument("--responsibilities", nargs="+", required=True)
    rr.add_argument("--instructions")
    rr.set_defaults(fn=cmd_role_render)

    sc = sub.add_parser("scan", help="parse fleet blocks from room text")
    sc.set_defaults(fn=cmd_scan)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
