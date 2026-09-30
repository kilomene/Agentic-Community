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
    python3 fleet_ops.py board list [--state S] [--assignee H]
    python3 fleet_ops.py board show <id>
    python3 fleet_ops.py board dep <id> <blocker-id>
    python3 fleet_ops.py board states
    python3 fleet_ops.py roster presence        # fleet liveness from last_seen
    python3 fleet_ops.py roster seen --handle tobi   # mark @tobi seen now
    python3 fleet_ops.py ledger --agent tobi     # diligence summary

Stdlib only.
"""

import argparse
import datetime
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "autopilot_hooks"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fleet_blocks  # noqa: E402
# --- wake config (workstream C) ---
import wake  # noqa: E402
# --- end wake config (workstream C) ---
# --- task board (workstream E) ---
import fleet_board  # noqa: E402  (shared task board w/ dependencies)
# --- end task board (workstream E) ---
# --- one-step enrollment (workstream D) ---
import enrollment  # noqa: E402  (enrollment window state for auto-pairing)
# --- end one-step enrollment (workstream D) ---

# --- heartbeat presence (workstream A) ---------------------------------------
# Fleet liveness: agents running the acp relay daemon send a heartbeat
# control frame every 5s; the relay records last_heartbeat per peer id.
# The head mirrors that into each roster agent's ``last_seen``
# (integer epoch seconds) — e.g. with `roster seen --handle tobi` after
# reading the relay presence listing — and displays it with
# `roster presence`.
#
# Note: workstream C (wake) keeps a SEPARATE head-side presence STORE
# ({handle: last_seen} JSON file via wake.touch_presence). The roster
# field is the human-readable source of record; `roster seen` can also
# update the wake presence store with --presence <path> so the two
# agree. Either may be read; don't write raw last_seen into both by
# hand — use the CLI.
#
# HEARTBEAT = LIVENESS DETECTION, NOT RESURRECTION. A stale agent is
# never auto-revived by any of this: the operator decides what to do
# about it.

PRESENCE_ALIVE_S = 15   # last seen <15s: heartbeat flowing
PRESENCE_IDLE_S = 60    # 15s-60s: beats missing, link may still be up
# beyond 60s: stale — dead, dropped, or daemon down.


def presence_status(age_s):
    """'alive' | 'idle' | 'stale' from seconds since last heartbeat.

    age_s may be None (never seen) -> 'stale'."""
    if age_s is None:
        return "stale"
    if age_s < PRESENCE_ALIVE_S:
        return "alive"
    if age_s < PRESENCE_IDLE_S:
        return "idle"
    return "stale"


def cmd_roster_seen(args):
    # --- heartbeat presence (workstream A) ---
    roster = load_roster(args.roster)
    handle = args.handle.lower()
    if handle not in roster["agents"]:
        raise SystemExit("unknown agent @%s" % handle)
    at = int(args.at) if args.at is not None else int(time.time())
    roster["agents"][handle]["last_seen"] = at
    save_roster(args.roster, roster)
    if getattr(args, "presence", None):
        wake.touch_presence(args.presence, handle, now=at)
    print("marked @%s seen" % handle)
    # --- end heartbeat presence (workstream A) ---


def cmd_roster_presence(args):
    # --- heartbeat presence (workstream A) ---
    roster = load_roster(args.roster)
    agents = roster["agents"]
    if not agents:
        print("(roster empty)")
        return
    now = int(time.time())
    for handle in sorted(agents):
        a = agents[handle]
        seen = a.get("last_seen")
        age = None if seen is None else now - seen
        status = presence_status(age)
        if age is None:
            detail = "never seen"
        elif age < 0:
            detail = "last_seen in the future"
        elif age < 120:
            detail = "seen %ds ago" % age
        else:
            detail = "seen %dm ago" % (age // 60)
        print("@%-16s %-6s %s" % (handle, status, detail))
    # --- end heartbeat presence (workstream A) ---


# --- end heartbeat presence (workstream A) -----------------------------------

# --- work ledger (workstream H) ---
import work_ledger  # noqa: E402
# --- end work ledger (workstream H) ---

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
        # --- wake config (workstream C) ---
        # Optional per-agent wake block; structural validation only here
        # (URL scheme policy is enforced at assignment time, where tests
        # may allow http-loopback). Anchor: WAKE-VALIDATE.
        if "wake" in agent:
            try:
                wake.parse_wake_config(agent["wake"])
            except ValueError as e:
                raise ValueError("agent %r: bad wake config: %s"
                                 % (handle, e))
        # --- end wake config (workstream C) ---
        # --- heartbeat presence (workstream A) ---
        # Optional per-agent last_seen (integer epoch seconds, written by
        # `roster seen` when the head observes a heartbeat / activity).
        ls = agent.get("last_seen")
        if ls is not None and not isinstance(ls, int):
            raise ValueError("agent %r: 'last_seen' must be an integer "
                             "(epoch seconds)" % handle)
        # --- end heartbeat presence (workstream A) ---
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


# --- wake config (workstream C) ---
# Workstream C: wake-on-task. The head-side task assignment path. When
# the target agent's presence is STALE (last_seen older than
# stale_after_s, or never seen) AND its roster entry carries a wake
# config, the wake webhook fires (short timeout, non-blocking) and the
# task is queued as a direct message through the daemon outbox so the
# relay mailbox holds it until the agent boots and drains it. The whole
# chain is audit-logged. A wake failure never blocks the assignment.
# Anchor: WAKE-ASSIGN.


def assign_task(roster_path, handle, title, instructions, due=None,
                task_id=None, presence_path=None,
                stale_after_s=wake.DEFAULT_STALE_AFTER_S,
                outbox_dir=None, audit_path=None,
                secret_resolver=None, allow_insecure_wake=False):
    """Assign a task to @handle with wake-on-task semantics.

    Returns a dict: task_id, to, stale, wake ({fired,status,error} or
    None), card (room text), outbox_path, events. Raises SystemExit on
    unknown handle.
    """
    roster = load_roster(roster_path)
    handle = handle.lower()
    if handle not in roster["agents"]:
        raise SystemExit("unknown agent @%s" % handle)
    agent = roster["agents"][handle]
    task_id = task_id or new_task_id()
    events = []

    presence = (wake.read_presence(presence_path)
                if presence_path else {})
    stale = wake.is_stale(handle, presence,
                          stale_after_s=stale_after_s)
    wake_result = None
    try:
        wake_cfg = wake.parse_wake_config(agent.get("wake"))
    except ValueError as e:
        raise SystemExit("agent @%s: bad wake config: %s" % (handle, e))
    if wake_cfg is not None:
        try:
            wake.validate_wake_url(wake_cfg,
                                   allow_insecure=allow_insecure_wake)
        except ValueError as e:
            raise SystemExit("agent @%s: bad wake url: %s" % (handle, e))

    def _audit(event, **fields):
        rec = {"event": event, "to": handle, "task_id": task_id}
        rec.update(fields)
        events.append(rec)
        if audit_path:
            wake.audit_log(audit_path, rec)

    card = render_task_assign(handle, title, instructions, due=due,
                              task_id=task_id,
                              display_name=agent.get("display_name"))

    # 1) wake the agent when it is stale and wake is configured.
    if stale and wake_cfg is not None:
        _audit("wake_attempted", url=wake_cfg["url"])
        wake_result = wake.fire_wake(
            wake_cfg,
            {"to": handle, "task_id": task_id, "title": title,
             "reason": "task_assigned_while_stale"},
            secret_resolver=secret_resolver)
        if wake_result["fired"]:
            _audit("wake_fired", status=wake_result["status"])
        else:
            _audit("wake_failed", error=wake_result["error"])
    elif stale:
        _audit("wake_skipped", reason="no_wake_config")

    # 2) queue the task so the relay mailbox holds it until the agent
    #    boots and drains it. Outbox format matches the daemon's
    #    _drain_outbox (direct_msg kind, workstream C).
    outbox_path = None
    agent_id = agent.get("agent_id")
    if outbox_dir and agent_id:
        os.makedirs(outbox_dir, exist_ok=True)
        outbox_path = os.path.join(
            outbox_dir, "task-%s-%s.json" % (handle, task_id))
        with open(outbox_path, "w", encoding="utf-8") as fh:
            json.dump({"kind": "direct_msg", "to": handle,
                       "to_pid": agent_id, "task_id": task_id,
                       "text": card}, fh, ensure_ascii=False)
        _audit("task_queued", outbox=outbox_path)
    else:
        _audit("task_not_queued",
               reason="no_outbox_dir" if not outbox_dir else "no_agent_id")

    return {"task_id": task_id, "to": handle, "stale": stale,
            "wake": wake_result, "card": card,
            "outbox_path": outbox_path, "events": events}


# --- end wake config (workstream C) ---


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


# --- task board (workstream E) -------------------------------------------
# Shared task board wiring (see fleet_board.py): every rendered task_assign
# is recorded on the board, and every room scan feeds task_done /
# task_failed / task_ack blocks back into board states. Unblock
# notifications go to the room via the daemon outbox
# (state_dir/outbox/*.json) — NEVER via the `acp` CLI, which would steal
# the daemon's relay socket (see daemon._drain_outbox).

def _board_state_dir():
    return os.environ.get("ACP_STATE_DIR",
                          os.path.expanduser("~/.acp/state"))


def _board_new(db_path=None):
    return fleet_board.FleetBoard(db_path)


def _board_record_assign(task_id, handle, title, due, board_db):
    try:
        board = _board_new(board_db)
    except Exception as e:  # noqa: BLE001 - board must not break rendering
        print("board: unavailable (%s); card still rendered" % e,
              file=sys.stderr)
        return
    try:
        board.create(task_id, title, assignee=handle, due=due,
                     state="assigned")
    except ValueError as e:
        # Re-render of an existing task id: keep the recorded entry.
        print("board: %s" % e, file=sys.stderr)
    finally:
        board.close()


def _board_fleet_group_id():
    try:
        with open(os.path.join(_board_state_dir(), "fleet.json"),
                  "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return None
    return cfg.get("group_id") if isinstance(cfg, dict) else None


def _board_queue_room_message(text):
    """Queue one room message via the daemon outbox pattern. Returns True
    when queued; the daemon drains it through its own relay link."""
    group_id = _board_fleet_group_id()
    if not group_id:
        print("board: no fleet group_id in %s/fleet.json; room notify "
              "skipped" % _board_state_dir(), file=sys.stderr)
        return False
    outbox = os.path.join(_board_state_dir(), "outbox")
    os.makedirs(outbox, exist_ok=True)
    name = "%s-%06x.json" % (
        datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
        random.getrandbits(24))
    tmp = os.path.join(outbox, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"kind": "group_msg", "group_id": group_id,
                   "text": text}, fh, ensure_ascii=False)
    os.replace(tmp, os.path.join(outbox, name))
    return True


def _board_ensure(board, task_id, block):
    """Get the board task, creating it (state open) when the room shows
    activity for a task the board never recorded."""
    t = board.get(task_id)
    if t is None:
        t = board.create(task_id, block.get("title") or task_id,
                         state="open")
    return t


def _board_try_set(board, task_id, state):
    """set_state that never raises; returns True only on a real change."""
    try:
        return board.set_state(task_id, state)
    except ValueError as e:
        print("board: %s -> %s: %s" % (task_id, state, e),
              file=sys.stderr)
        return False


def _board_sync_scan(blocks, board_db=None):
    """Feed scanned room blocks (oldest-first) into the board. Latest
    block per task wins. Returns {assignee: [newly-unblocked tasks]}.
    Idempotent: re-scanning the same blocks changes nothing and notifies
    nobody twice."""
    board = _board_new(board_db)
    try:
        unblocked = {}
        for b in blocks:
            kind = b.get("kind")
            task_id = str(b.get("task_id") or "")
            if not task_id:
                continue
            if kind == "task_assign":
                if board.get(task_id) is None:
                    board.create(task_id, b.get("title") or task_id,
                                 assignee=((b.get("to") or "").lower()
                                           or None),
                                 due=b.get("due"), state="assigned")
            elif kind == "task_ack":
                _board_ensure(board, task_id, b)
                if b.get("status") == "declined":
                    _board_try_set(board, task_id, "failed")
                elif board.get(task_id)["state"] == "blocked":
                    print("board: %s acked but still blocked by deps"
                          % task_id)
                else:
                    _board_try_set(board, task_id, "acked")
            elif kind == "task_done":
                _board_ensure(board, task_id, b)
                if _board_try_set(board, task_id, "done"):
                    for u in board.on_blocker_done(task_id):
                        unblocked.setdefault(u["assignee"], []).append(u)
            elif kind == "task_failed":
                _board_ensure(board, task_id, b)
                if _board_try_set(board, task_id, "failed"):
                    deps = board.dependents(task_id)
                    if deps:
                        # Documented choice: dependents stay blocked; the
                        # head must re-plan or override explicitly.
                        print("board: %s failed; dependent(s) stay blocked: "
                              "%s" % (task_id, ", ".join(deps)))
        for assignee in sorted(unblocked, key=lambda a: a or ""):
            tasks = unblocked[assignee]
            mention = "@%s — " % assignee if assignee else ""
            lines = ["%s%d task(s) unblocked, all blockers done:"
                     % (mention, len(tasks))]
            lines += ["- %s: %s" % (u["id"], u["title"]) for u in tasks]
            if _board_queue_room_message("\n".join(lines)):
                print("board: unblock notify queued for %s (%d task(s))"
                      % ("@%s" % assignee if assignee else "unassigned",
                         len(tasks)))
        return unblocked
    finally:
        board.close()


def _add_board_common(sp):
    sp.add_argument("--board-db", default=None,
                    help="board sqlite path "
                         "(default: $ACP_STATE_DIR/fleet_board.db)")


def cmd_board_list(args):
    board = _board_new(args.board_db)
    try:
        tasks = board.list(state=args.state, assignee=args.assignee)
    finally:
        board.close()
    if not tasks:
        print("(board empty)")
        return
    for t in tasks:
        deps = (" blocked_by=[%s]" % ",".join(t["blocked_by"])
                if t["blocked_by"] else "")
        due = " due=%s" % t["due"] if t["due"] else ""
        print("%s | %-10s | @%-12s | %s%s%s"
              % (t["id"], t["state"], t["assignee"] or "-",
                 t["title"], due, deps))


def cmd_board_show(args):
    board = _board_new(args.board_db)
    try:
        t = board.get(args.task_id)
    finally:
        board.close()
    if t is None:
        raise SystemExit("unknown task %r" % args.task_id)
    for key in ("id", "title", "assignee", "state", "due",
                "created_at", "updated_at"):
        print("%-11s %s" % (key + ":", t[key]))
    print("blocked_by:  %s" % (", ".join(t["blocked_by"]) or "-"))
    print("dependents:  %s" % (", ".join(t["dependents"]) or "-"))


def cmd_board_dep(args):
    board = _board_new(args.board_db)
    try:
        added = board.add_dependency(args.task_id, args.blocker_id)
        t = board.get(args.task_id)
    except ValueError as e:
        raise SystemExit("board: %s" % e)
    finally:
        board.close()
    if added:
        print("dep added: %s blocked by %s (state=%s)"
              % (args.task_id, args.blocker_id, t["state"]))
    else:
        print("dep already recorded")


def cmd_board_states(args):
    board = _board_new(args.board_db)
    try:
        tasks = board.list()
    finally:
        board.close()
    counts = {}
    for t in tasks:
        counts[t["state"]] = counts.get(t["state"], 0) + 1
    print("--- board states ---")
    for s in fleet_board.STATES:
        if counts.get(s):
            print("%-10s %d" % (s, counts[s]))
    for t in tasks:
        print("%s: %s @%s %s" % (t["id"], t["state"],
                                 t["assignee"] or "-", t["title"]))


# --- end task board (workstream E) ---


# --- work ledger (workstream H) ---
def record_block_events(blocks, ledger):
    """Single hook point: reduce fleet blocks to work-ledger events.

    ``blocks`` is the oldest-first list from :func:`scan_text`
    (or any single block dict wrapped in a list). ``ledger`` is a
    :class:`work_ledger.WorkLedger`. Every lifecycle block becomes
    one ledger event; re-scanning the same room text does not
    duplicate rows (dedupe_key per (event, task_id)).

    Wire map: task_assign -> assigned, task_ack -> acked,
    task_done -> done, task_failed -> failed.
    """
    if isinstance(blocks, dict):
        blocks = [blocks]
    wire = {"task_assign": "assigned",
            "task_ack": "acked",
            "task_done": "done",
            "task_failed": "failed"}
    for b in blocks:
        event = wire.get(b.get("kind"))
        if not event:
            continue
        task_id = str(b["task_id"])
        if b["kind"] == "task_assign":
            agent = str(b.get("to", ""))
            detail = b.get("title")
        else:
            agent = str(b.get("by", ""))
            status = b.get("status")
            note = b.get("note")
            detail = " ".join(p for p in (status, note) if p) or None
        ledger.record_event(task_id, agent, event, detail=detail,
                            dedupe_key="%s:%s" % (event, task_id))


def open_ledger(db_arg):
    """WorkLedger honoring an explicit --db, else the default path."""
    return work_ledger.WorkLedger(path=db_arg or work_ledger.default_db_path())
# --- end work ledger (workstream H) ---


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
    # --- task board (workstream E) ---
    # Pre-generate the id so the card and the board entry share it.
    task_id = args.task_id or new_task_id()
    # --- end task board (workstream E) ---
    # --- work ledger (workstream H) ---
    ledger = open_ledger(getattr(args, "db", None))
    try:
        ledger.record_event(task_id, handle, "assigned",
                            detail=args.title)
    finally:
        ledger.close()
    # --- end work ledger (workstream H) ---
    print(render_task_assign(handle, args.title, args.instructions,
                             due=args.due, task_id=task_id,
                             display_name=display or args.to))
    # --- task board (workstream E) ---
    _board_record_assign(task_id, handle, args.title, args.due,
                         args.board_db)
    # --- end task board (workstream E) ---


# --- wake config (workstream C) --- Anchor: WAKE-CLI-HANDLER.
def cmd_task_assign(args):
    result = assign_task(args.roster, args.to, args.title,
                         args.instructions, due=args.due,
                         task_id=args.task_id,
                         presence_path=args.presence,
                         stale_after_s=args.stale_after,
                         outbox_dir=args.outbox_dir,
                         audit_path=args.audit,
                         allow_insecure_wake=args.insecure_wake)
    print(json.dumps(result, ensure_ascii=False, indent=2,
                     default=str))
# --- end wake config (workstream C) ---


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
    # --- work ledger (workstream H) ---
    ledger = open_ledger(getattr(args, "db", None))
    try:
        record_block_events(blocks, ledger)
    finally:
        ledger.close()
    # --- end work ledger (workstream H) ---
    if not blocks:
        print("(no fleet blocks found)")
        return
    for b in blocks:
        print(json.dumps(b, ensure_ascii=False))
    print("--- task states ---")
    for tid, st in sorted(task_states(blocks).items()):
        print("%s: %s by=%s note=%s"
              % (tid, st["state"], st["by"], st["note"]))
    # --- task board (workstream E) ---
    try:
        _board_sync_scan(blocks, args.board_db)
    except Exception as e:  # noqa: BLE001 - board must not break scan
        print("board: sync failed (%s)" % e, file=sys.stderr)
    # --- end task board (workstream E) ---


# --- work ledger (workstream H) ---
def cmd_ledger(args):
    ledger = open_ledger(args.db)
    try:
        if args.task:
            events = ledger.events_for_task(args.task)
            if not events:
                print("(no ledger events for task %s)" % args.task)
                return
            for e in events:
                ts = datetime.datetime.fromtimestamp(
                    e["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                detail = " — %s" % e["detail"] if e["detail"] else ""
                print("%s  @%s  %s%s" % (ts, e["agent"], e["event"],
                                        detail))
        else:
            s = ledger.summary_for_agent(args.agent)
            print("@%s — work ledger summary" % s["agent"])
            for ev, n in s["counts"].items():
                print("  %s: %d" % (ev, n))
            print("  tasks completed: %d" % s["tasks_completed"])
            print("  tasks failed: %d" % s["tasks_failed"])
            ack = s["avg_ack_latency_s"]
            comp = s["avg_completion_time_s"]
            print("  avg ack latency: %s"
                  % ("%.1fs" % ack if ack is not None else "-"))
            print("  avg completion time: %s"
                  % ("%.1fs" % comp if comp is not None else "-"))
    finally:
        ledger.close()
# --- end work ledger (workstream H) ---


# --- one-step enrollment (workstream D) --------------------------------------
# Head-side enrollment mode: `fleet enroll --open <minutes>` opens a
# time-boxed window during which an agent presenting our live pairing
# code auto-completes pairing with NO confirm-code step. The window is
# just enrollment.json in the daemon's state dir — the running daemon
# picks it up on the next pairing attempt, no restart or IPC needed.
# With no window open the confirm-code flow runs untouched.

def _enroll_state_dir(args):
    return os.path.expanduser(args.state_dir)


def _enroll_opened_by(args):
    if args.opened_by:
        return args.opened_by
    try:
        import getpass
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "head"


def _enroll_fmt_ts(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_enroll(args):
    """fleet enroll --open MINUTES | --close | --status"""
    actions = [args.open is not None, args.close, args.status]
    if sum(actions) != 1:
        raise SystemExit(
            "choose exactly one: --open MINUTES, --close, --status")
    state_dir = _enroll_state_dir(args)
    if args.status:
        st = enrollment.status(state_dir)
        if st["open"]:
            print("enrollment window: OPEN")
            print("  opened by: %s at %s" % (st["opened_by"],
                                             _enroll_fmt_ts(st["opened_at"])))
            print("  closes at: %s (%ds remaining)"
                  % (_enroll_fmt_ts(st["open_until"]), st["remaining"]))
        else:
            print("enrollment window: CLOSED")
            if st.get("close_reason"):
                print("  last close: %s" % st["close_reason"])
        return
    if args.close:
        w = enrollment.close_window(state_dir, reason="closed by head")
        print("enrollment window closed (was: %s)"
              % ("open" if w["open"] else w.get("close_reason", "closed")))
        return
    opened_by = _enroll_opened_by(args)
    try:
        w = enrollment.open_window(state_dir, args.open, opened_by)
    except ValueError as e:
        raise SystemExit("cannot open enrollment window: %s" % e)
    print("enrollment window OPEN for %d minutes (until %s), opened by %s"
          % (w["minutes"], _enroll_fmt_ts(w["open_until"]), w["opened_by"]))
    print("agents presenting our pairing code now pair with NO confirm step")


# --- end one-step enrollment (workstream D) ---


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
    # --- heartbeat presence (workstream A) ---
    pr = rsub.add_parser("presence",
                         help="show fleet liveness from roster last_seen")
    _add_roster_common(pr)
    pr.set_defaults(fn=cmd_roster_presence)
    sn = rsub.add_parser("seen",
                         help="mark an agent seen (update roster last_seen)")
    _add_roster_common(sn)
    sn.add_argument("--handle", required=True)
    sn.add_argument("--at", type=int, default=None,
                    help="epoch seconds of the sighting (default: now)")
    sn.add_argument("--presence", default=None,
                    help="also update the wake presence store at this path")
    sn.set_defaults(fn=cmd_roster_seen)
    # --- end heartbeat presence (workstream A) ---

    t = sub.add_parser("task", help="task cards")
    tsub = t.add_subparsers(dest="tcmd", required=True)
    tr = tsub.add_parser("render"); _add_roster_common(tr)
    tr.add_argument("--to", required=True)
    tr.add_argument("--title", required=True)
    tr.add_argument("--instructions", required=True)
    tr.add_argument("--due")
    tr.add_argument("--task-id")
    # --- work ledger (workstream H) ---
    tr.add_argument("--db", default=None,
                    help="work ledger db (default ~/.acp/state/work_ledger.db)")
    # --- end work ledger (workstream H) ---
    # --- task board (workstream E) ---
    _add_board_common(tr)
    # --- end task board (workstream E) ---
    tr.set_defaults(fn=cmd_task_render)

    # --- wake config (workstream C) --- Anchor: WAKE-CLI.
    ta = tsub.add_parser("assign",
                         help="assign a task with wake-on-task semantics")
    _add_roster_common(ta)
    ta.add_argument("--to", required=True)
    ta.add_argument("--title", required=True)
    ta.add_argument("--instructions", required=True)
    ta.add_argument("--due")
    ta.add_argument("--task-id")
    ta.add_argument("--presence",
                    help="presence store json path ({handle: last_seen})")
    ta.add_argument("--stale-after", type=float,
                    default=wake.DEFAULT_STALE_AFTER_S,
                    help="staleness threshold in seconds (default 300)")
    ta.add_argument("--outbox-dir",
                    help="daemon outbox dir for relay-mailbox queueing")
    ta.add_argument("--audit",
                    help="audit trail jsonl path")
    ta.add_argument("--insecure-wake", action="store_true",
                    help="allow http wake urls on loopback (tests only)")
    ta.set_defaults(fn=cmd_task_assign)
    # --- end wake config (workstream C) ---

    ro = sub.add_parser("role", help="role cards")
    rosub = ro.add_subparsers(dest="ocmd", required=True)
    rr = rosub.add_parser("render"); _add_roster_common(rr)
    rr.add_argument("--to", required=True)
    rr.add_argument("--position", required=True)
    rr.add_argument("--responsibilities", nargs="+", required=True)
    rr.add_argument("--instructions")
    rr.set_defaults(fn=cmd_role_render)

    sc = sub.add_parser("scan", help="parse fleet blocks from room text")
    # --- work ledger (workstream H) ---
    sc.add_argument("--db", default=None,
                    help="work ledger db (default ~/.acp/state/work_ledger.db)")
    # --- end work ledger (workstream H) ---
    # --- task board (workstream E) ---
    _add_board_common(sc)
    # --- end task board (workstream E) ---
    sc.set_defaults(fn=cmd_scan)

    # --- work ledger (workstream H) ---
    lg = sub.add_parser("ledger", help="query the work ledger")
    lg.add_argument("--db", default=None,
                    help="work ledger db (default ~/.acp/state/work_ledger.db)")
    lg_sel = lg.add_mutually_exclusive_group(required=True)
    lg_sel.add_argument("--agent",
                        help="per-agent diligence summary (handle, @ optional)")
    lg_sel.add_argument("--task", help="event history for one task id")
    lg.set_defaults(fn=cmd_ledger)
    # --- end work ledger (workstream H) ---

    # --- task board (workstream E) ---
    b = sub.add_parser("board", help="shared task board with dependencies")
    bsub = b.add_subparsers(dest="bcmd", required=True)
    bl = bsub.add_parser("list", help="list board tasks")
    _add_board_common(bl)
    bl.add_argument("--state", choices=fleet_board.STATES)
    bl.add_argument("--assignee")
    bl.set_defaults(fn=cmd_board_list)
    bs = bsub.add_parser("show", help="show one task in detail")
    _add_board_common(bs)
    bs.add_argument("task_id")
    bs.set_defaults(fn=cmd_board_show)
    bd = bsub.add_parser("dep",
                         help="add a dependency: <id> blocked by <blocker-id>")
    _add_board_common(bd)
    bd.add_argument("task_id")
    bd.add_argument("blocker_id")
    bd.set_defaults(fn=cmd_board_dep)
    bst = bsub.add_parser("states", help="board state summary")
    _add_board_common(bst)
    bst.set_defaults(fn=cmd_board_states)
    # --- end task board (workstream E) ---

    # --- one-step enrollment (workstream D) ---
    e = sub.add_parser("enroll",
                       help="one-step pairing enrollment window")
    e.add_argument("--open", type=int, metavar="MINUTES",
                   help="open an enrollment window for MINUTES minutes")
    e.add_argument("--close", action="store_true",
                   help="close the enrollment window now")
    e.add_argument("--status", action="store_true",
                   help="show the enrollment window status")
    e.add_argument("--state-dir",
                   default=os.environ.get(
                       "ACP_STATE_DIR",
                       os.path.expanduser("~/.acp/state")),
                   help="daemon state dir (default $ACP_STATE_DIR or "
                   "~/.acp/state)")
    e.add_argument("--opened-by", default=None,
                   help="who opened the window (default: current user)")
    e.set_defaults(fn=cmd_enroll)
    # --- end one-step enrollment (workstream D) ---
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
