"""Phase 52: planner recovery.

The planning system itself is monitored. Planner pathologies detected:

  - repetitive plans: same plan proposed N times with no progress
  - circular reasoning: plan cycles back to an already-failed step
  - identical failed plans: exact repeat of a plan that already failed
  - impossible plans: require unavailable tools or unknown capabilities
  - plans conflicting with verified world state
  - plans producing no progress
  - plans returning to the same step repeatedly

On stall: stop the planning cycle, preserve task state, rebuild a plan
from verified world state, validate the new plan, then resume. Never
allow infinite planning loops (hard cap + rebuild-refusal guard).
"""
import time

# thresholds
REPETITION_LIMIT = 3        # same plan proposed this many times -> stall
NO_PROGRESS_LIMIT = 3       # plans with no observed progress -> stall
MAX_PLAN_CYCLES = 10        # hard cap: never plan forever
REBUILD_WINDOW_S = 300      # rebuild-refusal window
MAX_REBUILDS_PER_WINDOW = 2  # at most this many rebuilds per window

_REBUILDS = {}  # task_id -> [timestamps] (rebuild-refusal guard)


# ---- step-list API (used by the agent runtime) ----
def diagnose_stall(info):
    """Classify a planner stall from an observation dict.

    info: {"step_index": int, "history_kinds": [str...], "cycles": int}.
    Returns a human-readable diagnosis string."""
    info = info or {}
    step = info.get("step_index", "?")
    kinds = info.get("history_kinds", []) or []
    cycles = info.get("cycles", 0)

    if cycles >= MAX_PLAN_CYCLES:
        return f"plan cycle cap reached ({cycles}): plan stall"
    if kinds:
        from collections import Counter
        top, n = Counter(kinds).most_common(1)[0]
        if n >= REPETITION_LIMIT:
            return (f"repetitive failures ({top} x{n}) at step {step}: "
                    f"plan stall")
        return f"repeated failures {dict(Counter(kinds))} at step {step}: plan stall"
    return f"no progress at step {step}: plan stall"


def rebuild_plan(task_id, steps, failed_idx, reason="", store=None,
                 journal=None):
    """Rebuild the step list after a planner stall.

    Keeps steps before the failed one, replaces the failed step with an
    explicit recovery step, and prunes steps whose op_id is already
    COMPLETED in the registry (when store is given).

    Rebuilds are refused after MAX_REBUILDS_PER_WINDOW within
    REBUILD_WINDOW_S for the same task — a planner that keeps rebuilding
    is a stall itself, not a recovery.

    Returns (new_steps, reason_str).
    """
    now = time.time()
    history = [t for t in _REBUILDS.get(task_id, [])
               if now - t < REBUILD_WINDOW_S]
    if len(history) >= MAX_REBUILDS_PER_WINDOW:
        return list(steps or []), (
            f"rebuild refused: {len(history)} rebuilds in "
            f"{REBUILD_WINDOW_S}s — planner stall escalated to human")
    history.append(now)
    _REBUILDS[task_id] = history

    steps = list(steps or [])
    failed = steps[failed_idx] if 0 <= failed_idx < len(steps) else {}
    new_steps = []
    for i, s in enumerate(steps):
        if i < failed_idx:
            new_steps.append(s)
            continue
        if i == failed_idx:
            old_name = s.get("name", f"step-{i}")
            new_steps.append({
                "name": f"recover:{old_name}",
                "tool": "shell",
                # static safe command: the reason is informational only and
                # must never be interpolated into shell (parens/quotes in
                # diagnosis text would break or inject).
                "args": {"command": "echo planner-recovery-ok"},
                "recovering": old_name,
                "recovery_reason": reason,
            })
            continue
        # after the failed step: keep unless its op already completed
        op_id = s.get("op_id")
        if op_id and store:
            rec = store.op_get(op_id)
            if rec and rec["status"] == "COMPLETED":
                (journal or (store.journal if store else None) or
                 (lambda *a, **k: None))("PLAN_PRUNE_COMPLETED",
                                         task_id=task_id, step=i,
                                         op_id=op_id)
                continue
        new_steps.append(s)
    return new_steps, f"rebuilt: {reason or diagnosis_of(failed)}"


def diagnosis_of(failed_step):
    return f"step '{failed_step.get('name', '?')}' failed repeatedly"


def validate_plan(steps):
    """Validate every step's shape (schema + tool enum + required args).
    Returns (valid, issues). Never executes anything."""
    from . import model as modelmod
    issues = []
    steps = list(steps or [])
    if not steps:
        issues.append("plan is empty")
    for i, step in enumerate(steps):
        action = {"tool": step.get("tool"), "args": step.get("args", {})}
        if "verify" in step:
            action["verify"] = step["verify"]
        ok, errs = modelmod.validate_action(action)
        if not ok:
            issues.append(f"step {i}: {'; '.join(errs)}")
    return (len(issues) == 0), issues
