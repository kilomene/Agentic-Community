"""Phase 53: progress detection from OBSERVABLE state changes.

Progress is never measured by model output. It is measured by the
task's verified world-state (progress.step / progress.last_ok keys,
updated by the agent on every verified step): a changing fingerprint
of that state means real progress; a frozen one means the task is
stalled and recovery should be triggered.
"""
import hashlib
import json


# ---- store-backed progress tracking (agent integration) ----
def fingerprint_of(store):
    """Hash of the task's observable world-state (progress.* keys, excluding
    the tracker's own history). The agent updates progress.step/last_ok on
    every verified step, so a changing fingerprint means real progress."""
    data = {}
    for k, v in store.world_all().items():
        if k.startswith("progress.") and ".fingerprints." not in k:
            data[k] = v["value"]
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:16]


def track_stall(store, task_id, max_same=3):
    """Record the current observable fingerprint for a task.

    Returns (stalled, consecutive_identical): stalled is True when the
    last `max_same` fingerprints are identical, i.e. repeated actions
    produced no observable state change.
    """
    fp = fingerprint_of(store)
    key = f"progress.fingerprints.{task_id}"
    hist = store.world_get(key) or []
    hist = (hist + [fp])[-max_same:]
    store.world_set(key, hist, verifier="progress:tracker")
    # count trailing identical fingerprints
    n = 1
    for prev in reversed(hist[:-1]):
        if prev == fp:
            n += 1
        else:
            break
    stalled = len(hist) == max_same and n == max_same
    if stalled:
        store.journal("PROGRESS_STALLED", task_id=task_id,
                      unchanged_cycles=n)
    return stalled, n
