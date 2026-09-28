# Connector Scheduler

Cron-like persisted tasks for the ACP connector. Schedule connector
operations (send a message, set presence) or app-registered callbacks
to run once, on an interval, or daily.

## Actions

**Builtin actions** (always available):
* `send_message(peer_pid, text)` — send a chat message
* `send_file(peer_pid, path)` — send a file
* `set_presence(status)` — update presence

**Custom actions**: Register with `scheduler.register_action(name, fn)`.
Names must match `^[a-z][a-z0-9_]{1,40}$` and cannot shadow builtins.
Actions are code — they must be re-registered on every boot; only the
task rows survive restarts.

**Closed allowlist — no shell**: There is deliberately no shell-out,
subprocess, or `exec` action. The scheduler can only invoke registered
Python callables. This is a hard security boundary: a compromised
schedule DB cannot become remote code execution.

## Scheduling

```python
# Once at a Unix timestamp
tid = c.scheduler.schedule_once(time.time() + 3600, "send_message",
                                [peer_pid, "reminder!"])

# Every N seconds
tid = c.scheduler.schedule_every(86400, "set_presence", ["away"])

# Daily at HH:MM (local time)
tid = c.scheduler.schedule_daily("09:00", "send_message",
                                 [peer_pid, "good morning"])

# Cancel
c.scheduler.cancel(tid)

# List
for t in c.scheduler.list_tasks():
    print(t["task_id"], t["action"], t["next_run"])
```

Unknown action names are rejected **at schedule time** with `AcpError`.

## Results

```python
c.scheduler.on_result(lambda tid, action, ok, detail:
                      print(tid, action, ok, detail))
```

Called after every execution. The audit log also records
`scheduler.task_fired`.

## Persistence

Tasks live in the `scheduled_tasks` table in `connector.db`. They
survive restarts. On boot, the scheduler resumes: overdue `once` tasks
within the misfire grace period fire; `every` tasks resume on their
interval; `daily` tasks compute the next occurrence.

## Misfire policy

* **once**: If the due time passed more than 300s ago (grace period),
  the task is marked `misfire_skipped`, never fired.
* **every**: No catch-up — if intervals were missed, it fires once at
  the next opportunity and resumes the schedule.
* **daily**: Computes the next future occurrence; missed days are not
  backfilled.

Failed `once` tasks are retried after 60s, up to 5 attempts, then
marked failed.

## Execution model

Single background thread, sequential execution. A long-running action
blocks subsequent tasks. Keep actions fast; offload heavy work to your
own threads.

## Demo

```python
from acp_connector import Connector
import time

c = Connector("/tmp/demo", "passphrase", handle="demo")

# Custom action
def greet():
    print("Hello from the scheduler!")

c.scheduler.register_action("greet", greet)
c.scheduler.schedule_once(time.time() + 5, "greet", [])
c.scheduler.on_result(lambda tid, a, ok, d: print("fired:", a, ok))

time.sleep(7)
c.stop()
```

## Limitations (honest)

* **Sequential**: One thread runs all tasks. A stuck action stalls the
  queue.
* **Re-register after restart**: Custom action callables are not
  persisted — only the task rows are. Your app must call
  `register_action` on every boot before due tasks fire.
* **No distributed coordination**: If you run two connectors on the
  same home directory, both will fire the tasks. One scheduler per DB.
