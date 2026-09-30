# One-step enrollment

Head-side enrollment mode: `fleet enroll --open <minutes>` opens a
time-boxed window during which an agent presenting our live pairing code
auto-completes pairing with **NO confirm-code step**. When no window is
open, the normal confirm-code flow runs untouched — that default never
changes.

```
fleet enroll --open 30     # open a 30-minute window
fleet enroll --status      # show window state / time remaining
fleet enroll --close       # close the window now
```

The window is just `enrollment.json` in the daemon's state dir
(default `~/.acp/state`, overridable with `--state-dir` / `$ACP_STATE_DIR`),
so the head CLI and the running daemon coordinate through the
filesystem — no IPC, no daemon restart needed. A window survives daemon
restarts (it is time-boxed, not process-boxed).

## How it works

1. The head opens a window (who opened it and when are recorded).
2. An agent looks up our pairing code on the relay and starts pairing
   (`pair-code <code>`). Its client includes the presented code in the
   pair_request.
3. On the pairing request, the daemon checks: **window open AND the
   presented code equals the daemon's currently claimed pairing code**.
   If both hold, the daemon accepts immediately, skips the confirm-code
   step, and pairing completes.
4. The enrollment is written to the audit log (`pairing.enrolled`) with
   the peer id, handle, timestamp, and `"via": "enrollment"`, and to
   `pairing-requests.json` with `"enrolled": true`.

Expiry is enforced in two independent places — never a single timer:

* **on every pairing attempt** (`_maybe_enroll` → `get_window`
  auto-closes an expired window before any decision), and
* **on a periodic sweep** (`_enrollment_sweep`, every serve-loop cycle).

A window is capped at 24 hours (`enrollment.MIN/MAX_MINUTES`); anything
outside 1–1440 minutes is rejected.

## The trust tradeoff — read this before opening a window

Pairing codes are a **single-use rendezvous with a TTL**: anyone who
learns the code can resolve it to our peer id on the relay. The normal
flow adds a second factor — the 6-char confirm code shown only on our
side, typed on the *other* side out-of-band — so a leaked pairing code
alone cannot complete pairing.

**Opening an enrollment window deliberately drops that second factor.**
During the window, *anyone who knows our pairing code can pair with us*,
with no human in the loop. That is the entire point of the feature
(hands-free fleet enrollment), and it is safe only under these
conditions:

* **Open windows only when you are actively enrolling.** Close the
  window (`fleet enroll --close`) the moment enrollment is done — do
  not leave it open "just in case".
* **Keep windows short.** Minutes, not hours. The 24h cap is a
  backstop, not a recommendation.
* **Treat the pairing code as sensitive while a window is open.**
  Outside a window a leaked code is harmless without the confirm step;
  inside a window it is a pairing credential.
* **Watch the audit log.** Every enrollment is logged
  (`pairing.enrolled` with peer id/handle/time). If you see a peer you
  did not expect, close the window immediately and unpair the peer.

What enrollment does **not** change:

* Identity keys are still verified mid-handshake (a key swap still
  fails the pairing).
* The presented code is still checked — it must equal the daemon's
  *live claimed* code, compared timing-safe. A request that presents
  no code (direct peer-id pairing) or the wrong code falls back to the
  confirm-code flow even inside a window.
* The initiator must run a client that sends the presented code and
  auto-confirms on the enrollment flag. Older clients simply wait for
  the confirm code as before — they cannot be tricked into skipping
  it, and the responder never completes unilaterally.

## For agent developers

Initiator side (same-repo clients): `pair_initiate_code(code)` already
carries the code through; when the responder's challenge carries
`"enrollment": true`, the client auto-confirms with the presented code
(`PairingSession.confirm_enrollment`) instead of waiting for a human.
Direct-TCP pairing can opt in with `pair_initiate(host, port,
relay_code=...)`.
