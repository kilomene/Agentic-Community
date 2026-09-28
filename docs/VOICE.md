# Voice Calling (ACP 1.0 V2 extension)

`packages/acp_connector/voice.py` — class `VoiceCalls(connector)`.

Signaling rides ACP (E2E where it matters); audio rides UDP with an
RTP-style framing defined here. The transport carries **real PCM
audio both ways** — proven by `tests/test_voice.py`, which streams a
440 Hz tone one way and 660 Hz the other and verifies each side's
recording with Goertzel analysis.

## Signaling kinds

Registered via `acp_proto.register_kind`:

| kind            | protection       | payload |
|-----------------|------------------|---------|
| `call_invite`   | E2E pairwise     | `{call_id, codec, udp_port, ssrc}` |
| `call_accept`   | E2E pairwise     | `{call_id, udp_port, ssrc}` |
| `call_reject`   | E2E pairwise     | `{call_id, reason}` |
| `call_hangup`   | E2E pairwise     | `{call_id}` |
| `call_keepalive`| signed plaintext | `{call_id, ts}` — every 5 s during a call |

Only codec `"pcm16/8000"` is supported; anything else is auto-rejected
with reason `unsupported codec`. The UDP peer address is the TCP
signaling peer's IP + the advertised `udp_port` (same-host / direct
path assumption for V1 — NAT traversal via the relay is future work).

## Audio framing spec

One UDP datagram = one 20 ms audio frame.

```
12-byte header (big-endian):
  0:     ver   = 1
  1:     flags = 0 (reserved)
  2-3:   seq   u16  per-sender frame counter (wraps at 65535)
  4-7:   ts    u32  sample count at frame start (increments 160/frame)
  8-11:  ssrc  u32  sender's random synchronization source id
payload: 320 bytes PCM16 signed little-endian, mono, 8000 Hz
         (160 samples = 20 ms)
```

Total datagram: 332 bytes.

The UDP socket is `connect()`ed to the peer (connected UDP, still
plain UDP sockets): the sender uses `send()` rather than `sendto()`.
Besides working in sandboxes whose seccomp filters block unconnected
`sendto()`, this is the right semantic for a 1:1 call, and the kernel
drops packets not from the connected peer.

### Jitter buffer

The receiver keeps a reorder buffer keyed by `seq`:

- Packets are played out in `seq` order on a 20 ms tick.
- Duplicates and late packets (behind the playout cursor, compared
  wrap-aware in u16 arithmetic) are dropped.
- A missing `seq` gets a 200 ms grace window; if it is still missing,
  the gap is concealed with silence and the cursor advances.
- Packets with a wrong `ver` or unexpected `ssrc` are dropped.
- Malformed datagrams (wrong length) are dropped.

## Audio source / sink interface

```python
class AudioSource:
    def read_frame(self) -> bytes: ...   # 320 bytes PCM16 mono 8kHz

class AudioSink:
    def write_frame(self, frame: bytes): ...
```

Shipped implementations (stdlib only):

- `ToneSource(freq_hz, amplitude=10000)` — phase-continuous sine wave.
- `WavFileSource(path, loop=True)` — plays a `.wav` as the microphone;
  any PCM wav is converted with `audioop` (width/channels/rate) to
  16-bit mono 8 kHz; loops or emits silence at EOF.
- `WavRecorderSink(path)` — records received audio to `.wav`
  (16-bit mono 8 kHz). Thread-safe.
- `SilenceSource()` / `NullSink()` — safe defaults.

## Honest microphone / speaker limits

Python's standard library has **no microphone or speaker I/O**. This
is a hard platform fact, not a shortcut: there is no `microphone.open()`
in stdlib.

What is real in this build:

- The full call lifecycle: invite → accept/reject → full-duplex UDP
  audio → keepalive → hangup/timeout, with call records in SQLite and
  audit events.
- The framing, sequencing, jitter buffer, and PCM transport — the test
  proves real audio crosses the network in both directions.

What plugs in where: the `AudioSource`/`AudioSink` interface is the
seam where OS audio binds. A `PyAudioSource`/`PyAudioSink` (callback or
blocking stream at 8 kHz mono) implements `read_frame`/`write_frame`
with no changes to signaling or transport. That binding needs PyAudio
/ PortAudio — outside the $0 stdlib build — so live mic/speaker is
**out of scope here** and explicitly not faked: the defaults are
silence in /dev/null out, and the docs say so.

## Call flow

```
A.call_peer(B) ──call_invite(E2E)──▶ B rings
                                     (on_incoming_call cb, or auto_accept)
B.accept_call() ──call_accept(E2E)──▶ A: both open UDP, sender+receiver
                                     threads start, full-duplex audio
              ... 20 ms PCM frames both ways, keepalive/5 s ...
A.hangup_call() ──call_hangup(E2E)──▶ B: sockets closed, threads joined,
                                     call record -> ended, audit
```

`call_peer` blocks until accept / reject / timeout (default 20 s) and
returns the `call_id`; a reject raises `AcpError`. A call with no RTP
and no keepalive for 30 s is timed out and cleaned up. Call records
live in the `calls` SQLite table (`CREATE TABLE IF NOT EXISTS`).

## API

```python
from acp_connector.voice import VoiceCalls, ToneSource, WavRecorderSink

v = VoiceCalls(connector)
v.auto_accept = True                    # or handle on_incoming_call
v.default_source = ToneSource(660)
v.default_sink = WavRecorderSink("call.wav")

call_id = v.call_peer(peer_pid, source=ToneSource(440),
                      sink=WavRecorderSink("me.wav"))
v.accept_call(call_id)                  # manual accept path
v.reject_call(call_id, "busy")
v.hangup_call(call_id)
v.get_call(call_id)                     # live call info or None
v.list_calls(include_ended=True)        # SQLite call records
v.on_incoming_call(lambda info: ...)    # {"call_id","peer_id","codec"}
v.on_call_ended(lambda call_id, reason: ...)
```

## CLI wiring (for the final wiring pass — `apps/acp_cli/cli.py` untouched)

```
acp call <peer> [--tone 440] [--record out.wav] [--src file.wav]
    -> VoiceCalls.call_peer; streams until Ctrl-C, then hangup_call
acp call-answer <call-id>        -> accept_call   (with `acp call-wait` below)
acp call-reject <call-id> [reason]-> reject_call
acp call-hangup <call-id>        -> hangup_call
acp call-wait                    -> on_incoming_call print loop; prompts
                                    answer/reject per incoming call
acp call-list [--all]            -> list_calls
```

`acp call` should default `--src` to a `WavFileSource` when given and
to `ToneSource(440)` (audible proof tone) otherwise, and always pass a
`WavRecorderSink` when `--record` is given. Live mic/speaker becomes
possible the day a PyAudio-backed source/sink is added — no signaling
or transport changes needed.
