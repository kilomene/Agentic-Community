"""Tests for voice calling (packages/acp_connector/voice.py).

Two real connectors on localhost, real signaling crypto over ACP, real
PCM audio over UDP.

  1. signaling handshake + full-duplex audio proof: A streams a 440 Hz
     tone, B streams 660 Hz for ~3 s, both record; Goertzel analysis
     proves A's recording carries B's 660 Hz and B's carries A's
     440 Hz — i.e. real audio traversed the network both ways.
  2. reject flow: callee rejects, caller gets AcpError, record closed.
  3. hangup cleanup: sockets closed, threads stopped, call record ended.

Run: python3 -m pytest tests/test_voice.py -q
"""
import math
import os
import shutil
import struct
import sys
import tempfile
import time
import wave

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))

from acp_proto import AcpError  # noqa: E402
from acp_connector import Connector  # noqa: E402
from acp_connector.voice import (  # noqa: E402
    VoiceCalls, ToneSource, WavRecorderSink, NullSink,
)

PASS_PHRASE = "voice-test-pass"


def wait_until(fn, timeout=60, interval=0.2, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(interval)
    raise AssertionError(f"timeout waiting for {what}")


def expect_acp_error(fn, code):
    try:
        fn()
    except AcpError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e.detail}"
        return e
    raise AssertionError(f"expected AcpError({code}), none raised")


def make_node(handle):
    home = tempfile.mkdtemp(prefix="acp-voice-test-")
    c = Connector(home, PASS_PHRASE, handle=handle)
    port = c.start_server("127.0.0.1", 0)
    return c, home, port


def trust(a, port_a, b, port_b):
    for x, y, port_y in ((a, b, port_b), (b, a, port_a)):
        x._store_peer(y.peer_id, y.handle, y.identity.ed_pub.hex(),
                      y.identity.x_pub.hex())
        conn = x.transport.connect("127.0.0.1", port_y)
        x._bind_conn(y.peer_id, conn)
        x._spawn_reader(conn)


ca, home_a, port_a = make_node("v-alice")
cb, home_b, port_b = make_node("v-bob")
trust(ca, port_a, cb, port_b)
va, vb = VoiceCalls(ca), VoiceCalls(cb)


# ------------------------------------------------------------ DSP helpers
def read_wav_samples(path):
    w = wave.open(path, "rb")
    assert w.getnchannels() == 1 and w.getsampwidth() == 2
    assert w.getframerate() == 8000
    raw = w.readframes(w.getnframes())
    w.close()
    return [struct.unpack_from("<h", raw, i)[0]
            for i in range(0, len(raw), 2)]


def goertzel(samples, freq, sr=8000):
    """Power of `freq` in `samples` (stdlib-only DFT bin estimate)."""
    n = len(samples)
    k = int(0.5 + freq * n / sr)
    coeff = 2.0 * math.cos(2.0 * math.pi * k / n)
    s1 = s2 = 0.0
    for x in samples:
        s0 = x + coeff * s1 - s2
        s2, s1 = s1, s0
    return s1 * s1 + s2 * s2 - coeff * s1 * s2


def dominant_tone(path, expect_hz, other_hz):
    samples = read_wav_samples(path)
    assert len(samples) > 8000, f"too few recorded samples: {len(samples)}"
    seg = samples[len(samples) // 3: 2 * len(samples) // 3]
    p_expect = goertzel(seg, expect_hz)
    p_other = goertzel(seg, other_hz)
    print(f"   {os.path.basename(path)}: {expect_hz}Hz={p_expect:.2e}"
          f" {other_hz}Hz={p_other:.2e}", flush=True)
    assert p_expect > 4 * p_other, (
        f"{expect_hz} Hz does not dominate {other_hz} Hz in {path}")


# ------------------------------------------------------------------ 1. call
def test_full_duplex_audio_proof():
    rec_a = os.path.join(home_a, "rec_a.wav")
    rec_b = os.path.join(home_b, "rec_b.wav")
    sink_a = WavRecorderSink(rec_a)
    sink_b = WavRecorderSink(rec_b)
    vb.auto_accept = True
    vb.default_source = ToneSource(660)
    vb.default_sink = sink_b

    call_id = va.call_peer(cb.peer_id, source=ToneSource(440),
                           sink=sink_a)
    assert va.get_call(call_id)["state"] == "active"
    wait_until(lambda: vb.get_call(call_id) is not None
               and vb.get_call(call_id)["state"] == "active",
               what="callee active")

    time.sleep(3.0)  # stream both directions

    va.hangup_call(call_id)
    wait_until(lambda: va.get_call(call_id) is None, what="caller cleanup")
    wait_until(lambda: vb.get_call(call_id) is None, what="callee cleanup")
    sink_a.close()
    sink_b.close()

    # A must have received B's 660 Hz; B must have received A's 440 Hz.
    dominant_tone(rec_a, 660, 440)
    dominant_tone(rec_b, 440, 660)

    recs = va.list_calls(include_ended=True)
    mine = [r for r in recs if r["call_id"] == call_id]
    assert mine and mine[0]["state"] == "ended", "call not recorded ended"
    assert mine[0]["direction"] == "outgoing"
    recs_b = vb.list_calls(include_ended=True)
    mine_b = [r for r in recs_b if r["call_id"] == call_id]
    assert mine_b and mine_b[0]["direction"] == "incoming"


# ------------------------------------------------------------------ 2. reject
def test_reject_flow():
    vb.auto_accept = False
    vb.default_sink = NullSink()
    vb.on_incoming_call(lambda info: vb.reject_call(info["call_id"],
                                                   "busy"))
    expect_acp_error(
        lambda: va.call_peer(cb.peer_id, source=ToneSource(440),
                             sink=NullSink()),
        "INTERNAL")
    # Rejection closes the record on both sides.
    recs = va.list_calls(include_ended=True)
    rej = [r for r in recs if r["peer_id"] == cb.peer_id
           and r["state"] == "rejected"]
    assert rej, "caller has no rejected call record"
    wait_until(lambda: not vb.list_calls(), what="callee cleanup")


# ------------------------------------------------------------------ 3. hangup
def test_hangup_cleanup():
    vb.auto_accept = True
    vb.default_source = ToneSource(660)
    vb.default_sink = NullSink()
    call_id = va.call_peer(cb.peer_id, source=ToneSource(440),
                           sink=NullSink())
    wait_until(lambda: vb.get_call(call_id) is not None,
               what="callee ringing/active")
    # Callee hangs up this time.
    vb.hangup_call(call_id)
    wait_until(lambda: va.get_call(call_id) is None, what="caller cleanup")
    wait_until(lambda: vb.get_call(call_id) is None, what="callee cleanup")
    live_a = [t for t in (va._calls.get(call_id) or {}).get("threads", [])
              if t.is_alive()]
    assert not live_a, "caller media threads still alive"
    rec = [r for r in va.list_calls(include_ended=True)
           if r["call_id"] == call_id][0]
    assert rec["state"] == "ended" and rec["ended_at"], \
        "call record not closed"


def teardown_module():
    for c in (ca, cb):
        try:
            c.stop()
        except Exception:
            pass
    for h in (home_a, home_b):
        shutil.rmtree(h, ignore_errors=True)
