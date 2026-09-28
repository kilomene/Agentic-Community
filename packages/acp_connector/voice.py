"""Voice calling for ACP 1.0 (V2 extension).

Signaling rides ACP (kinds registered via acp_proto.register_kind):

  call_invite    E2E pairwise     {call_id, codec, udp_port, ssrc}
  call_accept    E2E pairwise     {call_id, udp_port, ssrc}
  call_reject    E2E pairwise     {call_id, reason}
  call_hangup    E2E pairwise     {call_id}
  call_keepalive plaintext signed {call_id, ts}

The only supported codec is "pcm16/8000": 16-bit signed PCM, mono,
8 kHz, 20 ms frames (320 bytes).

Audio transport: UDP with an RTP-style framing defined here (documented
in docs/VOICE.md). 12-byte header, big-endian:

    0:     ver   = 1
    1:     flags = 0 (reserved)
    2-3:   seq   u16  (per-sender frame counter, wraps)
    4-7:   ts    u32  (sample count at frame start, 160/frame)
    8-11:  ssrc  u32  (sender's random synchronization source id)
    12..:  320 bytes PCM16 mono 8 kHz payload

The receiver runs a jitter buffer: packets are reordered by seq inside
a 200 ms window; duplicates and late packets (older than the playout
cursor, wrap-aware) are dropped; a gap that persists past 200 ms is
concealed with silence and the cursor advances.

Audio I/O is the AudioSource / AudioSink interface. The transport
carries real PCM audio both ways; where the samples come from / go to
is the application's binding (see docs/VOICE.md for the honest
microphone/speaker story on a $0 stdlib build).
"""
import math
import socket
import struct
import threading
import time
import wave

from acp_crypto import random_bytes
from acp_proto import AcpError, b62encode, register_kind

CALL_INVITE = register_kind(
    "call_invite", e2e=True,
    schema=("call_id", "codec", "udp_port", "ssrc"))
CALL_ACCEPT = register_kind(
    "call_accept", e2e=True, schema=("call_id", "udp_port", "ssrc"))
CALL_REJECT = register_kind(
    "call_reject", e2e=True, schema=("call_id", "reason"))
CALL_HANGUP = register_kind(
    "call_hangup", e2e=True, schema=("call_id",))
CALL_KEEPALIVE = register_kind(
    "call_keepalive", e2e=False, schema=("call_id", "ts"))

CODEC = "pcm16/8000"
SAMPLE_RATE = 8000
FRAME_SAMPLES = 160          # 20 ms at 8 kHz
FRAME_BYTES = 320            # 160 samples x 2 bytes PCM16 mono
RTP_HEADER = struct.Struct(">BBHII")
RTP_VERSION = 1
JITTER_WINDOW_S = 0.200
KEEPALIVE_S = 5
CALL_TIMEOUT_S = 30
ACCEPT_TIMEOUT_S = 20

_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls(
  call_id    TEXT PRIMARY KEY,
  peer_id    TEXT NOT NULL,
  direction  TEXT NOT NULL,
  state      TEXT NOT NULL,
  codec      TEXT NOT NULL,
  local_port INTEGER,
  remote_port INTEGER,
  local_ssrc INTEGER,
  remote_ssrc INTEGER,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER
);
"""


# ------------------------------------------------------------ audio interface
class AudioSource:
    """Produces one 20 ms frame (320 bytes PCM16 mono 8 kHz) per call."""

    def read_frame(self) -> bytes:
        raise NotImplementedError


class AudioSink:
    """Consumes one 20 ms frame (320 bytes PCM16 mono 8 kHz) per call."""

    def write_frame(self, frame: bytes):
        raise NotImplementedError


class SilenceSource(AudioSource):
    """Yields digital silence (used as the safe default source)."""

    def read_frame(self):
        return b"\x00" * FRAME_BYTES


class NullSink(AudioSink):
    """Discards received audio (used as the safe default sink)."""

    def write_frame(self, frame):
        pass


class ToneSource(AudioSource):
    """Sine-wave generator. Phase-continuous across read_frame calls."""

    def __init__(self, freq_hz, amplitude=10000,
                 sample_rate=SAMPLE_RATE):
        self.freq = float(freq_hz)
        self.amplitude = int(amplitude)
        self.sample_rate = sample_rate
        self._phase = 0.0
        self._step = 2.0 * math.pi * self.freq / self.sample_rate

    def read_frame(self):
        out = bytearray(FRAME_BYTES)
        for i in range(FRAME_SAMPLES):
            s = int(self.amplitude * math.sin(self._phase))
            self._phase += self._step
            if self._phase >= 2.0 * math.pi:
                self._phase -= 2.0 * math.pi
            struct.pack_into("<h", out, i * 2, max(-32768, min(32767, s)))
        return bytes(out)


class WavFileSource(AudioSource):
    """Plays a .wav file as the call's microphone.

    Any PCM wav is accepted; audioop converts sample width, channels
    and sample rate to 16-bit mono 8 kHz. Loops at EOF when loop=True,
    otherwise emits silence after EOF.
    """

    def __init__(self, path, loop=True):
        import audioop
        self._audioop = audioop
        self._loop = loop
        self._lock = threading.Lock()
        self._w = wave.open(path, "rb")
        self._nch = self._w.getnchannels()
        self._sw = self._w.getsampwidth()
        self._fr = self._w.getframerate()
        if self._sw not in (1, 2, 4):
            raise AcpError("INTERNAL",
                           f"unsupported wav sample width {self._sw}")

    def read_frame(self):
        with self._lock:
            raw = self._w.readframes(FRAME_SAMPLES)
            if len(raw) == 0:
                if self._loop:
                    self._w.rewind()
                    raw = self._w.readframes(FRAME_SAMPLES)
                if len(raw) == 0:
                    return b"\x00" * FRAME_BYTES
            op = self._audioop
            if self._sw == 1:
                # 8-bit wav is unsigned; audioop wants signed.
                raw = op.lin2lin(op.bias(raw, 1, -128), 1, 2)
            elif self._sw == 4:
                raw = op.lin2lin(raw, 4, 2)
            if self._nch > 1:
                raw = op.tomono(raw, 2, 0.5, 0.5)
            if self._fr != SAMPLE_RATE:
                raw, _ = op.ratecv(raw, 2, 1, self._fr, SAMPLE_RATE, None)
            if len(raw) < FRAME_BYTES:
                raw += b"\x00" * (FRAME_BYTES - len(raw))
            return raw[:FRAME_BYTES]

    def close(self):
        with self._lock:
            try:
                self._w.close()
            except Exception:
                pass


class WavRecorderSink(AudioSink):
    """Records received call audio to a .wav file (16-bit mono 8 kHz)."""

    def __init__(self, path):
        self._lock = threading.Lock()
        self._w = wave.open(path, "wb")
        self._w.setnchannels(1)
        self._w.setsampwidth(2)
        self._w.setframerate(SAMPLE_RATE)
        self.frames = 0

    def write_frame(self, frame):
        if len(frame) != FRAME_BYTES:
            frame = (frame + b"\x00" * FRAME_BYTES)[:FRAME_BYTES]
        with self._lock:
            if self._w is not None:
                self._w.writeframes(frame)
                self.frames += 1

    def close(self):
        with self._lock:
            if self._w is not None:
                try:
                    self._w.close()
                except Exception:
                    pass
                self._w = None


# ------------------------------------------------------------------ calls
def _new_call_id():
    return "call-" + b62encode(random_bytes(12))


class VoiceCalls:
    """Voice calling bound to a Connector."""

    def __init__(self, connector):
        self._c = connector
        self._lock = threading.RLock()
        self._calls = {}  # call_id -> live call dict
        self._incoming_cbs = []
        self._ended_cbs = []
        self.auto_accept = False
        self.default_source = SilenceSource()
        self.default_sink = NullSink()
        store = connector.store
        with store._lock:
            store._db.executescript(_SCHEMA)
            store._db.commit()
        c = connector
        c.register_kind_handler(CALL_INVITE, self._on_invite)
        c.register_kind_handler(CALL_ACCEPT, self._on_accept)
        c.register_kind_handler(CALL_REJECT, self._on_reject)
        c.register_kind_handler(CALL_HANGUP, self._on_hangup)
        c.register_kind_handler(CALL_KEEPALIVE, self._on_keepalive)

    # ------------------------------------------------------------ callbacks
    def on_incoming_call(self, cb):
        """cb(info dict) for a ringing call; accept/reject via the API.

        info: {call_id, peer_id, codec}. Ignored when auto_accept is on.
        """
        self._incoming_cbs.append(cb)

    def on_call_ended(self, cb):
        """cb(call_id, reason)."""
        self._ended_cbs.append(cb)

    # ------------------------------------------------------------ API: place
    def call_peer(self, peer_pid, source=None, sink=None,
                  timeout=ACCEPT_TIMEOUT_S):
        """Invite a peer; blocks until accept / reject / timeout.

        Returns call_id on accept. Raises AcpError on reject or timeout.
        """
        c = self._c
        c._require_peer(peer_pid)
        call_id = _new_call_id()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        local_port = sock.getsockname()[1]
        ssrc = int.from_bytes(random_bytes(4), "big")
        ev = threading.Event()
        call = {
            "call_id": call_id, "peer_id": peer_pid,
            "direction": "outgoing", "state": "calling",
            "codec": CODEC, "sock": sock, "local_port": local_port,
            "remote_port": None, "local_ssrc": ssrc, "remote_ssrc": None,
            "peer_ip": None, "source": source or self.default_source,
            "sink": sink or self.default_sink,
            "stop": threading.Event(), "event": ev, "result": {},
            "threads": [], "last_media": time.time(),
            "last_signal": time.time(),
        }
        with self._lock:
            self._calls[call_id] = call
        self._record(call)
        self._start_receiver(call)
        try:
            c._send_e2e(CALL_INVITE, peer_pid, {
                "call_id": call_id, "codec": CODEC,
                "udp_port": local_port, "ssrc": ssrc})
        except AcpError:
            self._cleanup(call_id, "invite_failed")
            raise
        c.audit.log("call.invited", actor=peer_pid, target=call_id,
                    result="ok", details={"codec": CODEC})
        c._metric("call_placed")
        if not ev.wait(timeout):
            self._cleanup(call_id, "no_answer")
            raise AcpError("INTERNAL",
                           f"call {call_id} not answered within {timeout}s")
        if call["result"].get("rejected"):
            raise AcpError("INTERNAL",
                           "call rejected: %s"
                           % call["result"].get("reason", ""))
        return call_id

    # ------------------------------------------------------------ API: answer
    def accept_call(self, call_id, source=None, sink=None):
        """Accept a ringing incoming call."""
        c = self._c
        with self._lock:
            call = self._calls.get(call_id)
            if call is None or call["state"] != "ringing":
                raise AcpError("INTERNAL", "no such ringing call")
            call["source"] = source or self.default_source
            call["sink"] = sink or self.default_sink
            call["state"] = "active"
            self._set_state(call_id, "active")
        try:
            c._send_e2e(CALL_ACCEPT, call["peer_id"], {
                "call_id": call_id, "udp_port": call["local_port"],
                "ssrc": call["local_ssrc"]})
        except AcpError as e:
            self._cleanup(call_id, "accept_failed")
            raise AcpError("INTERNAL", f"accept send failed: {e.code}")
        self._start_sender(call)
        c.audit.log("call.accepted", actor=call["peer_id"],
                    target=call_id, result="ok", details={})

    def reject_call(self, call_id, reason="declined"):
        """Reject a ringing incoming call."""
        c = self._c
        with self._lock:
            call = self._calls.get(call_id)
            if call is None or call["state"] != "ringing":
                raise AcpError("INTERNAL", "no such ringing call")
        try:
            c._send_e2e(CALL_REJECT, call["peer_id"],
                        {"call_id": call_id, "reason": reason})
        except AcpError:
            pass
        self._cleanup(call_id, "rejected")
        c.audit.log("call.rejected", actor=call["peer_id"],
                    target=call_id, result="ok",
                    details={"reason": reason})

    # ------------------------------------------------------------ API: hangup
    def hangup_call(self, call_id):
        """Hang up an active call (sends call_hangup, frees the socket)."""
        c = self._c
        with self._lock:
            call = self._calls.get(call_id)
        if call is None:
            return
        try:
            c._send_e2e(CALL_HANGUP, call["peer_id"],
                        {"call_id": call_id})
        except AcpError:
            pass
        self._cleanup(call_id, "hangup")
        c.audit.log("call.hangup", actor=call["peer_id"],
                    target=call_id, result="ok", details={})

    # ------------------------------------------------------------ API: query
    def get_call(self, call_id):
        """Live call info dict, or None once cleaned up."""
        with self._lock:
            call = self._calls.get(call_id)
            if call is None:
                return None
            return {k: call[k] for k in (
                "call_id", "peer_id", "direction", "state", "codec",
                "local_port", "remote_port", "local_ssrc", "remote_ssrc")}

    def list_calls(self, include_ended=False):
        q = "SELECT * FROM calls"
        if not include_ended:
            q += " WHERE state NOT IN ('ended','rejected')"
        q += " ORDER BY started_at DESC"
        return [dict(r) for r in
                self._c.store._db.execute(q).fetchall()]

    # ------------------------------------------------------------ signaling in
    def _peer_ip(self, conn):
        try:
            return conn.peer_addr[0] if conn.peer_addr else "127.0.0.1"
        except Exception:
            return "127.0.0.1"

    def _udp_connect(self, call):
        """Connect the UDP socket to the peer's address.

        Connected UDP (connect + send/recv) is used instead of
        sendto/recvfrom: some sandboxed environments block unconnected
        UDP sendto() at the seccomp layer while connected send() is
        allowed, and one-peer-per-call is exactly the connected-UDP
        semantic. The kernel then also drops packets not from the peer.
        """
        call["sock"].connect((call["peer_ip"], call["remote_port"]))
        call["udp_connected"] = True

    def _on_invite(self, conn, env, payload):
        c = self._c
        peer = env["from"]
        call_id = payload["call_id"]
        if payload.get("codec") != CODEC:
            try:
                c._send_e2e(CALL_REJECT, peer,
                            {"call_id": call_id,
                             "reason": "unsupported codec"})
            except AcpError:
                pass
            c.audit.log("call.invite_bad_codec", actor=peer,
                        target=call_id, result="denied",
                        details={"codec": payload.get("codec")})
            return
        # Parse BEFORE creating the socket: a malformed udp_port/ssrc
        # must not leak a bound socket (the ValueError used to escape
        # from inside the dict literal below, after bind()).
        try:
            remote_port = int(payload["udp_port"])
            remote_ssrc = int(payload["ssrc"])
        except (ValueError, TypeError):
            raise AcpError("BAD_ENVELOPE", "call_invite ports not integers")
        if not 1 <= remote_port <= 65535:
            raise AcpError("BAD_ENVELOPE", "call_invite bad udp_port")
        with self._lock:
            if call_id in self._calls:
                return  # duplicate invite; ignore
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(("127.0.0.1", 0))
            except OSError:
                sock.close()
                return
            local_port = sock.getsockname()[1]
            ssrc = int.from_bytes(random_bytes(4), "big")
            call = {
                "call_id": call_id, "peer_id": peer,
                "direction": "incoming", "state": "ringing",
                "codec": CODEC, "sock": sock, "local_port": local_port,
                "remote_port": remote_port,
                "local_ssrc": ssrc,
                "remote_ssrc": remote_ssrc,
                "peer_ip": self._peer_ip(conn),
                "source": self.default_source, "sink": self.default_sink,
                "stop": threading.Event(), "event": threading.Event(),
                "result": {}, "threads": [],
                "last_media": time.time(), "last_signal": time.time(),
            }
            self._calls[call_id] = call
        try:
            self._udp_connect(call)
        except OSError as e:
            with self._lock:
                self._calls.pop(call_id, None)
            try:
                sock.close()
            except OSError:
                pass
            c.audit.log("call.udp_failed", actor=peer, target=call_id,
                        result="failed", details={"error": str(e)})
            return
        self._record(call)
        self._start_receiver(call)
        c.audit.log("call.ringing", actor=peer, target=call_id,
                    result="ok", details={})
        if self.auto_accept:
            try:
                self.accept_call(call_id)
            except AcpError as e:
                c.audit.log("call.auto_accept_failed", actor=peer,
                            target=call_id, result="failed",
                            details={"error": e.code})
        else:
            info = {"call_id": call_id, "peer_id": peer, "codec": CODEC}
            for cb in list(self._incoming_cbs):
                try:
                    cb(info)
                except Exception as e:
                    c.audit.log("call.callback_error", actor=peer,
                                target=call_id, result="failed",
                                details={"error": str(e)})

    def _on_accept(self, conn, env, payload):
        c = self._c
        peer = env["from"]
        call_id = payload["call_id"]
        with self._lock:
            call = self._calls.get(call_id)
            if call is None or call["peer_id"] != peer:
                c.audit.log("call.stray_accept", actor=peer,
                            target=call_id, result="denied", details={})
                return
            if call["state"] != "calling":
                return
            try:
                remote_port = int(payload["udp_port"])
                remote_ssrc = int(payload["ssrc"])
            except (ValueError, TypeError):
                raise AcpError("BAD_ENVELOPE",
                               "call_accept ports not integers")
            call["remote_port"] = remote_port
            call["remote_ssrc"] = remote_ssrc
            call["peer_ip"] = self._peer_ip(conn)
            call["state"] = "active"
            call["last_signal"] = time.time()
            self._set_state(call_id, "active")
        try:
            self._udp_connect(call)
        except OSError as e:
            c.audit.log("call.udp_failed", actor=peer, target=call_id,
                        result="failed", details={"error": str(e)})
            self._cleanup(call_id, "udp_unreachable")
            return
        self._start_sender(call)
        c.audit.log("call.active", actor=peer, target=call_id,
                    result="ok", details={})
        call["event"].set()

    def _on_reject(self, conn, env, payload):
        c = self._c
        peer = env["from"]
        call_id = payload["call_id"]
        with self._lock:
            call = self._calls.get(call_id)
            if call is None or call["peer_id"] != peer:
                return
            call["result"] = {"rejected": True,
                              "reason": payload.get("reason", "")}
        # Tear down first, wake call_peer after: when call_peer raises
        # "rejected", the call is fully closed and the record final.
        try:
            self._cleanup(call_id, "rejected")
        finally:
            call["event"].set()
        c.audit.log("call.rejected_remote", actor=peer, target=call_id,
                    result="ok",
                    details={"reason": payload.get("reason", "")})

    def _on_hangup(self, conn, env, payload):
        c = self._c
        peer = env["from"]
        call_id = payload["call_id"]
        with self._lock:
            call = self._calls.get(call_id)
            if call is None or call["peer_id"] != peer:
                return
        self._cleanup(call_id, "remote_hangup")
        c.audit.log("call.hangup_remote", actor=peer, target=call_id,
                    result="ok", details={})

    def _on_keepalive(self, conn, env, payload):
        with self._lock:
            call = self._calls.get(payload["call_id"])
            if call is not None and call["peer_id"] == env["from"]:
                call["last_signal"] = time.time()

    # ------------------------------------------------------------ media
    def _start_receiver(self, call):
        t = threading.Thread(target=self._recv_loop, args=(call,),
                             daemon=True,
                             name="acp-voice-rx-%s" % call["call_id"][:8])
        call["threads"].append(t)
        t.start()

    def _start_sender(self, call):
        with self._lock:
            if call.get("sender_started"):
                return
            call["sender_started"] = True
        t = threading.Thread(target=self._send_loop, args=(call,),
                             daemon=True,
                             name="acp-voice-tx-%s" % call["call_id"][:8])
        call["threads"].append(t)
        t.start()

    def _send_loop(self, call):
        c = self._c
        seq = 0
        ts = 0
        next_t = time.monotonic()
        ka_next = next_t + KEEPALIVE_S
        while not call["stop"].is_set():
            try:
                frame = call["source"].read_frame()
            except Exception:
                frame = b"\x00" * FRAME_BYTES
            if len(frame) != FRAME_BYTES:
                frame = (frame + b"\x00" * FRAME_BYTES)[:FRAME_BYTES]
            pkt = (RTP_HEADER.pack(RTP_VERSION, 0, seq & 0xFFFF,
                                   ts & 0xFFFFFFFF, call["local_ssrc"])
                   + frame)
            try:
                call["sock"].send(pkt)  # connected UDP (see _udp_connect)
            except OSError:
                break
            seq += 1
            ts += FRAME_SAMPLES
            now = time.monotonic()
            if now >= ka_next:
                ka_next = now + KEEPALIVE_S
                try:
                    c._send_plain(CALL_KEEPALIVE, call["peer_id"],
                                  {"call_id": call["call_id"],
                                   "ts": int(time.time())})
                except AcpError:
                    pass
            next_t += FRAME_SAMPLES / SAMPLE_RATE
            delay = next_t - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_t = time.monotonic()  # don't spiral when late

    def _handle_rtp(self, call, data):
        if len(data) != 12 + FRAME_BYTES:
            return None
        try:
            ver, _flags, seq, _ts, ssrc = RTP_HEADER.unpack(data[:12])
        except struct.error:
            return None
        if ver != RTP_VERSION:
            return None
        if call.get("remote_ssrc") is not None and ssrc != call["remote_ssrc"]:
            return None  # not from our peer's current SSRC
        return seq, data[12:]

    def _recv_loop(self, call):
        sock = call["sock"]
        sock.settimeout(0.02)
        buf = {}           # seq(u16) -> payload bytes
        expected = None    # next u16 seq to play
        missing_since = None
        next_tick = time.monotonic()
        while not call["stop"].is_set():
            try:
                data, _addr = sock.recvfrom(4096)
                parsed = self._handle_rtp(call, data)
                if parsed is not None:
                    seq, payload = parsed
                    key = seq & 0xFFFF
                    if expected is None:
                        expected = seq
                    # drop late/duplicate: behind the playout cursor
                    # (wrap-aware u16 compare)
                    behind = ((expected - seq) & 0xFFFF) < 0x8000 \
                        and key != (expected & 0xFFFF)
                    if not behind and key not in buf and len(buf) < 128:
                        buf[key] = payload
                    call["last_media"] = time.time()
            except socket.timeout:
                pass
            except OSError:
                break
            now = time.monotonic()
            if now >= next_tick:
                next_tick = now + FRAME_SAMPLES / SAMPLE_RATE
                expected, missing_since = self._playout(
                    call, buf, expected, missing_since, now)
            if time.time() - max(call["last_media"],
                                 call["last_signal"]) > CALL_TIMEOUT_S:
                self._c.audit.log("call.timeout", actor=call["peer_id"],
                                  target=call["call_id"], result="failed",
                                  details={})
                self._cleanup(call["call_id"], "timeout")
                break

    def _playout(self, call, buf, expected, missing_since, now):
        if expected is None:
            if not buf:
                return None, None
            expected = min(buf)  # start at the lowest buffered seq
        key = expected & 0xFFFF
        if key in buf:
            call["sink"].write_frame(buf.pop(key))
            return expected + 1, None
        if missing_since is None:
            return expected, now  # start the 200 ms grace window
        if now - missing_since >= JITTER_WINDOW_S:
            # gap persists: conceal with silence, advance the cursor
            call["sink"].write_frame(b"\x00" * FRAME_BYTES)
            return expected + 1, None
        return expected, missing_since

    # ------------------------------------------------------------ lifecycle
    def _record(self, call):
        with self._c.store._lock:
            self._c.store._db.execute(
                "INSERT OR REPLACE INTO calls(call_id, peer_id, direction,"
                " state, codec, local_port, remote_port, local_ssrc,"
                " remote_ssrc, started_at, ended_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (call["call_id"], call["peer_id"], call["direction"],
                 call["state"], call["codec"], call["local_port"],
                 call["remote_port"], call["local_ssrc"],
                 call["remote_ssrc"], int(time.time()), None))
            self._c.store._db.commit()

    def _set_state(self, call_id, state):
        with self._c.store._lock:
            if state in ("ended", "rejected"):
                self._c.store._db.execute(
                    "UPDATE calls SET state=?, ended_at=? WHERE call_id=?",
                    (state, int(time.time()), call_id))
            else:
                self._c.store._db.execute(
                    "UPDATE calls SET state=? WHERE call_id=?",
                    (state, call_id))
            self._c.store._db.commit()

    def _cleanup(self, call_id, reason):
        with self._lock:
            call = self._calls.pop(call_id, None)
        if call is None:
            return
        call["stop"].set()
        try:
            call["sock"].close()
        except OSError:
            pass
        me = threading.current_thread()
        for t in call["threads"]:
            if t is not me and t.is_alive():
                t.join(timeout=2)
        final = "rejected" if reason == "rejected" else "ended"
        call["state"] = final
        self._set_state(call_id, final)
        for cb in list(self._ended_cbs):
            try:
                cb(call_id, reason)
            except Exception:
                pass
