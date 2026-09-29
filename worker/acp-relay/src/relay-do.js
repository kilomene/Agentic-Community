// AcpRelay — Cloudflare Durable Object: ACP 1.0 relay over WebSocket.
//
// Ports the BEHAVIOR of services/acp_relay/relay.py (the TCP relay) to the
// Workers runtime. Wire convention: every WebSocket BINARY message carries
// exactly one TCP-style frame: 4-byte big-endian length + JSON bytes.
// Control frames are length-prefixed JSON too (never ACP envelopes).
// Text WebSocket messages are ignored.
//
// v1 scope: client connections + an always-on mailbox. Federation
// (relay_link) is refused. The relay routes by envelope metadata only
// ("from", "to", "kind", "ts", "nonce"); it holds no E2E keys and never
// sees plaintext — "box" ciphertext stays opaque. A compromised relay
// learns who talks to whom, when, and how much — never message content.

import { DurableObject } from "cloudflare:workers";

const MAX_FRAME = 4 * 1024 * 1024; // protocol §4: 4 MiB frame cap
const FRESHNESS_S = 300; // hello timestamp window, seconds
const HELLO_TIMEOUT_MS = 15_000; // time allowed to complete the handshake
const MBX_MAX_MSGS = 200; // per-recipient mailbox caps (v1)
const MBX_MAX_BYTES = 8 * 1024 * 1024;
const MBX_TTL_S = 7 * 86400;
const CHUNK = 100 * 1024; // DO storage values cap at 128 KiB; stay under it

const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Pairing-code directory (short rendezvous codes so nobody types a peer id).
//   {pair_code_claim:   {code: "ABC123", ttl: 600, req}} -> {pair_code_claimed: {code, req}}
//                                                        or {pair_code_error: {code, req, error}}
//   {pair_code_release: {code, req}}                     -> {pair_code_released: {code, req}}
//   {pair_code_lookup:  {code, req}}                     -> {pair_code_result: {code, req, pid}}
//                                                        or {pair_code_result: {code, req, pid: null, error}}
// Codes are a RENDEZVOUS, not authentication: 32^6 space (~30 bits),
// per-connection lookup rate limiting, TTL-bounded. The pairing handshake
// still requires the responder's on-screen confirm code + key verification.
const PAIR_CODE_RE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/;
const PAIR_CODE_TTL_DEFAULT_S = 600;
const PAIR_CODE_TTL_MIN_S = 60;
const PAIR_CODE_TTL_MAX_S = 3600;
const PAIR_LOOKUP_PER_MIN = 30;
const PAIR_LOOKUP_WINDOW_MS = 60_000;

// ---------------------------------------------------------------- helpers

// b62decode mirroring acp_proto.b62decode: minimal big-endian bytes,
// minimum 1 byte (n == 0 -> b"\x00"). Throws on any non-alphabet char.
function b62decode(s) {
  let n = 0n;
  for (let i = 0; i < s.length; i++) {
    const d = B62.indexOf(s[i]);
    if (d < 0) throw new Error("bad base62 character");
    n = n * 62n + BigInt(d);
  }
  let hex = n.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// canonical(obj): deterministic JSON like acp_proto.canonical — keys sorted
// recursively (codepoint order), separators "," and ":", UTF-8. Hello
// payloads are ASCII-only, so this is byte-exact against the Python side.
function canonicalJson(v) {
  if (v === null || v === undefined) return "null";
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  switch (typeof v) {
    case "string":
      return JSON.stringify(v);
    case "number":
      if (!Number.isFinite(v)) throw new Error("non-finite number");
      return JSON.stringify(v);
    case "boolean":
      return v ? "true" : "false";
    case "object": {
      const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      return (
        "{" +
        keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") +
        "}"
      );
    }
    default:
      throw new Error("unencodable value in canonical JSON");
  }
}

// Parse one wire frame from a binary WS message. Returns
// { len, payload, raw } or null when malformed/oversize.
function parseFrame(buf) {
  if (!(buf instanceof ArrayBuffer) || buf.byteLength < 6) return null;
  const len = new DataView(buf).getUint32(0, false);
  if (len > MAX_FRAME) return null;
  if (4 + len !== buf.byteLength) return null;
  return { len, payload: new Uint8Array(buf, 4, len), raw: buf };
}

// Structural check mirroring relay.py _looks_like_envelope: plausibly an
// ACP envelope frame (as opposed to a control frame). Never throws.
function looksLikeEnvelope(o) {
  return (
    !!o &&
    typeof o === "object" &&
    !Array.isArray(o) &&
    typeof o.kind === "string" &&
    typeof o.from === "string" &&
    typeof o.to === "string" &&
    Number.isInteger(o.ts) &&
    typeof o.nonce === "string" &&
    typeof o.sig === "string" &&
    ("payload" in o) !== ("box" in o)
  );
}

// Verify a hello object. Returns the pid string; throws on any problem.
// Mirrors relay.py verify_hello: pid IS the Ed25519 verify key.
async function verifyHello(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) {
    throw new Error("missing hello object");
  }
  const pid = h.pid;
  const ts = h.ts;
  const sigS = h.sig;
  if (typeof pid !== "string" || !pid) throw new Error("bad pid");
  if (!Number.isInteger(ts)) throw new Error("bad ts");
  if (typeof sigS !== "string" || !sigS) throw new Error("bad sig");
  const nowS = Math.floor(Date.now() / 1000);
  if (Math.abs(nowS - ts) > FRESHNESS_S) throw new Error("stale ts");
  let vkey;
  let sig;
  try {
    vkey = b62decode(pid);
    sig = b62decode(sigS);
  } catch {
    throw new Error("bad base62 in pid/sig");
  }
  if (vkey.length > 32 || sig.length > 64) throw new Error("pid/sig too long");
  const vkey32 = new Uint8Array(32);
  vkey32.set(vkey, 32 - vkey.length); // left-pad with zero bytes
  const sig64 = new Uint8Array(64);
  sig64.set(sig, 64 - sig.length);
  const msg = new TextEncoder().encode(canonicalJson({ pid, ts }));
  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      vkey32,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig64, msg);
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("bad hello signature");
  return pid;
}

// ------------------------------------------------------------------ class

export class AcpRelay extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.peers = new Map(); // pid (string) -> accepted server WebSocket
    this.draining = new Set(); // pids with a mailbox drain in flight
    this.nextId = 1; // persisted mailbox id counter
    this.queues = new Map(); // pid -> { entries: [{id,ts,size,n}], bytes }
    this.codes = new Map(); // pair code -> { pid, expiresAt, ws }
    this.lookupHits = new Map(); // ws -> [timestamp ms] (lookup rate limit)
    // No fetch/message is processed until persisted state is loaded.
    ctx.blockConcurrencyWhile(() => this.#load());
  }

  async #load() {
    const s = this.ctx.storage;
    const nid = await s.get("mbx:nextid");
    if (Number.isInteger(nid) && nid >= 1) this.nextId = nid;
    const qkeys = await s.list({ prefix: "mbx:q:" });
    for (const [k, v] of qkeys) {
      if (!Array.isArray(v)) continue;
      const pid = k.slice("mbx:q:".length);
      const entries = v.filter(
        (e) => e && Number.isInteger(e.id) && Number.isInteger(e.size) && e.size >= 0
      );
      this.queues.set(pid, {
        entries,
        bytes: entries.reduce((a, e) => a + e.size, 0),
      });
    }
  }

  // -- websocket entry ------------------------------------------------

  async fetch(req) {
    const up = req.headers.get("Upgrade");
    if (!up || up.toLowerCase() !== "websocket") {
      return new Response("websocket upgrade required", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    // Pin binary delivery to ArrayBuffer regardless of the
    // websocket_standard_binary_type compatibility flag (must be set
    // before accept(); the default flips to "blob" on newer dates).
    server.binaryType = "arraybuffer";
    server.accept();
    const conn = { ws: server, pid: null, authed: false, tail: null };
    const helloTimer = setTimeout(() => {
      if (!conn.authed) {
        try {
          server.close(4401, "hello timeout");
        } catch {
          /* already gone */
        }
      }
    }, HELLO_TIMEOUT_MS);
    // Serialize per-connection handling: the TCP relay processes one
    // frame at a time per socket; async WS handlers must not interleave.
    server.addEventListener("message", (ev) => {
      const run = () =>
        this.#onMessage(conn, ev, helloTimer).catch(() => {
          try {
            server.close(1011);
          } catch {
            /* already gone */
          }
        });
      conn.tail = (conn.tail || Promise.resolve()).then(run, run);
    });
    server.addEventListener("close", () => this.#onClose(conn, helloTimer));
    server.addEventListener("error", () => this.#onClose(conn, helloTimer));
    return new Response(null, { status: 101, webSocket: client });
  }

  #onClose(conn, helloTimer) {
    if (helloTimer) clearTimeout(helloTimer);
    this.draining.delete(conn.pid);
    if (conn.pid && this.peers.get(conn.pid) === conn.ws) {
      this.peers.delete(conn.pid);
    }
    // Release this connection's pair codes so they cannot be squatted.
    for (const [code, entry] of this.codes) {
      if (entry.ws === conn.ws) this.codes.delete(code);
    }
    this.lookupHits.delete(conn.ws);
  }

  async #onMessage(conn, ev, helloTimer) {
    const data = ev.data;
    if (typeof data === "string") return; // text frames are ignored
    const frame = parseFrame(data);
    if (!conn.authed) {
      await this.#handleHello(conn, frame, helloTimer);
      return;
    }
    if (!frame) {
      this.#sendControl(conn.ws, { relayed: false, error: "bad_frame" });
      return;
    }
    await this.#dispatch(conn, frame);
  }

  // -- handshake ------------------------------------------------------

  async #handleHello(conn, frame, helloTimer) {
    const ws = conn.ws;
    const fail = () => {
      try {
        ws.close(4401);
      } catch {
        /* already gone */
      }
    };
    if (!frame) return fail();
    let obj;
    try {
      obj = JSON.parse(new TextDecoder().decode(frame.payload));
    } catch {
      return fail();
    }
    if (!obj || typeof obj !== "object") return fail();
    // Federation is out of scope for v1: refuse relay links outright.
    if ("relay_link" in obj) {
      try {
        ws.close();
      } catch {
        /* already gone */
      }
      return;
    }
    let pid;
    try {
      pid = await verifyHello(obj.hello);
    } catch {
      return fail(); // handshake failed: close silently, no reply
    }
    if (helloTimer) clearTimeout(helloTimer);
    conn.pid = pid;
    conn.authed = true;
    // A duplicate pid registration closes the older socket first.
    const old = this.peers.get(pid);
    if (old && old !== ws) {
      try {
        old.close();
      } catch {
        /* already gone */
      }
    }
    this.peers.set(pid, ws);
    await this.#drainMailbox(conn);
  }

  // -- mailbox drain --------------------------------------------------
  // Queued frames go out FIFO before any new traffic; unacked frames stay
  // queued and are retried on the next hello.

  async #drainMailbox(conn) {
    const pid = conn.pid;
    const ws = conn.ws;
    this.draining.add(pid);
    try {
      await this.#pruneExpired(pid);
      const q = this.queues.get(pid);
      if (!q || q.entries.length === 0) return;
      const ids = q.entries.map((e) => e.id);
      this.#sendControl(ws, { mailbox_delivery: { ids } });
      for (const e of [...q.entries]) {
        const buf = await this.#readFrameBytes(e.id);
        if (!buf) {
          await this.#dropEntry(pid, e.id); // orphaned metadata: drop it
          continue;
        }
        try {
          ws.send(buf); // raw stored bytes: length prefix intact
        } catch {
          break; // socket died mid-drain; the rest stay queued
        }
      }
    } finally {
      this.draining.delete(pid);
    }
  }

  // -- dispatch -------------------------------------------------------

  async #dispatch(conn, frame) {
    let obj;
    try {
      obj = JSON.parse(new TextDecoder().decode(frame.payload));
    } catch {
      this.#sendControl(conn.ws, { relayed: false, error: "bad_frame" });
      return;
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      this.#sendControl(conn.ws, { relayed: false, error: "bad_frame" });
      return;
    }
    if ("ping" in obj) {
      this.#sendControl(conn.ws, { pong: obj.ping });
      return;
    }
    if ("mailbox_ack" in obj) {
      await this.#handleAck(conn, obj);
      return;
    }
    if ("pair_code_claim" in obj) {
      this.#handlePairCodeClaim(conn, obj);
      return;
    }
    if ("pair_code_release" in obj) {
      this.#handlePairCodeRelease(conn, obj);
      return;
    }
    if ("pair_code_lookup" in obj) {
      this.#handlePairCodeLookup(conn, obj);
      return;
    }
    if (looksLikeEnvelope(obj)) {
      const target = obj.to;
      const peer = this.peers.get(target);
      // While the target's drain is in flight, new traffic waits its
      // turn in the mailbox so redelivery always precedes it.
      if (peer && peer.readyState === 1 && !this.draining.has(target)) {
        try {
          peer.send(frame.raw); // forward the exact received bytes
          return;
        } catch {
          /* socket died: fall through to mailbox */
        }
      }
      const id = await this.#storeFrame(target, frame.raw);
      this.#sendControl(conn.ws, {
        relayed: false,
        to: target,
        error: "offline",
        queued: true,
        mailbox_id: id,
      });
      return;
    }
    if (typeof obj.to === "string") {
      this.#sendControl(conn.ws, {
        relayed: false,
        to: obj.to,
        error: "bad_frame",
      });
      return;
    }
    this.#sendControl(conn.ws, { relayed: false, error: "bad_frame" });
  }

  async #handleAck(conn, obj) {
    const ack = obj.mailbox_ack;
    const rawIds =
      ack && typeof ack === "object" && Array.isArray(ack.ids) ? ack.ids : null;
    if (!rawIds) return; // malformed: silent, like the TCP relay
    const ids = rawIds.map((v) => Number(v)).filter((v) => Number.isInteger(v));
    let n = 0;
    for (const id of ids) {
      if (await this.#dropEntry(conn.pid, id)) n++;
    }
    // Only this connection's pid queue is ever touched.
    this.#sendControl(conn.ws, { mailbox_ack: { acked: n } });
  }

  // -- pair-code directory -----------------------------------------------
  // Short rendezvous codes so agents pair without exchanging peer ids.

  #normalizePairCode(raw) {
    if (typeof raw !== "string") return null;
    const code = raw.trim().toUpperCase();
    return PAIR_CODE_RE.test(code) ? code : null;
  }

  #prunePairCode(code) {
    const entry = this.codes.get(code);
    if (entry && entry.expiresAt <= Date.now()) {
      this.codes.delete(code);
      return null;
    }
    return entry || null;
  }

  #handlePairCodeClaim(conn, obj) {
    const body = obj.pair_code_claim;
    const req = body && typeof body.req === "string" ? body.req : "";
    const code = this.#normalizePairCode(body ? body.code : null);
    if (!code) {
      this.#sendControl(conn.ws, {
        pair_code_error: { code: null, req, error: "invalid_code" },
      });
      return;
    }
    let ttl = Number(body.ttl);
    if (!Number.isFinite(ttl)) ttl = PAIR_CODE_TTL_DEFAULT_S;
    ttl = Math.max(PAIR_CODE_TTL_MIN_S, Math.min(PAIR_CODE_TTL_MAX_S, ttl));
    if (this.#prunePairCode(code)) {
      this.#sendControl(conn.ws, {
        pair_code_error: { code, req, error: "taken" },
      });
      return;
    }
    this.codes.set(code, {
      pid: conn.pid,
      expiresAt: Date.now() + ttl * 1000,
      ws: conn.ws,
    });
    this.#sendControl(conn.ws, { pair_code_claimed: { code, req } });
  }

  #handlePairCodeRelease(conn, obj) {
    const body = obj.pair_code_release;
    const req = body && typeof body.req === "string" ? body.req : "";
    const code = this.#normalizePairCode(body ? body.code : null);
    if (code) {
      const entry = this.codes.get(code);
      if (entry && entry.ws === conn.ws) this.codes.delete(code);
    }
    this.#sendControl(conn.ws, { pair_code_released: { code, req } });
  }

  #handlePairCodeLookup(conn, obj) {
    const body = obj.pair_code_lookup;
    const req = body && typeof body.req === "string" ? body.req : "";
    const code = this.#normalizePairCode(body ? body.code : null);
    const reply = (extra) =>
      this.#sendControl(conn.ws, { pair_code_result: { code, req, ...extra } });
    if (!code) return reply({ pid: null, error: "invalid_code" });
    // Rate-limit lookups per connection: codes are ~30 bits, so guessing
    // them out is infeasible, but slow the attempts down anyway.
    const now = Date.now();
    let hits = this.lookupHits.get(conn.ws) || [];
    hits = hits.filter((t) => now - t < PAIR_LOOKUP_WINDOW_MS);
    if (hits.length >= PAIR_LOOKUP_PER_MIN) {
      this.lookupHits.set(conn.ws, hits);
      return reply({ pid: null, error: "rate_limited" });
    }
    hits.push(now);
    this.lookupHits.set(conn.ws, hits);
    const entry = this.#prunePairCode(code);
    if (!entry) return reply({ pid: null, error: "not_found" });
    return reply({ pid: entry.pid });
  }

  // -- mailbox storage ------------------------------------------------
  // DO storage values cap at 128 KiB, so frame bytes are chunked:
  //   mbx:q:<pid>   -> [{id, ts, size, n}] FIFO queue metadata
  //   mbx:f:<id>    -> {n, size, ts} frame metadata
  //   mbx:f:<id>:<i> -> ArrayBuffer chunk i
  //   mbx:nextid    -> next mailbox id (integer)
  // Writes are write-through on every mutation.

  async #storeFrame(pid, raw) {
    const size = raw.byteLength;
    let q = this.queues.get(pid);
    if (!q) {
      q = { entries: [], bytes: 0 };
      this.queues.set(pid, q);
    }
    // Drop oldest first while the per-recipient caps would be exceeded.
    while (
      q.entries.length > 0 &&
      (q.entries.length >= MBX_MAX_MSGS || q.bytes + size > MBX_MAX_BYTES)
    ) {
      await this.#dropEntry(pid, q.entries[0].id);
    }
    const id = this.nextId++;
    const bytes = new Uint8Array(raw);
    const n = Math.max(1, Math.ceil(bytes.length / CHUNK));
    const ts = Math.floor(Date.now() / 1000);
    const s = this.ctx.storage;
    const ops = [];
    for (let i = 0; i < n; i++) {
      // slice() copies, so .buffer is exactly this chunk's bytes.
      const chunk = bytes.slice(i * CHUNK, (i + 1) * CHUNK);
      ops.push(s.put(`mbx:f:${id}:${i}`, chunk.buffer));
    }
    const entry = { id, ts, size, n };
    q.entries.push(entry);
    q.bytes += size;
    ops.push(s.put(`mbx:q:${pid}`, q.entries));
    ops.push(s.put(`mbx:f:${id}`, { n, size, ts }));
    ops.push(s.put("mbx:nextid", this.nextId));
    await Promise.all(ops);
    return id;
  }

  async #dropEntry(pid, id) {
    const q = this.queues.get(pid);
    if (!q) return false;
    const idx = q.entries.findIndex((e) => e.id === id);
    if (idx < 0) return false;
    const [e] = q.entries.splice(idx, 1);
    q.bytes -= e.size;
    if (q.bytes < 0) q.bytes = 0;
    const s = this.ctx.storage;
    const ops = [s.put(`mbx:q:${pid}`, q.entries), s.delete(`mbx:f:${id}`)];
    const n = Number.isInteger(e.n) ? e.n : 0;
    for (let i = 0; i < n; i++) ops.push(s.delete(`mbx:f:${id}:${i}`));
    await Promise.all(ops);
    return true;
  }

  async #readFrameBytes(id) {
    const s = this.ctx.storage;
    const meta = await s.get(`mbx:f:${id}`);
    if (!meta || !Number.isInteger(meta.n) || meta.n < 1) return null;
    const parts = [];
    for (let i = 0; i < meta.n; i++) {
      const c = await s.get(`mbx:f:${id}:${i}`);
      if (!(c instanceof ArrayBuffer)) return null;
      parts.push(new Uint8Array(c));
    }
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out.buffer;
  }

  async #pruneExpired(pid) {
    const q = this.queues.get(pid);
    if (!q || q.entries.length === 0) return;
    const cutoff = Math.floor(Date.now() / 1000) - MBX_TTL_S;
    for (const e of [...q.entries]) {
      if (e.ts <= cutoff) await this.#dropEntry(pid, e.id);
    }
  }

  // -- control frames -------------------------------------------------

  #sendControl(ws, obj) {
    try {
      const body = new TextEncoder().encode(canonicalJson(obj));
      const out = new Uint8Array(4 + body.length);
      new DataView(out.buffer).setUint32(0, body.length, false);
      out.set(body, 4);
      ws.send(out.buffer);
    } catch {
      /* best effort: the socket is probably gone */
    }
  }
}
