// office-tunnel: single-file worker (dashboard quick-edit friendly).
import { DurableObject } from "cloudflare:workers";

export class TunnelDO extends DurableObject {
  constructor(state, env) {
    super(state, env);
    this.client = null;      // accepted server-side WebSocket
    this.pending = new Map();// id -> { resolve, reject, timer }
    this.nextId = 1;
  }

  async fetch(req) {
    const url = new URL(req.url);

    // Internal state probe (used by the "/" status route).
    if (url.pathname === "/state") {
      return Response.json({ client: this.client !== null });
    }

    // Tunnel client WebSocket.
    if (url.pathname === "/tunnel") {
      const pair = new WebSocketPair();
      const [wsClient, wsServer] = Object.values(pair);
      wsServer.accept();
      if (this.client) {
        try { this.client.close(4000, "replaced by new client"); } catch (_) {}
      }
      this.client = wsServer;
      // Fail everything still waiting on the old socket.
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        this.pending.delete(id);
        p.reject(new Error("tunnel client reconnected"));
      }
      wsServer.addEventListener("message", (ev) => this.onClientMessage(ev.data));
      const drop = () => { if (this.client === wsServer) this.client = null; };
      wsServer.addEventListener("close", drop);
      wsServer.addEventListener("error", drop);
      return new Response(null, { status: 101, webSocket: wsClient });
    }

    // Browser request -> forward over the tunnel.
    if (!this.client) {
      return new Response("tunnel client offline", { status: 502 });
    }
    const id = this.nextId++;
    let bodyB64 = null;
    if (req.body) {
      const buf = await req.arrayBuffer();
      if (buf.byteLength > MAX_BODY) {
        return new Response("request body too large", { status: 413 });
      }
      if (buf.byteLength > 0) bodyB64 = b64encode(buf);
    }
    const headers = {};
    req.headers.forEach((v, k) => { headers[k] = v; });
    delete headers["host"]; // client sets Host for the local origin

    const msg = JSON.stringify({ id, method: req.method, path: url.pathname + url.search, headers, body: bodyB64 });

    const reply = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("tunnel request timeout"));
      }, REQ_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.client.send(msg);
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      }
    }).catch((e) => ({ _error: String(e && e.message || e) }));

    if (reply._error) {
      const code = /timeout/.test(reply._error) ? 504 : 502;
      return new Response("tunnel error: " + reply._error, { status: code });
    }
    let body = null;
    if (reply.body) {
      if (reply.body.length > MAX_BODY * 1.4) {
        return new Response("response body too large", { status: 502 });
      }
      body = b64decode(reply.body);
    }
    // Strip hop-by-hop headers the edge manages itself.
    const rh = new Headers();
    for (const [k, v] of Object.entries(reply.headers || {})) {
      if (!/^(connection|transfer-encoding|keep-alive)$/i.test(k)) rh.set(k, v);
    }
    return new Response(body, { status: reply.status || 200, headers: rh });
  }

  onClientMessage(data) {
    let m;
    try { m = JSON.parse(data); } catch (_) { return; }
    if (!m || typeof m.id !== "number") return;
    const p = this.pending.get(m.id);
    if (!p) return;
    this.pending.delete(m.id);
    clearTimeout(p.timer);
    p.resolve(m);
  }
}

// ---------------------------------------------------------------- entry

// Tunnel protocol limits.
const REQ_TIMEOUT_MS = 25_000;          // 25s per proxied request
const MAX_BODY = 8 * 1024 * 1024;       // 8 MiB body cap each way

function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

function b64decode(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes.buffer;
}

// office-tunnel Worker entry (modules format).
//
// A tiny reverse-tunnel for the office dashboard, built because the
// sandbox blocks all UDP (seccomp EPERM on sendto/sendmsg), which makes
// cloudflared's QUIC-only edge connections impossible here. Instead the
// sandbox holds one outbound WebSocket (which the sandbox DOES allow)
// to this Worker, and browser traffic for office.novamail.store is
// proxied over it to the local office server.
//
// Routes:
//   GET /                  -> JSON status { ok, service, version, client }
//   GET /tunnel?secret=... -> WebSocket upgrade from the tunnel client
//                            (secret checked against TUNNEL_SECRET env).
//                            Forwarded to the TunnelDO singleton.
//   anything else           -> proxied to the tunnel client via the
//                            TunnelDO singleton (idFromName "office-tunnel-v1").
//                            502 when no client is connected.
//
// Cloudflare Access still gates office.novamail.store at the edge, so
// the owner-only policy applies before traffic ever reaches this Worker.

const VERSION = "1.0.0";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === "GET" && url.pathname === "/_tunnel/status") {
      const stub = env.TUNNEL_DO.get(env.TUNNEL_DO.idFromName("office-tunnel-v1"));
      const state = await stub.fetch(new Request("https://do/state")).then(r => r.json()).catch(() => ({ client: false }));
      return Response.json({ ok: true, service: "office-tunnel", version: VERSION, client_connected: !!state.client });
    }

    if (url.pathname === "/tunnel") {
      const upgrade = req.headers.get("Upgrade");
      if (!upgrade || upgrade.toLowerCase() !== "websocket") {
        return new Response("websocket upgrade required", { status: 426 });
      }
      if (url.searchParams.get("secret") !== env.TUNNEL_SECRET) {
        return new Response("forbidden", { status: 403 });
      }
      const stub = env.TUNNEL_DO.get(env.TUNNEL_DO.idFromName("office-tunnel-v1"));
      return stub.fetch(req);
    }

    // Browser traffic -> tunnel.
    const stub = env.TUNNEL_DO.get(env.TUNNEL_DO.idFromName("office-tunnel-v1"));
    return stub.fetch(req);
  },
};

