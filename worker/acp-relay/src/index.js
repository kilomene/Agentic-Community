// acp-relay Worker entry (modules format).
//
// Routes:
//   GET /     -> JSON status { ok, service, version }
//   GET /acp  -> WebSocket upgrade, forwarded to the AcpRelay Durable
//                Object singleton (idFromName "acp-relay-v1")
//   anything else -> 404

import { AcpRelay } from "./relay-do.js";

const VERSION = "1.0.0";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/") {
      return Response.json({ ok: true, service: "acp-relay", version: VERSION });
    }
    if (req.method === "GET" && url.pathname === "/acp") {
      const upgrade = req.headers.get("Upgrade");
      if (!upgrade || upgrade.toLowerCase() !== "websocket") {
        return new Response("websocket upgrade required", { status: 426 });
      }
      const stub = env.ACP_RELAY.get(env.ACP_RELAY.idFromName("acp-relay-v1"));
      return stub.fetch(req);
    }
    return new Response("not found", { status: 404 });
  },
};

// Re-exported so the Durable Object binding resolves against the entry
// module (wrangler / the API metadata reference class_name "AcpRelay").
export { AcpRelay };
