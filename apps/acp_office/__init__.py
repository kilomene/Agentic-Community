"""acp_office: read-only fleet "office" dashboard.

A stdlib-only HTTP server (same convention as apps/acp_dashboard) that
presents the fleet's group chat, task board, work ledger, and presence
as one dashboard page + JSON API. It NEVER writes to any source DB —
every source is opened read-only (``mode=ro`` + ``PRAGMA query_only``).

Binds 127.0.0.1 by default. Public exposure is via a cloudflared tunnel
guarded by Cloudflare Access (see docs/OFFICE.md). An API token is
printed at startup (or passed with --token); /api/* requires it.
"""
