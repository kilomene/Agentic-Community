"""acp_marketplace: discoverable marketplace for capability-packages and
agent service listings, plus a real offer/escrow/dispute protocol.

All marketplace traffic rides ACP E2E envelopes between paired agents
(``market_*`` kinds, registered below via ``acp_proto.register_kind``)
plus a local package index file (``<home>/marketplace/index.json``).

HONEST MONEY STATEMENT: the marketplace NEVER moves real money. Escrow
holds are bookkeeping records made by a :class:`PaymentAdapter`. The
only bundled adapter is ``NullAdapter``, which records holds in SQLite
and moves NO funds. "Settlement of real funds requires a payment
adapter; none is bundled per the $0 rule." Any claim to the contrary
is a bug — see payments.py and docs/MARKETPLACE.md.

Package installs NEVER execute code: install only writes verified
files and records an audit event. Running package code is a separate,
explicit local action outside this module.
"""
import json
import os
import shutil
import threading
import time

from acp_crypto import ed25519_sign, ed25519_verify
from acp_proto import (
    AcpError, b62decode_fixed, b62encode_fixed, canonical, register_kind,
)

from .manifest import (
    build_manifest, sign_manifest, verify_manifest, verify_package_files,
    _check_path, manifest_to_json,
)
from .marketstore import MarketStore
from .payments import NullAdapter

__all__ = ["Marketplace", "NullAdapter", "MARKET_KINDS"]

# ------------------------------------------------------------------- kinds

MARKET_LIST = register_kind("market_list", e2e=True,
                            schema=("query", "capability", "cursor"))
MARKET_LISTINGS = register_kind("market_listings", e2e=True,
                                schema=("listings", "next_cursor"))
MARKET_FETCH = register_kind("market_fetch", e2e=True,
                             schema=("name",))
MARKET_PACKAGE = register_kind("market_package", e2e=True,
                               schema=("found",))
MARKET_OFFER = register_kind("market_offer", e2e=True,
                             schema=("offer_id", "listing_id", "terms", "ts"))
MARKET_OFFER_ACCEPT = register_kind("market_offer_accept", e2e=True,
                                    schema=("offer_id",))
MARKET_OFFER_DECLINE = register_kind("market_offer_decline", e2e=True,
                                     schema=("offer_id", "reason"))
MARKET_ESCROW_HOLD = register_kind("market_escrow_hold", e2e=True,
                                   schema=("offer_id", "hold_id", "adapter",
                                           "amount_cents", "currency"))
MARKET_ESCROW_RELEASE = register_kind("market_escrow_release", e2e=True,
                                      schema=("offer_id", "hold_id",
                                              "adapter", "amount_cents",
                                              "currency"))
MARKET_ESCROW_CANCEL = register_kind("market_escrow_cancel", e2e=True,
                                     schema=("offer_id", "reason",
                                             "hold_id", "adapter",
                                             "amount_cents", "currency"))
MARKET_DISPUTE_OPEN = register_kind("market_dispute_open", e2e=True,
                                    schema=("offer_id", "claim"))
MARKET_DISPUTE_RESOLVE = register_kind("market_dispute_resolve", e2e=True,
                                       schema=("offer_id", "resolution",
                                               "ts", "resolver_sig"))

MARKET_KINDS = (MARKET_LIST, MARKET_LISTINGS, MARKET_FETCH, MARKET_PACKAGE,
                MARKET_OFFER, MARKET_OFFER_ACCEPT, MARKET_OFFER_DECLINE,
                MARKET_ESCROW_HOLD, MARKET_ESCROW_RELEASE,
                MARKET_ESCROW_CANCEL, MARKET_DISPUTE_OPEN,
                MARKET_DISPUTE_RESOLVE)

_LIST_TIMEOUT = 30
_FETCH_TIMEOUT = 60
_FETCH_MAX_BYTES = 2 * 1024 * 1024  # market_package file payload cap
_PAGE_SIZE = 25

# Offer states
ST_OFFERED = "offered"
ST_ACCEPTED = "accepted"
ST_ESCROW = "escrow_held"
ST_RELEASED = "released"
ST_CANCELLED = "cancelled"
ST_DECLINED = "declined"
ST_DISPUTED = "disputed"
_TERMINAL = {ST_RELEASED, ST_CANCELLED, ST_DECLINED}


class Marketplace:
    """Marketplace bound to one Connector (one agent identity)."""

    def __init__(self, connector):
        self._c = connector
        self.home = os.path.join(connector.home, "marketplace")
        self.packages_dir = os.path.join(self.home, "packages")
        self.installed_dir = os.path.join(self.home, "installed")
        self.quarantine_dir = os.path.join(connector.home, "quarantine")
        for d in (self.home, self.packages_dir, self.installed_dir,
                  self.quarantine_dir):
            os.makedirs(d, exist_ok=True)
        self.index_path = os.path.join(self.home, "index.json")

        self.store = MarketStore(os.path.join(connector.home,
                                              "marketplace.db"))
        self._adapters = {"null": NullAdapter(self.store)}
        self._install_policy = "manual"  # manual | auto | deny
        self._install_cb = None

        self._lock = threading.Lock()
        self._waiters = {}  # key -> {"event", "payload"}

        c = connector
        c.register_kind_handler(MARKET_LIST, self._h_market_list)
        c.register_kind_handler(MARKET_LISTINGS, self._h_market_listings)
        c.register_kind_handler(MARKET_FETCH, self._h_market_fetch)
        c.register_kind_handler(MARKET_PACKAGE, self._h_market_package)
        c.register_kind_handler(MARKET_OFFER, self._h_offer)
        c.register_kind_handler(MARKET_OFFER_ACCEPT, self._h_offer_accept)
        c.register_kind_handler(MARKET_OFFER_DECLINE, self._h_offer_decline)
        c.register_kind_handler(MARKET_ESCROW_HOLD, self._h_escrow_hold)
        c.register_kind_handler(MARKET_ESCROW_RELEASE,
                                self._h_escrow_release)
        c.register_kind_handler(MARKET_ESCROW_CANCEL, self._h_escrow_cancel)
        c.register_kind_handler(MARKET_DISPUTE_OPEN, self._h_dispute_open)
        c.register_kind_handler(MARKET_DISPUTE_RESOLVE,
                                self._h_dispute_resolve)

    # ------------------------------------------------------------ adapters
    def register_adapter(self, adapter):
        self._adapters[adapter.name] = adapter

    def _pubkey(self, pid):
        """Ed25519 verify key for a peer id, self-aware: the connector's
        own peer store never contains itself."""
        if pid == self._c.peer_id:
            return self._c.identity.ed_pub
        return self._c._get_pubkey(pid)

    def get_adapter(self, name):
        try:
            return self._adapters[name]
        except KeyError:
            raise AcpError("INTERNAL", f"unknown payment adapter {name!r}")

    def set_install_policy(self, policy):
        if policy not in ("manual", "auto", "deny"):
            raise AcpError("BAD_ENVELOPE", f"bad install policy {policy!r}")
        self._install_policy = policy

    def on_install_request(self, cb):
        """cb(manifest) -> bool. Consulted when policy is 'manual'."""
        self._install_cb = cb

    # ----------------------------------------------------- waiter machinery
    def _wait_for(self, key, timeout):
        waiter = {"event": threading.Event(), "payload": None}
        with self._lock:
            self._waiters[key] = waiter
        try:
            if not waiter["event"].wait(timeout):
                raise AcpError("INTERNAL",
                               f"timeout waiting for {key[0]}")
            return waiter["payload"]
        finally:
            with self._lock:
                self._waiters.pop(key, None)

    def _fulfill(self, key, payload):
        with self._lock:
            w = self._waiters.get(key)
        if w is not None:
            w["payload"] = payload
            w["event"].set()

    def _audit(self, action, actor="local", target=None, result="ok",
               **details):
        self._c.audit.log(f"marketplace.{action}", actor=actor,
                           target=target, result=result, details=details)

    # ============================================================ PACKAGES
    def publish_package(self, source_dir, name, version, description,
                        capabilities, entry_point):
        """Build, sign, and publish a capability package from a source
        dir. Writes files + manifest.json to the local package store,
        records it in the SQLite index, and rewrites index.json."""
        unsigned = build_manifest(source_dir, name, version, description,
                                  capabilities, entry_point,
                                  self._c.peer_id)
        manifest = sign_manifest(unsigned, self._c.identity.ed_priv)
        dest = os.path.join(self.packages_dir, f"{name}-{version}")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.makedirs(dest)
        entries = []
        for root, _dirs, files in os.walk(source_dir):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, source_dir)
                safe = _check_path(rel)
                entries.append((rel, safe, full))
        entries.sort()
        for _rel, safe, full in entries:
            with open(full, "rb") as f:
                data = f.read()
            with open(os.path.join(dest, safe), "wb") as f:
                f.write(data)
        with open(os.path.join(dest, "manifest.json"), "w") as f:
            f.write(manifest_to_json(manifest))
        self.store.add_package(name, version, manifest_to_json(manifest),
                               self._c.peer_id)
        self._rewrite_index()
        self._audit("package.published", target=f"{name}-{version}",
                    capabilities=list(capabilities))
        return manifest

    def _rewrite_index(self):
        listings = self.store.list_packages(limit=100000)
        with open(self.index_path, "w") as f:
            json.dump({"packages": listings,
                       "updated_at": int(time.time())}, f, indent=2)

    def list_packages(self, query="", capability=None, cursor=0,
                      limit=_PAGE_SIZE):
        listings = self.store.list_packages(query=query,
                                            capability=capability,
                                            limit=limit + 1, offset=cursor)
        next_cursor = cursor + limit if len(listings) > limit else None
        return listings[:limit], next_cursor

    def get_package(self, name, version=None):
        """Discovery hook: return the signed manifest dict or None."""
        row = self.store.get_package(name, version)
        return row["manifest"] if row else None

    def search_packages(self, query):
        """Discovery UI hook (JSON-serializable)."""
        listings, _ = self.list_packages(query=query, limit=100)
        return listings

    # ------------------------------------------------------- peer serving
    def _h_market_list(self, conn, env, payload):
        query = payload.get("query") or ""
        capability = payload.get("capability")
        cursor = int(payload.get("cursor") or 0)
        pkgs, _ = self.list_packages(query=query, capability=capability,
                                     cursor=cursor)
        svcs = self.store.list_services(query=query, capability=capability,
                                        limit=_PAGE_SIZE, offset=cursor)
        listings = sorted(pkgs + svcs, key=lambda l: l.get("ts", 0),
                          reverse=True)[:_PAGE_SIZE]
        next_cursor = (cursor + _PAGE_SIZE
                       if len(pkgs) + len(svcs) >= _PAGE_SIZE else None)
        self._c._send_e2e(MARKET_LISTINGS, env["from"],
                          {"listings": listings,
                           "next_cursor": next_cursor})
        self._audit("list.served", actor=env["from"],
                    query=query, count=len(listings))

    def _h_market_listings(self, conn, env, payload):
        self._fulfill((MARKET_LISTINGS, env["from"]), payload)

    def request_listings(self, peer_pid, query="", capability=None,
                         cursor=0, timeout=_LIST_TIMEOUT):
        key = (MARKET_LISTINGS, peer_pid)
        waiter = {"event": threading.Event(), "payload": None}
        with self._lock:
            self._waiters[key] = waiter
        try:
            self._c._send_e2e(MARKET_LIST, peer_pid,
                              {"query": query, "capability": capability,
                               "cursor": cursor})
            if not waiter["event"].wait(timeout):
                raise AcpError("INTERNAL", "timeout waiting for"
                                          " market_listings")
            payload = waiter["payload"]
            # Cache what the peer advertises so make_offer can target a
            # listing learned remotely (verified again at fetch/install).
            for listing in payload.get("listings") or []:
                try:
                    self.store.add_known_listing(listing, peer_pid)
                except Exception:
                    pass
            return payload
        finally:
            with self._lock:
                self._waiters.pop(key, None)

    def _h_market_fetch(self, conn, env, payload):
        name = payload.get("name")
        version = payload.get("version")
        row = self.store.get_package(name, version)
        if row is None:
            self._c._send_e2e(MARKET_PACKAGE, env["from"],
                              {"found": False, "name": name,
                               "error": "package not found"})
            return
        manifest = row["manifest"]
        pkg_dir = os.path.join(self.packages_dir,
                               f"{manifest['name']}-{manifest['version']}")
        files = []
        total = 0
        for entry in manifest["files"]:
            safe = _check_path(entry["path"])
            with open(os.path.join(pkg_dir, safe), "rb") as f:
                data = f.read()
            total += len(data)
            if total > _FETCH_MAX_BYTES:
                self._c._send_e2e(
                    MARKET_PACKAGE, env["from"],
                    {"found": False, "name": name,
                     "error": "package_too_large"})
                return
            files.append({"path": entry["path"], "sha256": entry["sha256"],
                          "content": b62encode_fixed(data)})
        self._c._send_e2e(MARKET_PACKAGE, env["from"],
                          {"found": True, "manifest": manifest,
                           "files": files})
        self._audit("package.served", actor=env["from"],
                    target=f"{name}", bytes=total)

    def _h_market_package(self, conn, env, payload):
        name = ((payload.get("manifest") or {}).get("name")
                or payload.get("name"))
        self._fulfill((MARKET_PACKAGE, env["from"], name), payload)

    def fetch_package(self, peer_pid, name, version=None,
                      timeout=_FETCH_TIMEOUT):
        """Fetch a package from a peer over ACP. Returns
        (manifest, {path: bytes}) after verifying publisher signature
        and every file sha256."""
        from acp_proto import b62decode_fixed as _b62d
        key = (MARKET_PACKAGE, peer_pid, name)
        waiter = {"event": threading.Event(), "payload": None}
        with self._lock:
            self._waiters[key] = waiter
        try:
            req = {"name": name}
            if version:
                req["version"] = version
            self._c._send_e2e(MARKET_FETCH, peer_pid, req)
            if not waiter["event"].wait(timeout):
                raise AcpError("INTERNAL",
                               "timeout waiting for market_package")
            resp = waiter["payload"]
        finally:
            with self._lock:
                self._waiters.pop(key, None)
        if not resp.get("found"):
            raise AcpError("INTERNAL",
                           f"package not available: {resp.get('error')}")
        manifest = verify_manifest(resp["manifest"], self._pubkey)
        files_by_path = {}
        for f in resp["files"]:
            files_by_path[f["path"]] = _b62d(f["content"])
        verify_package_files(manifest, files_by_path)
        # Cache the verified manifest in the local index so the package
        # is discoverable/installable locally afterwards.
        self.store.add_package(manifest["name"], manifest["version"],
                               manifest_to_json(manifest),
                               manifest["publisher_id"])
        return manifest, files_by_path

    # -------------------------------------------------------------- install
    def install_package(self, name, version=None, from_peer=None,
                        approve=False):
        """Discovery UI hook: verify + quarantine + policy-gated install.

        NEVER executes package code: install only writes files and
        records an audit event. With the default 'manual' policy the
        caller must pass approve=True (explicit local action), or set
        an on_install_request callback / 'auto' policy.
        Returns a JSON-serializable receipt.
        """
        if from_peer is not None:
            manifest, files_by_path = self.fetch_package(from_peer, name,
                                                         version)
        else:
            row = self.store.get_package(name, version)
            if row is None:
                raise AcpError("INTERNAL", f"unknown package {name!r}")
            manifest = verify_manifest(row["manifest"], self._pubkey)
            pkg_dir = os.path.join(
                self.packages_dir, f"{manifest['name']}-{manifest['version']}")
            files_by_path = {}
            for entry in manifest["files"]:
                safe = _check_path(entry["path"])
                with open(os.path.join(pkg_dir, safe), "rb") as f:
                    files_by_path[entry["path"]] = f.read()
            verify_package_files(manifest, files_by_path)

        # 1. sanitize every path (traversal/absolute/NUL rejected here)
        staged = []
        seen = set()
        for entry in manifest["files"]:
            safe = _check_path(entry["path"])
            if safe in seen:
                raise AcpError("FILE_REJECTED",
                               f"name collision: {safe!r}")
            seen.add(safe)
            staged.append((safe, files_by_path[entry["path"]]))

        # 2. quarantine: write to an isolated staging dir first
        qdir = os.path.join(self.quarantine_dir,
                            f"{manifest['name']}-{manifest['version']}")
        if os.path.isdir(qdir):
            shutil.rmtree(qdir)
        os.makedirs(qdir)
        for safe, data in staged:
            if not os.path.abspath(os.path.join(qdir, safe)).startswith(
                    os.path.abspath(qdir) + os.sep):
                raise AcpError("FILE_REJECTED", "quarantine escape")
            with open(os.path.join(qdir, safe), "wb") as f:
                f.write(data)
        # re-verify from quarantine bytes (what we install is what we
        # verified)
        qfiles = {e["path"]: open(os.path.join(
            qdir, _check_path(e["path"])), "rb").read()
            for e in manifest["files"]}
        verify_package_files(manifest, qfiles)

        # 3. policy gate: explicit local action required
        if self._install_policy == "deny":
            raise AcpError("POLICY_DENIED", "package installs are denied")
        if self._install_policy == "manual":
            approved = bool(approve)
            if not approved and self._install_cb is not None:
                approved = bool(self._install_cb(manifest))
            if not approved:
                raise AcpError("POLICY_DENIED",
                               "install requires explicit local approval")

        # 4. install: files only, never executed
        dest = os.path.join(self.installed_dir,
                            f"{manifest['name']}-{manifest['version']}")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(qdir, dest)
        with open(os.path.join(dest, "manifest.json"), "w") as f:
            f.write(manifest_to_json(manifest))
        shutil.rmtree(qdir, ignore_errors=True)
        self.store.add_install(manifest["name"], manifest["version"],
                               dest, manifest["publisher_id"])
        self._audit("package.installed", target=f"{manifest['name']}-"
                    f"{manifest['version']}",
                    publisher=manifest["publisher_id"][:16],
                    files=len(staged),
                    note="files written only; package code NOT executed")
        return {"installed": dest, "name": manifest["name"],
                "version": manifest["version"],
                "publisher_id": manifest["publisher_id"],
                "files": len(staged)}

    # ============================================================ SERVICES
    def publish_service(self, title, description="", capabilities=(),
                        price_model="free", terms=""):
        """Publish a service listing signed by this agent."""
        if price_model not in ("free", "negotiable"):
            raise AcpError("BAD_ENVELOPE",
                           f"bad price_model {price_model!r}")
        listing = {
            "listing_id": os.urandom(16).hex(),
            "agent_id": self._c.peer_id,
            "title": title,
            "description": description,
            "capabilities": list(capabilities),
            "price_model": price_model,
            "terms": terms,
            "ts": int(time.time()),
        }
        listing["sig"] = b62encode_fixed(ed25519_sign(
            self._c.identity.ed_priv, canonical(listing)))
        self.store.add_service(listing)
        self._audit("service.published", target=listing["listing_id"],
                    title=title)
        return listing

    def search_services(self, query):
        """Discovery UI hook (JSON-serializable)."""
        return self.store.list_services(query=query, limit=100)

    def verify_service_sig(self, listing):
        """Verify a service listing's publisher signature."""
        vkey = self._pubkey(listing["agent_id"])
        if vkey is None:
            raise AcpError("UNKNOWN_SENDER", "unknown listing agent")
        unsigned = {k: v for k, v in listing.items() if k != "sig"}
        try:
            sig = b62decode_fixed(listing["sig"])
        except (ValueError, KeyError):
            raise AcpError("BAD_ENVELOPE", "bad listing sig encoding")
        if not ed25519_verify(vkey, canonical(unsigned), sig):
            raise AcpError("INVALID_SIG", "service listing sig invalid")
        return True

    # ========================================================= TRANSACTIONS
    def _resolve_listing(self, listing_id):
        """A listing is offerable if it is local (my service / my
        package) or was learned from a peer via market_list."""
        if self.store.get_service(listing_id) is not None:
            return listing_id
        if "@" in (listing_id or ""):
            name, _, version = listing_id.partition("@")
            if self.store.get_package(name, version or None) is not None:
                return listing_id
        if self.store.get_known_listing(listing_id) is not None:
            return listing_id
        raise AcpError("INTERNAL", f"unknown listing {listing_id!r}")

    def _parties(self, offer):
        me = self._c.peer_id
        if offer["buyer_id"] == me:
            return offer["seller_id"]
        if offer["seller_id"] == me:
            return offer["buyer_id"]
        raise AcpError("POLICY_DENIED", "not a party to this offer")

    def _require_party_sender(self, env, offer):
        if env["from"] not in (offer["buyer_id"], offer["seller_id"]):
            raise AcpError("POLICY_DENIED",
                           "sender is not a party to this offer")

    def _set_offer_state(self, offer_id, state):
        self.store.update_offer(offer_id, state)
        self._audit("offer.state", target=offer_id, state=state)

    # -------------------------------------------------------------- offers
    def make_offer(self, peer_pid, listing_id, terms):
        """Buyer side: create an offer and send market_offer."""
        self._resolve_listing(listing_id)
        offer_id = os.urandom(16).hex()
        self.store.add_offer(offer_id, listing_id, self._c.peer_id,
                             peer_pid, terms, ST_OFFERED)
        self._c._send_e2e(MARKET_OFFER, peer_pid,
                          {"offer_id": offer_id, "listing_id": listing_id,
                           "terms": terms, "ts": int(time.time())})
        self._audit("offer.made", target=offer_id, listing=listing_id,
                    peer=peer_pid[:16])
        return offer_id

    def _h_offer(self, conn, env, payload):
        # Envelope signature already verified by the connector; a
        # forged market_offer never reaches this handler.
        listing_id = self._resolve_listing(payload["listing_id"])
        offer_id = payload["offer_id"]
        if self.store.get_offer(offer_id) is not None:
            self._audit("offer.duplicate", actor=env["from"],
                        target=offer_id, result="denied",
                        note="duplicate offer_id dropped")
            return
        self.store.add_offer(offer_id, listing_id, env["from"],
                             self._c.peer_id, payload["terms"], ST_OFFERED)
        self._audit("offer.received", actor=env["from"], target=offer_id,
                    listing=listing_id)

    def accept_offer(self, offer_id):
        """Seller side: offered -> accepted, notify buyer."""
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        if offer["seller_id"] != self._c.peer_id:
            raise AcpError("POLICY_DENIED", "only the seller can accept")
        if offer["state"] != ST_OFFERED:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot accept offer in state {offer['state']}")
        self._set_offer_state(offer_id, ST_ACCEPTED)
        self._c._send_e2e(MARKET_OFFER_ACCEPT, offer["buyer_id"],
                          {"offer_id": offer_id})

    def _h_offer_accept(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            self._audit("offer.accept_unknown", actor=env["from"],
                        target=payload["offer_id"], result="denied")
            return
        self._require_party_sender(env, offer)
        if offer["state"] != ST_OFFERED:
            # Replayed accept (same nonce is already dropped by the
            # connector replay cache; a fresh-nonce replay lands here):
            # idempotent no-op, never double-applies.
            self._audit("offer.accept_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied",
                        note="duplicate accept dropped")
            return
        self._set_offer_state(offer["offer_id"], ST_ACCEPTED)

    def decline_offer(self, offer_id, reason=""):
        """Seller side: offered -> declined, notify buyer."""
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        if offer["seller_id"] != self._c.peer_id:
            raise AcpError("POLICY_DENIED", "only the seller can decline")
        if offer["state"] != ST_OFFERED:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot decline offer in state {offer['state']}")
        self._set_offer_state(offer_id, ST_DECLINED)
        self._c._send_e2e(MARKET_OFFER_DECLINE, offer["buyer_id"],
                          {"offer_id": offer_id, "reason": reason})

    def _h_offer_decline(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            return
        self._require_party_sender(env, offer)
        if offer["state"] != ST_OFFERED:
            self._audit("offer.decline_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied")
            return
        self._set_offer_state(offer["offer_id"], ST_DECLINED)

    def get_offer(self, offer_id):
        return self.store.get_offer(offer_id)

    def list_offers(self, limit=100):
        return self.store.list_offers(limit=limit)

    # -------------------------------------------------------------- escrow
    def escrow_hold(self, offer_id, amount_cents, currency,
                    adapter_name="null"):
        """Buyer side: accepted -> escrow_held via a payment adapter.

        The adapter records the hold; with NullAdapter NO money moves
        (see payments.py honest-money statement).
        """
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        if offer["buyer_id"] != self._c.peer_id:
            raise AcpError("POLICY_DENIED",
                           "only the buyer places the escrow hold")
        if offer["state"] != ST_ACCEPTED:
            if offer["state"] in _TERMINAL or offer["state"] == ST_ESCROW:
                raise AcpError("ALREADY_SETTLED",
                               f"offer is {offer['state']}")
            raise AcpError("BAD_ENVELOPE",
                           f"cannot hold escrow in state {offer['state']}")
        adapter = self.get_adapter(adapter_name)
        hold_id = adapter.create_hold(offer_id, amount_cents, currency)
        self._set_offer_state(offer_id, ST_ESCROW)
        self._c._send_e2e(MARKET_ESCROW_HOLD, offer["seller_id"],
                          {"offer_id": offer_id, "hold_id": hold_id,
                           "adapter": adapter_name,
                           "amount_cents": int(amount_cents),
                           "currency": currency})
        self._audit("escrow.held", target=offer_id, hold=hold_id,
                    amount_cents=int(amount_cents), currency=currency,
                    adapter=adapter_name,
                    note="bookkeeping record only; no funds moved")
        return hold_id

    def _record_counterparty_hold(self, offer_id, payload):
        hold_id = payload["hold_id"]
        if self.store.get_hold(hold_id) is None:
            self.store.add_hold(hold_id, offer_id, payload["adapter"],
                                int(payload["amount_cents"]),
                                payload["currency"], state="held")

    def _h_escrow_hold(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            raise AcpError("INTERNAL",
                           f"unknown offer {payload['offer_id']}")
        # Only the buyer (offer creator) may announce the hold.
        if env["from"] != offer["buyer_id"]:
            raise AcpError("POLICY_DENIED",
                           "escrow hold must come from the buyer")
        if offer["state"] == ST_ESCROW:
            self._record_counterparty_hold(offer["offer_id"], payload)
            self._audit("escrow.hold_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied",
                        note="duplicate hold dropped")
            return
        if offer["state"] != ST_ACCEPTED:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot hold escrow in state {offer['state']}")
        self._record_counterparty_hold(offer["offer_id"], payload)
        self._set_offer_state(offer["offer_id"], ST_ESCROW)

    def escrow_release(self, offer_id):
        """Party side: escrow_held -> released. Exactly-once: a second
        call raises AcpError("ALREADY_SETTLED")."""
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        self._parties(offer)  # raises unless I am a party
        if offer["state"] in _TERMINAL:
            raise AcpError("ALREADY_SETTLED",
                           f"offer already {offer['state']}")
        if offer["state"] != ST_ESCROW:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot release escrow in state {offer['state']}")
        hold = self.store.get_hold_for_offer(offer_id)
        if hold is None:
            raise AcpError("INTERNAL", "no hold recorded for offer")
        adapter = self.get_adapter(hold["adapter"])
        adapter.release_hold(hold["hold_id"])
        self._set_offer_state(offer_id, ST_RELEASED)
        peer = self._parties(self.store.get_offer(offer_id))
        self._c._send_e2e(MARKET_ESCROW_RELEASE, peer,
                          {"offer_id": offer_id, "hold_id": hold["hold_id"],
                           "adapter": hold["adapter"],
                           "amount_cents": hold["amount_cents"],
                           "currency": hold["currency"]})
        self._audit("escrow.released", target=offer_id,
                    hold=hold["hold_id"],
                    note="bookkeeping record only; no funds moved")

    def _h_escrow_release(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            raise AcpError("INTERNAL",
                           f"unknown offer {payload['offer_id']}")
        self._require_party_sender(env, offer)
        if offer["state"] in _TERMINAL:
            # Duplicate release: idempotent no-op, never double-applies.
            self._audit("escrow.release_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied",
                        note="duplicate release dropped")
            return
        if offer["state"] != ST_ESCROW:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot release escrow in state {offer['state']}")
        self._record_counterparty_hold(offer["offer_id"], payload)
        adapter = self.get_adapter(payload["adapter"])
        try:
            adapter.release_hold(payload["hold_id"])
        except AcpError as e:
            if e.code != "ALREADY_SETTLED":
                raise
        self._set_offer_state(offer["offer_id"], ST_RELEASED)

    def escrow_cancel(self, offer_id, reason=""):
        """Party side: escrow_held -> cancelled. Exactly-once."""
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        self._parties(offer)
        if offer["state"] in _TERMINAL:
            raise AcpError("ALREADY_SETTLED",
                           f"offer already {offer['state']}")
        if offer["state"] != ST_ESCROW:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot cancel escrow in state {offer['state']}")
        hold = self.store.get_hold_for_offer(offer_id)
        if hold is None:
            raise AcpError("INTERNAL", "no hold recorded for offer")
        adapter = self.get_adapter(hold["adapter"])
        adapter.cancel_hold(hold["hold_id"])
        self._set_offer_state(offer_id, ST_CANCELLED)
        peer = self._parties(self.store.get_offer(offer_id))
        self._c._send_e2e(MARKET_ESCROW_CANCEL, peer,
                          {"offer_id": offer_id, "reason": reason,
                           "hold_id": hold["hold_id"],
                           "adapter": hold["adapter"],
                           "amount_cents": hold["amount_cents"],
                           "currency": hold["currency"]})
        self._audit("escrow.cancelled", target=offer_id,
                    hold=hold["hold_id"], reason=reason)

    def _h_escrow_cancel(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            raise AcpError("INTERNAL",
                           f"unknown offer {payload['offer_id']}")
        self._require_party_sender(env, offer)
        if offer["state"] in _TERMINAL:
            self._audit("escrow.cancel_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied",
                        note="duplicate cancel dropped")
            return
        if offer["state"] != ST_ESCROW:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot cancel escrow in state {offer['state']}")
        self._record_counterparty_hold(offer["offer_id"], payload)
        adapter = self.get_adapter(payload["adapter"])
        try:
            adapter.cancel_hold(payload["hold_id"])
        except AcpError as e:
            if e.code != "ALREADY_SETTLED":
                raise
        self._set_offer_state(offer["offer_id"], ST_CANCELLED)

    # ------------------------------------------------------------- disputes
    def open_dispute(self, offer_id, claim):
        """Party side: escrow_held -> disputed."""
        offer = self.store.get_offer(offer_id)
        if offer is None:
            raise AcpError("INTERNAL", f"unknown offer {offer_id}")
        peer = self._parties(offer)
        if offer["state"] != ST_ESCROW:
            raise AcpError("BAD_ENVELOPE",
                           f"cannot dispute offer in state {offer['state']}")
        self._set_offer_state(offer_id, ST_DISPUTED)
        self._c._send_e2e(MARKET_DISPUTE_OPEN, peer,
                          {"offer_id": offer_id, "claim": claim})
        self._audit("dispute.opened", target=offer_id, claim=claim)
        return True

    def _h_dispute_open(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            raise AcpError("INTERNAL",
                           f"unknown offer {payload['offer_id']}")
        self._require_party_sender(env, offer)
        if offer["state"] != ST_ESCROW:
            self._audit("dispute.open_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied")
            return
        self._set_offer_state(offer["offer_id"], ST_DISPUTED)

    def resolve_dispute(self, offer_id, resolution, peers=None):
        """Arbiter side: sign a resolution and deliver it to the parties.

        resolution is "release" (seller gets the hold) or "refund"
        (buyer gets it back). The resolver's Ed25519 signature over
        canonical({offer_id, resolution, ts}) lets each party verify the
        resolver's identity independently.
        """
        if resolution not in ("release", "refund"):
            raise AcpError("BAD_ENVELOPE",
                           f"bad resolution {resolution!r}")
        ts = int(time.time())
        body = {"offer_id": offer_id, "resolution": resolution, "ts": ts}
        sig = b62encode_fixed(ed25519_sign(self._c.identity.ed_priv,
                                     canonical(body)))
        payload = dict(body, resolver_sig=sig)
        targets = list(peers) if peers else []
        if not targets:
            offer = self.store.get_offer(offer_id)
            if offer is None:
                raise AcpError("INTERNAL", f"unknown offer {offer_id}")
            targets = [self._parties(offer)]
        for peer in targets:
            self._c._send_e2e(MARKET_DISPUTE_RESOLVE, peer, payload)
        # If I am a party, apply locally as well.
        offer = self.store.get_offer(offer_id)
        if offer is not None and self._c.peer_id in (offer["buyer_id"],
                                                     offer["seller_id"]):
            self._apply_resolution(offer, resolution, self._c.peer_id)
        self._audit("dispute.resolved", target=offer_id,
                    resolution=resolution)
        return True

    def _h_dispute_resolve(self, conn, env, payload):
        offer = self.store.get_offer(payload["offer_id"])
        if offer is None:
            self._audit("dispute.resolve_unknown", actor=env["from"],
                        target=payload["offer_id"], result="denied")
            return
        # Verify the resolver's own signature (resolver may be a
        # third-party arbiter, not necessarily a party).
        vkey = self._pubkey(env["from"])
        if vkey is None:
            raise AcpError("UNKNOWN_SENDER", "unknown resolver")
        body = {"offer_id": payload["offer_id"],
                "resolution": payload["resolution"], "ts": payload["ts"]}
        try:
            sig = b62decode_fixed(payload["resolver_sig"])
        except (ValueError, KeyError):
            raise AcpError("BAD_ENVELOPE", "bad resolver_sig encoding")
        if not ed25519_verify(vkey, canonical(body), sig):
            raise AcpError("INVALID_SIG", "resolver signature invalid")
        if payload["resolution"] not in ("release", "refund"):
            raise AcpError("BAD_ENVELOPE",
                           f"bad resolution {payload['resolution']!r}")
        if offer["state"] != ST_DISPUTED:
            self._audit("dispute.resolve_replay", actor=env["from"],
                        target=offer["offer_id"], result="denied",
                        note="offer not disputed")
            return
        self._apply_resolution(offer, payload["resolution"], env["from"])

    def _apply_resolution(self, offer, resolution, resolver):
        hold = self.store.get_hold_for_offer(offer["offer_id"])
        if hold is not None:
            adapter = self.get_adapter(hold["adapter"])
            try:
                if resolution == "release":
                    adapter.release_hold(hold["hold_id"])
                else:
                    adapter.cancel_hold(hold["hold_id"])
            except AcpError as e:
                if e.code != "ALREADY_SETTLED":
                    raise
        self._set_offer_state(offer["offer_id"],
                              ST_RELEASED if resolution == "release"
                              else ST_CANCELLED)
        self._audit("dispute.applied", target=offer["offer_id"],
                    resolution=resolution, resolver=resolver[:16])
