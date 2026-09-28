"""SQLite persistence for acp_marketplace.

Own database file (``marketplace.db`` in the connector home directory),
following the acp_connector.store conventions: CREATE TABLE IF NOT
EXISTS, one re-entrant lock serializing every method.
"""
import json
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS market_packages(
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  manifest     TEXT NOT NULL,
  publisher_id TEXT NOT NULL,
  published_at INTEGER NOT NULL,
  PRIMARY KEY(name, version)
);
CREATE INDEX IF NOT EXISTS idx_mktpkg_pub ON market_packages(publisher_id);
CREATE TABLE IF NOT EXISTS market_services(
  listing_id   TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL,
  title        TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  capabilities TEXT NOT NULL DEFAULT '[]',
  price_model  TEXT NOT NULL DEFAULT 'free',
  terms        TEXT NOT NULL DEFAULT '',
  ts           INTEGER NOT NULL,
  sig          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS market_offers(
  offer_id    TEXT PRIMARY KEY,
  listing_id  TEXT NOT NULL,
  buyer_id    TEXT NOT NULL,
  seller_id   TEXT NOT NULL,
  terms       TEXT NOT NULL,
  state       TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS market_holds(
  hold_id      TEXT PRIMARY KEY,
  offer_id     TEXT NOT NULL,
  adapter      TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency     TEXT NOT NULL,
  state        TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mkthold_offer ON market_holds(offer_id);
CREATE TABLE IF NOT EXISTS market_installs(
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  path         TEXT NOT NULL,
  publisher_id TEXT NOT NULL,
  installed_at INTEGER NOT NULL,
  PRIMARY KEY(name, version)
);
CREATE TABLE IF NOT EXISTS market_known_listings(
  listing_id TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  title      TEXT NOT NULL,
  data       TEXT NOT NULL,
  known_via  TEXT NOT NULL,
  seen_at    INTEGER NOT NULL
);
"""


def _row(r):
    return dict(r) if r is not None else None


class MarketStore:
    def __init__(self, path):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self):
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------- packages
    def add_package(self, name, version, manifest_json, publisher_id):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO market_packages(name, version,"
                " manifest, publisher_id, published_at)"
                " VALUES (?,?,?,?,?)",
                (name, version, manifest_json, publisher_id,
                 int(time.time())))
            self._db.commit()

    def get_package(self, name, version=None):
        with self._lock:
            if version is not None:
                r = self._db.execute(
                    "SELECT * FROM market_packages WHERE name=? AND"
                    " version=?", (name, version)).fetchone()
            else:
                r = self._db.execute(
                    "SELECT * FROM market_packages WHERE name=? ORDER BY"
                    " published_at DESC LIMIT 1", (name,)).fetchone()
            row = _row(r)
            if row:
                row["manifest"] = json.loads(row["manifest"])
            return row

    def list_packages(self, query="", capability=None, limit=25, offset=0):
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM market_packages ORDER BY published_at DESC"
                " LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            out = []
            q = (query or "").lower()
            for r in rows:
                m = json.loads(r["manifest"])
                if q and q not in (m.get("name", "") + " "
                                   + m.get("description", "")).lower():
                    continue
                if capability and capability not in m.get("capabilities",
                                                          []):
                    continue
                out.append({"type": "package", "name": m["name"],
                            "version": m["version"],
                            "description": m.get("description", ""),
                            "capabilities": m.get("capabilities", []),
                            "publisher_id": m.get("publisher_id", ""),
                            "ts": m.get("ts", 0)})
            return out

    # ------------------------------------------------------------- services
    def add_service(self, listing):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO market_services(listing_id,"
                " agent_id, title, description, capabilities, price_model,"
                " terms, ts, sig) VALUES (?,?,?,?,?,?,?,?,?)",
                (listing["listing_id"], listing["agent_id"],
                 listing["title"], listing.get("description", ""),
                 json.dumps(listing.get("capabilities", [])),
                 listing.get("price_model", "free"),
                 listing.get("terms", ""), listing["ts"],
                 listing["sig"]))
            self._db.commit()

    def list_services(self, query="", capability=None, limit=25, offset=0):
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM market_services ORDER BY ts DESC"
                " LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            out = []
            q = (query or "").lower()
            for r in rows:
                caps = json.loads(r["capabilities"])
                if q and q not in (r["title"] + " "
                                   + r["description"]).lower():
                    continue
                if capability and capability not in caps:
                    continue
                out.append({"type": "service",
                            "listing_id": r["listing_id"],
                            "agent_id": r["agent_id"], "title": r["title"],
                            "description": r["description"],
                            "capabilities": caps,
                            "price_model": r["price_model"],
                            "terms": r["terms"], "ts": r["ts"],
                            "sig": r["sig"]})
            return out

    def get_service(self, listing_id):
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM market_services WHERE listing_id=?",
                (listing_id,)).fetchone()
            row = _row(r)
            if row:
                row["capabilities"] = json.loads(row["capabilities"])
            return row

    # --------------------------------------------------------------- offers
    def add_offer(self, offer_id, listing_id, buyer_id, seller_id, terms,
                  state):
        now = int(time.time())
        with self._lock:
            self._db.execute(
                "INSERT INTO market_offers(offer_id, listing_id, buyer_id,"
                " seller_id, terms, state, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (offer_id, listing_id, buyer_id, seller_id,
                 json.dumps(terms), state, now, now))
            self._db.commit()

    def get_offer(self, offer_id):
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM market_offers WHERE offer_id=?",
                (offer_id,)).fetchone()
            row = _row(r)
            if row:
                row["terms"] = json.loads(row["terms"])
            return row

    def update_offer(self, offer_id, state):
        with self._lock:
            cur = self._db.execute(
                "UPDATE market_offers SET state=?, updated_at=?"
                " WHERE offer_id=?", (state, int(time.time()),
                                      offer_id)).rowcount
            self._db.commit()
            return cur

    def list_offers(self, limit=100):
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM market_offers ORDER BY created_at DESC"
                " LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                d = _row(r)
                d["terms"] = json.loads(d["terms"])
                out.append(d)
            return out

    # ---------------------------------------------------------------- holds
    def add_hold(self, hold_id, offer_id, adapter, amount_cents, currency,
                 state="held"):
        now = int(time.time())
        with self._lock:
            self._db.execute(
                "INSERT INTO market_holds(hold_id, offer_id, adapter,"
                " amount_cents, currency, state, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (hold_id, offer_id, adapter, amount_cents, currency,
                 state, now, now))
            self._db.commit()

    def get_hold(self, hold_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM market_holds WHERE hold_id=?",
                (hold_id,)).fetchone())

    def get_hold_for_offer(self, offer_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM market_holds WHERE offer_id=? ORDER BY"
                " created_at DESC LIMIT 1", (offer_id,)).fetchone())

    def update_hold(self, hold_id, state):
        with self._lock:
            cur = self._db.execute(
                "UPDATE market_holds SET state=?, updated_at=?"
                " WHERE hold_id=?",
                (state, int(time.time()), hold_id)).rowcount
            self._db.commit()
            return cur

    # -------------------------------------------------------------- installs
    def add_install(self, name, version, path, publisher_id):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO market_installs(name, version,"
                " path, publisher_id, installed_at)"
                " VALUES (?,?,?,?,?)",
                (name, version, path, publisher_id, int(time.time())))
            self._db.commit()

    def list_installs(self):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM market_installs"
                " ORDER BY installed_at DESC").fetchall()]

    # --------------------------------------- listings learned from peers
    def add_known_listing(self, listing, known_via):
        lid = (listing["listing_id"] if listing.get("type") == "service"
               else "%s@%s" % (listing.get("name"), listing.get("version")))
        title = (listing.get("title") if listing.get("type") == "service"
                 else listing.get("name", ""))
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO market_known_listings(listing_id,"
                " kind, agent_id, title, data, known_via, seen_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (lid, listing.get("type", ""), listing.get("agent_id", ""),
                 title, json.dumps(listing), known_via,
                 int(time.time())))
            self._db.commit()

    def get_known_listing(self, listing_id):
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM market_known_listings WHERE listing_id=?",
                (listing_id,)).fetchone()
            row = _row(r)
            if row:
                row["data"] = json.loads(row["data"])
            return row
