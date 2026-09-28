"""Family records with per-peer visibility.

family_add(name, relation, notes, visible_to) -> id, where visible_to is
a list of peer ids or ["*"] for every peer.

family_list(for_peer=None): the owner (for_peer=None) sees everything.
A peer must hold the 'family_read' grant and then sees only members
whose visible_to contains their id or "*". family_update/delete need
'family_write' when done for a peer.
"""
import json
import os
import time

from acp_proto import AcpError


class Family:
    def __init__(self, store, permissions, audit, owner_pid):
        self._store = store
        self._permissions = permissions
        self._audit = audit
        self._owner = owner_pid

    def add(self, name, relation="", notes="", visible_to=None):
        if not isinstance(name, str) or not name:
            raise AcpError("INTERNAL", "family name must be non-empty")
        visible_to = list(visible_to) if visible_to else []
        fam_id = "fam_" + os.urandom(6).hex()
        now = int(time.time())
        self._store.add_family(fam_id, name, relation or "", notes or "",
                               visible_to, self._owner, now)
        self._audit.log("family.added", target=fam_id, result="ok",
                        details={"name": name,
                                 "visible_to_count": len(visible_to)})
        return fam_id

    def list(self, for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "family_read")
        rows = self._store.list_families()
        out = []
        for r in rows:
            vis = json.loads(r["visible_to"] or "[]")
            if for_peer is not None and not (
                    for_peer in vis or "*" in vis):
                continue
            out.append({
                "id": r["family_id"], "name": r["name"],
                "relation": r["relation"], "notes": r["notes"],
                "visible_to": vis, "created_by": r["created_by"],
                "created_at": r["created_at"],
            })
        return out

    def update(self, fam_id, for_peer=None, **fields):
        if for_peer is not None:
            self._permissions.check(for_peer, "family_write")
        if self._store.get_family(fam_id) is None:
            raise AcpError("NOT_FOUND", f"unknown family {fam_id}")
        self._store.update_family(fam_id, **fields)
        self._audit.log("family.updated", actor=for_peer or "local",
                        target=fam_id, result="ok",
                        details={"fields": sorted(fields)})

    def delete(self, fam_id, for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "family_write")
        if self._store.get_family(fam_id) is None:
            raise AcpError("NOT_FOUND", f"unknown family {fam_id}")
        self._store.delete_family(fam_id)
        self._audit.log("family.deleted", actor=for_peer or "local",
                        target=fam_id, result="ok", details={})
