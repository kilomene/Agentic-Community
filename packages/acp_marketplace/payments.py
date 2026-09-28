"""Payment adapters for the marketplace escrow protocol.

HONEST MONEY STATEMENT: nothing in this file moves real money. The only
bundled adapter is :class:`NullAdapter`, which records escrow holds in a
local SQLite table and moves NO funds anywhere — it is a bookkeeping
record of intent, suitable for $0 development and protocol testing.
Settlement of real funds requires a real payment adapter, and NONE is
bundled (per the project's $0 rule). Any UI, CLI, or doc text that
suggests otherwise is a bug.

Real-adapter interface spec (for a future implementer):
  * ``create_hold(offer_id, amount_cents, currency) -> hold_id``:
    place a hold on the buyer's funds. MUST be idempotent per
    (offer_id, amount_cents, currency): a repeated call for the same
    offer must return the existing hold_id, never create a second hold.
    The hold MUST be reversible until released or cancelled.
  * ``release_hold(hold_id)``: settle the held funds to the seller.
    MUST be exactly-once: a second call MUST raise
    ``AcpError("ALREADY_SETTLED")`` and MUST NOT move funds again.
    After a successful release, ``get_status`` reports ``released`` and
    the operation is final (settlement finality: the seller can rely on
    the funds).
  * ``cancel_hold(hold_id)``: return held funds to the buyer.
    Same exactly-once guarantee as ``release_hold``.
  * ``get_status(hold_id) -> dict``: ``{"hold_id", "offer_id",
    "amount_cents", "currency", "state"}`` where state is one of
    ``held`` / ``released`` / ``cancelled``. MUST reflect the payment
    provider's ground truth, not a local guess.
  * Guarantees a real adapter must provide: holds are backed by real
    funds at a real provider; release/cancel are exactly-once against
    the provider (use the provider's idempotency keys); network errors
    leave state UNKNOWN and the adapter must re-query before retrying;
    all amounts are integer minor units (cents); currency is ISO-4217.
"""
import os

from acp_proto import AcpError


class PaymentAdapter:
    """Abstract escrow payment adapter. See module docstring for the
    real-adapter interface spec and settlement-finality expectations."""

    name = "base"

    def create_hold(self, offer_id, amount_cents, currency):
        """Place a hold; return hold_id. Idempotent per offer."""
        raise NotImplementedError

    def release_hold(self, hold_id):
        """Settle held funds to the seller. Exactly-once."""
        raise NotImplementedError

    def cancel_hold(self, hold_id):
        """Return held funds to the buyer. Exactly-once."""
        raise NotImplementedError

    def get_status(self, hold_id):
        """Return {"hold_id","offer_id","amount_cents","currency","state"}."""
        raise NotImplementedError


class NullAdapter(PaymentAdapter):
    """Bookkeeping-only adapter: records holds in SQLite, moves NO money.

    Every method docstring and the marketplace README state this in
    plain language: this adapter is a local ledger for development and
    protocol testing. No funds exist, none move, none settle. A hold
    here is a signed statement of intent between the two agents, and a
    release is both agents agreeing the intent is fulfilled.
    """

    name = "null"

    def __init__(self, store):
        self._store = store

    def create_hold(self, offer_id, amount_cents, currency):
        """Record a hold. Moves NO money. Idempotent per offer: a
        second call for the same offer returns the existing hold_id."""
        if amount_cents is None or int(amount_cents) <= 0:
            raise AcpError("BAD_ENVELOPE", "amount_cents must be > 0")
        if not currency or not isinstance(currency, str):
            raise AcpError("BAD_ENVELOPE", "currency is required")
        existing = self._store.get_hold_for_offer(offer_id)
        if existing is not None:
            return existing["hold_id"]
        hold_id = os.urandom(16).hex()
        self._store.add_hold(hold_id, offer_id, self.name,
                             int(amount_cents), currency, state="held")
        return hold_id

    def release_hold(self, hold_id):
        """Mark a recorded hold released. Moves NO money. Exactly-once:
        a second call raises AcpError("ALREADY_SETTLED")."""
        hold = self._store.get_hold(hold_id)
        if hold is None:
            raise AcpError("INTERNAL", f"unknown hold {hold_id}")
        if hold["state"] != "held":
            raise AcpError("ALREADY_SETTLED",
                           f"hold {hold_id} is {hold['state']}")
        self._store.update_hold(hold_id, "released")
        return True

    def cancel_hold(self, hold_id):
        """Mark a recorded hold cancelled. Moves NO money. Exactly-once:
        a second call raises AcpError("ALREADY_SETTLED")."""
        hold = self._store.get_hold(hold_id)
        if hold is None:
            raise AcpError("INTERNAL", f"unknown hold {hold_id}")
        if hold["state"] != "held":
            raise AcpError("ALREADY_SETTLED",
                           f"hold {hold_id} is {hold['state']}")
        self._store.update_hold(hold_id, "cancelled")
        return True

    def get_status(self, hold_id):
        """Return the recorded hold status. This is a local ledger
        entry, not a bank statement: no money backs it."""
        hold = self._store.get_hold(hold_id)
        if hold is None:
            raise AcpError("INTERNAL", f"unknown hold {hold_id}")
        return {"hold_id": hold["hold_id"], "offer_id": hold["offer_id"],
                "amount_cents": hold["amount_cents"],
                "currency": hold["currency"], "state": hold["state"]}
