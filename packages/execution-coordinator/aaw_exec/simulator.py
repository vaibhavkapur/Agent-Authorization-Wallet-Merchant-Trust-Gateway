"""Simulated payment processor.

The processor keeps its **own** durable ledger (``processor_ledger``) keyed by
idempotency key, independent from the wallet's ``payment_attempts``. That
separation is what makes "response lost after success" reproducible: the
ledger says executed, the wallet never heard back, and reconciliation must
query the ledger instead of guessing.

Fault injection (``fault`` argument):

* ``decline``               – processor declines (definitive non-execution)
* ``lose_response``         – processor executes, response is lost
* ``crash_before_submit``   – worker dies after the claim was persisted, before submitting
* ``slow``                  – no-op marker used by the demo UI
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from aaw_domain.clock import Clock, SystemClock
from aaw_domain.models import ProcessorLedgerEntry, new_id


class ResponseLost(Exception):
    """The processor executed (or may have executed) but the response never arrived."""


class WorkerCrash(Exception):
    """Simulates the wallet process dying between claim persistence and submission."""


@dataclass
class PaymentResult:
    status: str  # succeeded | declined
    psp_confirmation_id: str
    idempotent_replay: bool = False


class PaymentSimulator:
    def __init__(self, session: Session, clock: Optional[Clock] = None):
        self.session = session
        self.clock = clock or SystemClock()

    def lookup(self, idempotency_key: str) -> Optional[ProcessorLedgerEntry]:
        return self.session.get(ProcessorLedgerEntry, idempotency_key)

    def execute(self, idempotency_key: str, amount_minor: int, currency: str, payee_id: str,
                fault: Optional[str] = None) -> PaymentResult:
        existing = self.lookup(idempotency_key)
        if existing is not None:
            # Repeated delivery of the same business operation returns the existing result.
            return PaymentResult(existing.status, existing.psp_confirmation_id, idempotent_replay=True)
        if fault == "crash_before_submit":
            raise WorkerCrash("simulated crash after claim persistence, before submission")
        status = "declined" if fault == "decline" else "succeeded"
        entry = ProcessorLedgerEntry(
            idempotency_key=idempotency_key,
            amount_minor=amount_minor,
            currency=currency,
            payee_id=payee_id,
            status=status,
            psp_confirmation_id=new_id("psp"),
            executed_at=self.clock.now_ts(),
        )
        self.session.add(entry)
        self.session.flush()
        if fault == "lose_response":
            raise ResponseLost("simulated network failure after the processor executed")
        return PaymentResult(status, entry.psp_confirmation_id)
