"""Execution coordinator (plan §15–16).

Grant lifecycle::

    active → claimed → consumed
    active → cancelled | expired
    claimed → execution_unknown → consumed | resolved_not_executed

* **Claim** is a compare-and-swap on ``authorization_grants (status, version)``:
  only one purchase can move a grant from ``active`` to ``claimed``. The claim
  row is committed *before* the processor is called, so a crash after that
  point leaves a durable reservation for the worker to reconcile.
* **Idempotency**: repeated delivery of the same business operation (same grant,
  same checkout) returns the existing claim. A transport replay never reaches
  the coordinator (TAP nonce records); a new purchase against a consumed or
  claimed grant fails the CAS with a distinct reason code.
* **After definitive non-execution** the profile rule decides whether the
  grant may be presented again (AP2: yes, after a rejection receipt; VI: no).
  The worker never silently resets a grant to reusable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from aaw_domain.artifacts import audit
from aaw_domain.clock import Clock, SystemClock
from aaw_domain.models import AuthorizationGrant, ExecutionClaim, PaymentAttempt, Receipt, new_id
from aaw_domain.outcomes import Decision, Diagnostic, Reason
from aaw_domain.profiles import CheckoutSummary, get_profile
from aaw_signer import KeyHandle

from .receipts import sign_receipt
from .simulator import PaymentSimulator, ResponseLost, WorkerCrash

STALE_CLAIM_SECONDS = 30


class ClaimConflict(Exception):
    def __init__(self, reason: Reason, grant_status: str):
        super().__init__(f"{reason.value} (grant status {grant_status})")
        self.reason = reason
        self.grant_status = grant_status


@dataclass
class ReceiptSigner:
    handle: KeyHandle
    issuer_id: str


@dataclass
class ReceiptSigners:
    checkout: ReceiptSigner  # merchant gateway
    payment: ReceiptSigner  # payment processor


def idempotency_key_for(grant_id: str, checkout_hash: str) -> str:
    return hashlib.sha256(f"{grant_id}|{checkout_hash}".encode("utf-8")).hexdigest()


class Coordinator:
    def __init__(self, signers: ReceiptSigners, clock: Optional[Clock] = None):
        self.signers = signers
        self.clock = clock or SystemClock()

    # -- lookup ---------------------------------------------------------------

    def existing_claim(self, session: Session, grant_id: str, checkout_hash: str) -> Optional[ExecutionClaim]:
        key = idempotency_key_for(grant_id, checkout_hash)
        return session.execute(select(ExecutionClaim).where(ExecutionClaim.idempotency_key == key)).scalar_one_or_none()

    # -- step 12: atomic reservation -----------------------------------------

    def claim(
        self,
        session: Session,
        grant: AuthorizationGrant,
        checkout: CheckoutSummary,
        diag: Diagnostic,
        trace_id: str,
        final_artifact_hashes: Dict[str, Optional[str]],
    ) -> ExecutionClaim:
        now = self.clock.now_ts()
        key = idempotency_key_for(grant.id, checkout.checkout_hash)
        result = session.execute(
            update(AuthorizationGrant)
            .where(
                AuthorizationGrant.id == grant.id,
                AuthorizationGrant.status == "active",
                AuthorizationGrant.version == grant.version,
                AuthorizationGrant.expires_at > now,
            )
            .values(status="claimed", version=grant.version + 1, updated_at=now)
        )
        if result.rowcount != 1:
            session.expire(grant)
            fresh = session.get(AuthorizationGrant, grant.id)
            status = fresh.status if fresh else "missing"
            reason = {
                "claimed": Reason.AUTHORIZATION_ALREADY_CLAIMED,
                "consumed": Reason.AUTHORIZATION_CONSUMED,
                "cancelled": Reason.AUTHORIZATION_CANCELLED,
                "expired": Reason.EXPIRED_AUTHORIZATION,
                "execution_unknown": Reason.EXECUTION_UNCERTAIN,
                "requires_new_authorization": Reason.AUTHORIZATION_REQUIRES_RENEWAL,
            }.get(status, Reason.AUTHORIZATION_ALREADY_CLAIMED)
            if fresh and fresh.status == "active" and fresh.expires_at <= now:
                reason = Reason.EXPIRED_AUTHORIZATION
            raise ClaimConflict(reason, status)
        claim = ExecutionClaim(
            id=new_id("exec"),
            grant_id=grant.id,
            checkout_digest=checkout.checkout_hash,
            checkout_reference=checkout.checkout_id,
            idempotency_key=key,
            state="claimed",
            trace_id=trace_id,
            profile=grant.profile,
            amount_minor=checkout.total_minor,
            currency=checkout.currency,
            payee_id=checkout.merchant["id"],
            decision=diag.decision.value,
            diagnostic_json=dict(diag.to_dict(), final_artifact_hashes=final_artifact_hashes),
            claimed_at=now,
        )
        session.add(claim)
        attempt = PaymentAttempt(
            id=new_id("pay"),
            claim_id=claim.id,
            idempotency_key=key,
            amount_minor=checkout.total_minor,
            currency=checkout.currency,
            payee_id=checkout.merchant["id"],
            state="submitted",
            created_at=now,
            updated_at=now,
        )
        session.add(attempt)
        claim.payment_attempt_id = attempt.id
        grant.status = "claimed"
        grant.version = grant.version + 1
        audit(session, actor="coordinator", action="EXECUTION_CLAIMED", target_type="grant", target_id=grant.id,
              trace_id=trace_id, clock=self.clock, claim_id=claim.id, checkout_hash=checkout.checkout_hash)
        session.flush()
        return claim

    # -- execution -------------------------------------------------------------

    def execute(self, session: Session, claim: ExecutionClaim, fault: Optional[str] = None) -> ExecutionClaim:
        """Run the payment for a persisted claim. Must be called in a fresh transaction
        after the claim was committed."""
        now = self.clock.now_ts()
        grant = session.get(AuthorizationGrant, claim.grant_id)
        attempt = session.get(PaymentAttempt, claim.payment_attempt_id)
        sim = PaymentSimulator(session, self.clock)
        claim.state = "executing"
        session.flush()
        try:
            result = sim.execute(claim.idempotency_key, claim.amount_minor, claim.currency, claim.payee_id, fault=fault)
        except WorkerCrash:
            # Leave the durable reservation as-is; the worker will find the stale claim.
            claim.state = "claimed"
            session.flush()
            raise
        except ResponseLost:
            claim.state = "execution_unknown"
            attempt.state = "unknown"
            attempt.fault = fault
            attempt.updated_at = now
            grant.status = "execution_unknown"
            grant.version += 1
            grant.updated_at = now
            audit(session, actor="coordinator", action="EXECUTION_UNKNOWN", target_type="claim", target_id=claim.id,
                  trace_id=claim.trace_id, clock=self.clock, fault=fault)
            session.flush()
            return claim
        attempt.fault = fault
        self._settle(session, claim, grant, attempt, result.status, result.psp_confirmation_id)
        return claim

    def _settle(self, session: Session, claim: ExecutionClaim, grant: AuthorizationGrant, attempt: PaymentAttempt,
                status: str, psp_confirmation_id: Optional[str]) -> None:
        now = self.clock.now_ts()
        hashes = (claim.diagnostic_json or {}).get("final_artifact_hashes", {}) or {}
        if status == "succeeded":
            attempt.state = "succeeded"
            attempt.psp_confirmation_id = psp_confirmation_id
            claim.state = "consumed"
            claim.order_id = new_id("order")
            grant.status = "consumed"
            action = "EXECUTION_CONSUMED"
            self._receipt(session, claim, "checkout", hashes.get("merchant"), "Success", order_id=claim.order_id)
            self._receipt(session, claim, "payment", hashes.get("payment"), "Success",
                          payment_id=attempt.id, psp_confirmation_id=psp_confirmation_id)
        else:
            attempt.state = "declined" if status == "declined" else "not_executed"
            claim.state = "resolved_not_executed"
            action = "EXECUTION_NOT_EXECUTED"
            self._receipt(session, claim, "checkout", hashes.get("merchant"), "Error", error="invalid_mandate",
                          error_description="payment was not executed" if status != "declined" else "payment declined")
            self._receipt(session, claim, "payment", hashes.get("payment"), "Error", payment_id=attempt.id,
                          error="payment_declined" if status == "declined" else "not_executed",
                          error_description="processor declined" if status == "declined" else "definitive non-execution")
            profile = get_profile(claim.profile)
            if profile.reuse_after_rejection_allowed():
                grant.status = "active"  # AP2: rejection receipt issued → agent may present again
                audit(session, actor="coordinator", action="REPRESENTATION_PERMITTED_AFTER_REJECTION_RECEIPT",
                      target_type="grant", target_id=grant.id, trace_id=claim.trace_id, clock=self.clock,
                      profile=claim.profile)
            else:
                grant.status = "requires_new_authorization"  # VI: one L3 pair per mandate pair
                audit(session, actor="coordinator", action="NEW_AUTHORIZATION_REQUIRED", target_type="grant",
                      target_id=grant.id, trace_id=claim.trace_id, clock=self.clock, profile=claim.profile)
        attempt.updated_at = now
        claim.resolved_at = now
        grant.version += 1
        grant.updated_at = now
        audit(session, actor="coordinator", action=action, target_type="claim", target_id=claim.id,
              trace_id=claim.trace_id, clock=self.clock, payment_state=attempt.state)
        session.flush()

    def _receipt(self, session: Session, claim: ExecutionClaim, kind: str, reference: Optional[str], status: str,
                 **kw: Any) -> None:
        signer = self.signers.checkout if kind == "checkout" else self.signers.payment
        token = sign_receipt(signer.handle, signer.issuer_id, claim.profile, kind, reference or "", status,
                             self.clock.now_ts(), **kw)
        session.add(Receipt(id=new_id("rcpt"), claim_id=claim.id, receipt_type=kind, issuer_id=signer.issuer_id,
                            status=status, reference=reference or "", jwt=token, created_at=self.clock.now_ts()))

    # -- reconciliation -------------------------------------------------------

    def reconcile(self, session: Session, claim: ExecutionClaim, force_not_executed: bool = False) -> ExecutionClaim:
        """Resolve a claim whose outcome is uncertain by asking the processor ledger."""
        grant = session.get(AuthorizationGrant, claim.grant_id)
        attempt = session.get(PaymentAttempt, claim.payment_attempt_id)
        sim = PaymentSimulator(session, self.clock)
        entry = sim.lookup(claim.idempotency_key)
        if entry is not None:
            self._settle(session, claim, grant, attempt, entry.status, entry.psp_confirmation_id)
            audit(session, actor="worker", action="RECONCILED_FROM_LEDGER", target_type="claim", target_id=claim.id,
                  trace_id=claim.trace_id, clock=self.clock, ledger_status=entry.status)
            return claim
        age = self.clock.now_ts() - claim.claimed_at
        if force_not_executed or age > STALE_CLAIM_SECONDS:
            self._settle(session, claim, grant, attempt, "not_executed", None)
            audit(session, actor="worker", action="RECONCILED_NOT_EXECUTED", target_type="claim", target_id=claim.id,
                  trace_id=claim.trace_id, clock=self.clock, age_seconds=age)
        return claim

    # -- cancellation ---------------------------------------------------------

    def cancel(self, session: Session, grant: AuthorizationGrant, actor: str, trace_id: str) -> Dict[str, Any]:
        """Cancellation is serialised with claiming through the same CAS on the grant row."""
        now = self.clock.now_ts()
        result = session.execute(
            update(AuthorizationGrant)
            .where(AuthorizationGrant.id == grant.id, AuthorizationGrant.status == "active",
                   AuthorizationGrant.version == grant.version)
            .values(status="cancelled", cancelled_at=now, version=grant.version + 1, updated_at=now)
        )
        session.expire(grant)
        fresh = session.get(AuthorizationGrant, grant.id)
        if result.rowcount == 1:
            audit(session, actor=actor, action="GRANT_CANCELLED", target_type="grant", target_id=grant.id,
                  trace_id=trace_id, clock=self.clock)
            return {"status": "cancelled", "outcome": "cancelled_before_execution"}
        if fresh.status in ("claimed", "execution_unknown"):
            audit(session, actor=actor, action="CANCELLATION_PENDING", target_type="grant", target_id=grant.id,
                  trace_id=trace_id, clock=self.clock, grant_status=fresh.status)
            return {"status": fresh.status, "outcome": "cancellation_pending",
                    "note": "submission has begun; cancellation stops future use but cannot reverse an accepted payment"}
        return {"status": fresh.status, "outcome": "not_cancellable", "note": f"grant is already {fresh.status}"}


def decision_for_conflict(reason: Reason) -> Decision:
    if reason == Reason.EXECUTION_UNCERTAIN:
        return Decision.RECONCILIATION_REQUIRED
    if reason in (Reason.AUTHORIZATION_CONSUMED, Reason.EXPIRED_AUTHORIZATION, Reason.AUTHORIZATION_REQUIRES_RENEWAL):
        return Decision.REQUIRE_NEW_AUTHORIZATION
    return Decision.DENY
