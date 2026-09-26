"""Payment-side verification + execution coordination (plan §11, §15).

``execute`` is called by the merchant gateway after request authentication and
merchant-side verification succeeded. The coordinator independently re-verifies
both role views (a gateway bug must not become a payment), evaluates
application policy against the grant, then reserves and executes.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from aaw_domain.artifacts import ArtifactVault, audit
from aaw_domain.checkout import CheckoutError, parse_checkout_jwt
from aaw_domain.models import (
    AuditEvent,
    AuthorizationGrant,
    ExecutionClaim,
    PaymentAttempt,
    Receipt,
    VerificationAttempt,
    new_id,
)
from aaw_domain.outcomes import RULESET_VERSION, CheckStatus, Decision, Diagnostic, Reason, decide
from aaw_domain.pipeline import check_input_limits, evaluate
from aaw_domain.profiles import Presentation, VerifyExpectations, get_profile
from aaw_exec import ClaimConflict, WorkerCrash, decision_for_conflict

from ..context import AppContext
from .consent import ServiceError, grant_dict

STATE_ONLY_REASONS = {
    Reason.AUTHORIZATION_CONSUMED.value,
    Reason.AUTHORIZATION_ALREADY_CLAIMED.value,
    Reason.EXECUTION_UNCERTAIN.value,
    Reason.AUTHORIZATION_REQUIRES_RENEWAL.value,
}


def claim_dict(c: ExecutionClaim, attempt: Optional[PaymentAttempt] = None) -> Dict[str, Any]:
    d = {
        "id": c.id,
        "grant_id": c.grant_id,
        "state": c.state,
        "checkout_digest": c.checkout_digest,
        "checkout_reference": c.checkout_reference,
        "idempotency_key": c.idempotency_key,
        "profile": c.profile,
        "amount_minor": c.amount_minor,
        "currency": c.currency,
        "payee_id": c.payee_id,
        "decision": c.decision,
        "trace_id": c.trace_id,
        "order_id": c.order_id,
        "claimed_at": c.claimed_at,
        "resolved_at": c.resolved_at,
    }
    if attempt is not None:
        d["payment_attempt"] = {"id": attempt.id, "state": attempt.state, "psp_confirmation_id": attempt.psp_confirmation_id,
                                "fault": attempt.fault, "updated_at": attempt.updated_at}
    return d


class ExecutionService:
    def __init__(self, ctx: AppContext):
        self.ctx = ctx

    # -- verification (shared by dry-run and execution) ----------------------

    def _verify(self, s, payload: Dict[str, Any], diag: Diagnostic):
        now = self.ctx.rt.now()
        trust = self.ctx.rt.trust(s)
        limit = check_input_limits(payload)
        if limit:
            diag.add(limit)
            return None, None, None, None
        profile_name = payload.get("profile")
        try:
            profile = get_profile(profile_name)
        except KeyError:
            diag.add(Reason.UNSUPPORTED_PROFILE)
            return None, None, None, None
        diag.profile = profile.name
        diag.profile_version = profile.version
        grant = s.get(AuthorizationGrant, payload.get("grant_id") or "")
        try:
            checkout = parse_checkout_jwt(payload["checkout_jwt"], trust, now)
        except (CheckoutError, KeyError) as exc:
            diag.add(getattr(exc, "reason", Reason.MALFORMED_ARTIFACT), detail=str(exc))
            return profile, grant, None, None
        tap = payload.get("request_authentication") or {}
        nonce = tap.get("nonce")
        agent_aud = self.ctx.agent_audience(tap.get("agent_id") or (grant.agent_id if grant else ""))
        mpres = Presentation(profile.name, profile.version, "merchant", payload.get("merchant_presentation") or {},
                             checkout.merchant.get("website", ""), nonce or "", checkout.checkout_hash)
        ppres = Presentation(profile.name, profile.version, "payment", payload.get("payment_presentation") or {},
                             self.ctx.settings.payment_audience, nonce or "", checkout.checkout_hash)
        mpv = profile.verify(mpres, trust, VerifyExpectations("merchant", checkout.merchant.get("website", ""), now, nonce=nonce,
                                                              expected_checkout_jwt=checkout.checkout_jwt),
                             expected_intermediate_aud=agent_aud)
        ppv = profile.verify(ppres, trust, VerifyExpectations("payment", self.ctx.settings.payment_audience, now, nonce=nonce,
                                                              expected_checkout_hash=checkout.checkout_hash),
                             expected_intermediate_aud=agent_aud)
        # Request authentication (performed by the gateway; reported here for the unified diagnostic)
        if tap:
            diag.request_authentication = CheckStatus.VALID if tap.get("ok") else CheckStatus.FAILED
            if not tap.get("ok"):
                diag.add(Reason(tap["reason"]) if tap.get("reason") in Reason.__members__ else Reason.REQUEST_SIGNATURE_INVALID)
            diag.details["request_authentication"] = tap
            if grant is not None and tap.get("agent_id") and tap.get("agent_id") != grant.agent_id:
                diag.add(Reason.AGENT_KEY_MISMATCH, detail="TAP key belongs to a different agent than the grant delegate")
        else:
            diag.request_authentication = CheckStatus.SKIPPED
        # Direct mode: the user-signed closed mandate must carry the consent nonce of this grant.
        if grant is not None and grant.mode == "direct":
            summary = _grant_summary(s, self.ctx, grant.id)
            expected_nonce = (summary or {}).get("consent_nonce")
            for pv in (mpv, ppv):
                if expected_nonce and pv.details.get("final_nonce") != expected_nonce:
                    pv.fail(Reason.NONCE_MISMATCH, "closed mandate nonce is not this grant's consent nonce")
                    pv.protocol_valid = False
        evaluate(diag, grant=grant, merchant_pv=mpv, payment_pv=ppv, checkout=checkout, now=now, profile=profile.name)
        return profile, grant, checkout, (mpv, ppv)

    def verify_only(self, payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
        started = time.perf_counter()
        trace_id = payload.get("trace_id") or new_id("trace")
        diag = Diagnostic(trace_id=trace_id)
        with self.ctx.rt.session() as s:
            _, grant, checkout, _ = self._verify(s, payload, diag)
            if diag.decision == Decision.DENY and not diag.reason_codes:
                decide(diag)
            s.add(VerificationAttempt(id=new_id("ver"), grant_id=grant.id if grant else None,
                                      checkout_reference=checkout.checkout_id if checkout else None, trace_id=trace_id,
                                      verifier_role="dry-run", profile=diag.profile, ruleset_version=RULESET_VERSION,
                                      decision=diag.decision.value, reason_codes=list(diag.reason_codes),
                                      diagnostic_json=diag.to_dict(), latency_ms=int((time.perf_counter() - started) * 1000),
                                      verified_at=self.ctx.rt.now()))
            audit(s, actor=actor, action="VERIFICATION_DRY_RUN", target_type="grant", target_id=grant.id if grant else "-",
                  trace_id=trace_id, clock=self.ctx.clock, decision=diag.decision.value)
        return {"trace_id": trace_id, "diagnostic": diag.to_dict(), "dry_run": True}

    # -- execution -------------------------------------------------------------

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        started = time.perf_counter()
        trace_id = payload.get("trace_id") or new_id("trace")
        fault = payload.get("fault") or self.ctx.rt.faults.get("payment")
        diag = Diagnostic(trace_id=trace_id)
        with self.ctx.rt.session() as s:
            profile, grant, checkout, pvs = self._verify(s, payload, diag)
            if diag.decision == Decision.DENY and not diag.reason_codes:
                decide(diag)
            # Repeated delivery / signed retry of the same business operation → existing result,
            # provided the fresh presentation itself is sound (only grant-state reasons may fail).
            if grant is not None and checkout is not None:
                existing = self.ctx.coordinator.existing_claim(s, grant.id, checkout.checkout_hash)
                if existing is not None and set(diag.reason_codes) <= STATE_ONLY_REASONS:
                    audit(s, actor="coordinator", action="IDEMPOTENT_REPLAY", target_type="claim", target_id=existing.id,
                          trace_id=trace_id, clock=self.ctx.clock)
                    return self._result(s, existing, trace_id, idempotent=True)
            self._record(s, diag, grant, checkout, started, claim_id=None)
            if diag.decision != Decision.ALLOW:
                audit(s, actor="coordinator", action="EXECUTION_REFUSED", target_type="grant",
                      target_id=grant.id if grant else "-", trace_id=trace_id, clock=self.ctx.clock,
                      decision=diag.decision.value, reasons=diag.reason_codes)
                return {"trace_id": trace_id, "diagnostic": diag.to_dict(), "claim": None, "receipts": {}}
            mpv, ppv = pvs
            try:
                claim = self.ctx.coordinator.claim(
                    s, grant, checkout, diag, trace_id,
                    {"merchant": mpv.final_artifact_hash, "payment": ppv.final_artifact_hash},
                )
            except ClaimConflict as exc:
                diag.add(exc.reason, grant_status=exc.grant_status)
                diag.execution_state = CheckStatus.FAILED
                diag.decision = decision_for_conflict(exc.reason)
                audit(s, actor="coordinator", action="CLAIM_CONFLICT", target_type="grant", target_id=grant.id,
                      trace_id=trace_id, clock=self.ctx.clock, reason=exc.reason.value)
                return {"trace_id": trace_id, "diagnostic": diag.to_dict(), "claim": None, "receipts": {}}
            vault = ArtifactVault(s, self.ctx.clock)
            vault.store(artifact_type="merchant_presentation", profile=profile.name, issuer_id=grant.agent_id,
                        obj=payload.get("merchant_presentation") or {}, allowed_reader_roles=["merchant", "auditor"],
                        grant_id=grant.id, claim_id=claim.id)
            vault.store(artifact_type="payment_presentation", profile=profile.name, issuer_id=grant.agent_id,
                        obj=payload.get("payment_presentation") or {}, allowed_reader_roles=["payment", "auditor"],
                        grant_id=grant.id, claim_id=claim.id)
            vault.store(artifact_type="checkout_jwt", profile=profile.name, issuer_id=checkout.merchant["id"],
                        obj=checkout.checkout_jwt, allowed_reader_roles=["merchant", "payment", "user", "auditor"],
                        grant_id=grant.id, claim_id=claim.id)
            claim_id = claim.id
        # Reservation committed. Execute in a fresh transaction.
        try:
            with self.ctx.rt.session() as s:
                claim = s.get(ExecutionClaim, claim_id)
                self.ctx.coordinator.execute(s, claim, fault=fault)
        except WorkerCrash:
            with self.ctx.rt.session() as s:
                audit(s, actor="coordinator", action="WORKER_CRASH_SIMULATED", target_type="claim", target_id=claim_id,
                      trace_id=trace_id, clock=self.ctx.clock)
        with self.ctx.rt.session() as s:
            claim = s.get(ExecutionClaim, claim_id)
            return self._result(s, claim, trace_id, idempotent=False)

    def _result(self, s, claim: ExecutionClaim, trace_id: str, idempotent: bool) -> Dict[str, Any]:
        attempt = s.get(PaymentAttempt, claim.payment_attempt_id) if claim.payment_attempt_id else None
        receipts = {r.receipt_type: r.jwt for r in s.execute(select(Receipt).where(Receipt.claim_id == claim.id)).scalars()}
        diag = dict(claim.diagnostic_json)
        if claim.state in ("execution_unknown", "claimed", "executing"):
            diag["decision"] = Decision.RECONCILIATION_REQUIRED.value
            diag["execution_state"] = CheckStatus.FAILED.value
            if Reason.EXECUTION_UNCERTAIN.value not in diag.get("reason_codes", []):
                diag.setdefault("reason_codes", []).append(Reason.EXECUTION_UNCERTAIN.value)
        elif claim.state == "resolved_not_executed":
            diag["decision"] = Decision.ALLOW.value
            diag["execution_outcome"] = "not_executed"
        elif claim.state == "consumed":
            diag["execution_outcome"] = "executed"
        diag["trace_id"] = trace_id
        return {"trace_id": trace_id, "diagnostic": diag, "claim": claim_dict(claim, attempt), "receipts": receipts,
                "idempotent_replay": idempotent}

    def _record(self, s, diag: Diagnostic, grant, checkout, started: float, claim_id: Optional[str]) -> None:
        s.add(VerificationAttempt(
            id=new_id("ver"), grant_id=grant.id if grant else None, claim_id=claim_id,
            checkout_reference=checkout.checkout_id if checkout else None, trace_id=diag.trace_id or "",
            verifier_role="coordinator", profile=diag.profile, ruleset_version=RULESET_VERSION,
            decision=diag.decision.value, reason_codes=list(diag.reason_codes), diagnostic_json=diag.to_dict(),
            latency_ms=int((time.perf_counter() - started) * 1000), verified_at=self.ctx.rt.now(),
        ))

    # -- reads -----------------------------------------------------------------

    def get(self, claim_id: str, principal_kind: str, principal_id: str) -> Dict[str, Any]:
        with self.ctx.rt.session() as s:
            claim = s.get(ExecutionClaim, claim_id)
            if claim is None:
                raise ServiceError(404, "execution not found")
            grant = s.get(AuthorizationGrant, claim.grant_id)
            self._authorize(grant, principal_kind, principal_id)
            res = self._result(s, claim, claim.trace_id, idempotent=False)
            res["grant"] = grant_dict(grant)
            res["verification_attempts"] = [
                {"id": v.id, "role": v.verifier_role, "decision": v.decision, "reason_codes": v.reason_codes,
                 "latency_ms": v.latency_ms, "verified_at": v.verified_at, "ruleset_version": v.ruleset_version}
                for v in s.execute(select(VerificationAttempt).where(VerificationAttempt.trace_id == claim.trace_id)
                                   .order_by(VerificationAttempt.verified_at)).scalars()
            ]
            return res

    def list(self, principal_kind: str, principal_id: str) -> List[Dict[str, Any]]:
        with self.ctx.rt.session() as s:
            col = AuthorizationGrant.user_id if principal_kind == "user" else AuthorizationGrant.agent_id
            grant_ids = [g.id for g in s.execute(select(AuthorizationGrant).where(col == principal_id)).scalars()]
            if principal_kind == "gateway":
                rows = s.execute(select(ExecutionClaim).order_by(ExecutionClaim.claimed_at.desc())).scalars()
            else:
                rows = s.execute(select(ExecutionClaim).where(ExecutionClaim.grant_id.in_(grant_ids))
                                 .order_by(ExecutionClaim.claimed_at.desc())).scalars()
            return [claim_dict(c, s.get(PaymentAttempt, c.payment_attempt_id) if c.payment_attempt_id else None)
                    for c in rows]

    def evidence(self, claim_id: str, role: str, principal_kind: str, principal_id: str) -> Dict[str, Any]:
        if role not in ("merchant", "payment", "user", "auditor"):
            raise ServiceError(400, "role must be merchant, payment, user or auditor")
        with self.ctx.rt.session() as s:
            claim = s.get(ExecutionClaim, claim_id)
            if claim is None:
                raise ServiceError(404, "execution not found")
            grant = s.get(AuthorizationGrant, claim.grant_id)
            self._authorize(grant, principal_kind, principal_id)
            vault = ArtifactVault(s, self.ctx.clock)
            profile = get_profile(claim.profile)
            out: Dict[str, Any] = {"claim_id": claim.id, "role": role, "profile": claim.profile,
                                   "profile_version": profile.version, "artifacts": {}, "receipts": {}}
            for art in vault.for_claim(claim.id) + vault.for_grant(grant.id):
                if role not in art.allowed_reader_roles:
                    continue
                obj = vault.load(art, role)
                if art.artifact_type in ("merchant_presentation", "payment_presentation"):
                    pres_role = "merchant" if art.artifact_type.startswith("merchant") else "payment"
                    pres = Presentation(claim.profile, profile.version, pres_role, obj, "", "")
                    out["artifacts"][art.artifact_type] = profile.evidence_view(pres)
                else:
                    out["artifacts"][art.artifact_type] = obj
            for r in s.execute(select(Receipt).where(Receipt.claim_id == claim.id)).scalars():
                if role == "merchant" and r.receipt_type != "checkout":
                    continue
                if role == "payment" and r.receipt_type != "payment":
                    continue
                out["receipts"][r.receipt_type] = {"jwt": r.jwt, "status": r.status, "reference": r.reference,
                                                   "issuer": r.issuer_id, "decoded": _decode(r.jwt)}
            diag = dict(claim.diagnostic_json)
            details = diag.get("details", {})
            if role == "merchant":
                diag["details"] = {k: v for k, v in details.items() if k in ("merchant_view", "request_authentication")}
            elif role == "payment":
                diag["details"] = {k: v for k, v in details.items() if k in ("payment_view",)}
            out["diagnostic"] = diag
            if role in ("user", "auditor"):
                out["grant"] = grant_dict(grant)
            if role == "auditor":
                out["audit_events"] = [
                    {"actor": e.actor, "action": e.action, "target": f"{e.target_type}:{e.target_id}", "at": e.at,
                     "details": e.details_json}
                    for e in s.execute(select(AuditEvent).where((AuditEvent.trace_id == claim.trace_id) |
                                                                (AuditEvent.target_id == grant.id))
                                       .order_by(AuditEvent.at)).scalars()
                ]
            out["explanation"] = _explanations(role)
            return out

    @staticmethod
    def _authorize(grant, principal_kind: str, principal_id: str) -> None:
        if principal_kind == "user" and grant.user_id != principal_id:
            raise ServiceError(403, "execution belongs to another user")
        if principal_kind == "agent" and grant.agent_id != principal_id:
            raise ServiceError(403, "execution belongs to another agent")


def _grant_summary(s, ctx: AppContext, grant_id: str) -> Optional[Dict[str, Any]]:
    try:
        return ArtifactVault(s, ctx.clock).load_type(grant_id, "grant_summary", "system")
    except KeyError:
        return None


def _decode(jwt: str) -> Dict[str, Any]:
    from aaw_signer import peek_header, peek_payload

    try:
        return {"header": peek_header(jwt), "payload": peek_payload(jwt)}
    except Exception:  # pragma: no cover
        return {}


def _explanations(role: str) -> str:
    return {
        "merchant": "The merchant receives the checkout mandate chain: the merchant-signed checkout it issued, the user's "
                    "delegation to this agent (only this merchant revealed from the allowed set), and the checkout receipt. "
                    "It does not receive the spending cap, other permitted merchants or the payment instrument.",
        "payment": "The payment verifier receives the payment mandate chain: the exact amount, payee, instrument reference and "
                   "checkout hash, plus the payment receipt. It does not receive line items or the merchant-signed checkout.",
        "user": "The user view shows the reviewed consent snapshot, the resulting grant and both receipts.",
        "auditor": "The auditor view shows every artifact and the audit trail. Signatures prove who authorized what; they do "
                   "not prove the merchant's product description was truthful or that goods were delivered.",
    }[role]
