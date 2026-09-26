"""Merchant gateway: merchant checkout issuance + TAP verification + merchant-side
mandate verification, then hand-off to the execution coordinator.

The gateway is the *merchant* verifier role (AP2 "Merchant", VI merchant /
L3b recipient). It never sees the payment-side presentation's private claims; it
forwards that presentation opaquely to the coordinator/payment verifier.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from aaw_ap2.receipts import receipt_error_code
from aaw_domain.artifacts import audit
from aaw_domain.bootstrap import CATALOG, merchant_record
from aaw_domain.checkout import build_checkout_jwt, checkout_hash
from aaw_domain.models import MerchantCheckout, Receipt, VerificationAttempt, new_id
from aaw_domain.outcomes import RULESET_VERSION, CheckStatus, Decision, Diagnostic, Reason, decide
from aaw_domain.profiles import Presentation, VerifyExpectations, get_profile
from aaw_domain.runtime import Runtime
from aaw_exec.receipts import sign_receipt
from aaw_tap import TapRequest, verify_tap_request


class GatewayError(Exception):
    def __init__(self, status_code: int, body: Dict[str, Any]):
        super().__init__(body.get("detail") or "gateway error")
        self.status_code = status_code
        self.body = body


class MerchantService:
    def __init__(self, rt: Runtime):
        self.rt = rt

    def catalog(self, merchant_id: str) -> List[Dict[str, Any]]:
        if merchant_id not in CATALOG:
            raise GatewayError(404, {"detail": "unknown merchant"})
        return CATALOG[merchant_id]

    def create_checkout(self, merchant_id: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        catalog = {p["id"]: p for p in self.catalog(merchant_id)}
        line_items = []
        for it in items:
            p = catalog.get(it["id"])
            if p is None:
                raise GatewayError(400, {"detail": f"unknown item {it['id']}"})
            line_items.append({"id": p["id"], "title": p["title"], "quantity": int(it.get("quantity", 1)),
                               "unit_price_minor": p["unit_price_minor"]})
        if not line_items:
            raise GatewayError(400, {"detail": "empty checkout"})
        merchant = merchant_record(merchant_id)
        handle = self.rt.keys.get(merchant_id)
        now = self.rt.now()
        checkout_id = new_id("co")
        jwt = build_checkout_jwt(handle, merchant, line_items, "USD", now, checkout_id=checkout_id)
        total = sum(li["quantity"] * li["unit_price_minor"] for li in line_items)
        with self.rt.session() as s:
            s.add(MerchantCheckout(id=checkout_id, merchant_id=merchant_id, checkout_jwt=jwt, checkout_hash=checkout_hash(jwt),
                                   total_minor=total, currency="USD", line_items_json=line_items, status="open",
                                   created_at=now, expires_at=now + 3600))
            audit(s, actor=f"merchant:{merchant_id}", action="CHECKOUT_CREATED", target_type="checkout",
                  target_id=checkout_id, clock=self.rt.clock, total_minor=total)
        return self.checkout_dict(checkout_id)

    def checkout_dict(self, checkout_id: str) -> Dict[str, Any]:
        with self.rt.session() as s:
            co = s.get(MerchantCheckout, checkout_id)
            if co is None:
                raise GatewayError(404, {"detail": "unknown checkout"})
            return {
                "checkout_id": co.id,
                "merchant": merchant_record(co.merchant_id),
                "checkout_jwt": co.checkout_jwt,
                "checkout_hash": co.checkout_hash,
                "total_minor": co.total_minor,
                "currency": co.currency,
                "line_items": co.line_items_json,
                "status": co.status,
                "order_id": co.order_id,
                "expires_at": co.expires_at,
            }


class GatewayService:
    def __init__(self, rt: Runtime, gateway_id: str, payment_audience: str,
                 coordinator_execute: Callable[[Dict[str, Any]], Dict[str, Any]]):
        self.rt = rt
        self.gateway_id = gateway_id
        self.payment_audience = payment_audience
        self.merchants = MerchantService(rt)
        self.coordinator_execute = coordinator_execute

    @property
    def handle(self):
        return self.rt.keys.get("merchant_gateway")

    def complete(self, checkout_id: str, req: TapRequest, body: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = body.get("trace_id") or f"trace_{uuid.uuid4().hex[:16]}"
        started = time.perf_counter()
        now = self.rt.now()
        diag = Diagnostic(trace_id=trace_id, profile=body.get("profile"))
        # The merchant's own decision only covers its role; binding to its checkout is
        # verified below, execution belongs to the coordinator.
        diag.execution_state = CheckStatus.NOT_APPLICABLE
        error: Optional[GatewayError] = None
        with self.rt.session() as s:
            trust = self.rt.trust(s)
            # 1. request authentication (TAP)
            tap = verify_tap_request(req, trust, s, now, required_tag="agent-payer-auth", trace_id=trace_id)
            diag.details["request_authentication"] = tap.to_dict()
            if not tap.ok:
                diag.request_authentication = CheckStatus.FAILED
                diag.add(tap.reason or Reason.REQUEST_SIGNATURE_INVALID, detail=tap.detail)
                decide(diag)
                self._record(s, diag, "gateway", None, checkout_id, started)
                audit(s, actor="gateway", action="REQUEST_REJECTED", target_type="checkout", target_id=checkout_id,
                      trace_id=trace_id, clock=self.rt.clock, reason=tap.reason.value if tap.reason else None)
                error = GatewayError(401, {"detail": "request authentication failed", "diagnostic": diag.to_dict()})
            else:
                diag.request_authentication = CheckStatus.VALID
        if error:
            raise error

        with self.rt.session() as s:
            trust = self.rt.trust(s)
            # 2. checkout
            co = s.get(MerchantCheckout, checkout_id)
            if co is None:
                raise GatewayError(404, {"detail": "unknown checkout", "diagnostic": diag.to_dict()})
            merchant = merchant_record(co.merchant_id)
            # A signed retry of an already completed checkout is still fully verified here; the
            # coordinator then returns the original outcome (idempotency by grant + checkout).
            if co.expires_at < now:
                diag.add(Reason.EXPIRED_AUTHORIZATION, detail="checkout expired")

            # 3. merchant-side mandate verification
            profile_name = body.get("profile")
            try:
                profile = get_profile(profile_name)
            except KeyError:
                diag.add(Reason.UNSUPPORTED_PROFILE)
                diag.delegation_verification = CheckStatus.FAILED
                decide(diag)
                self._record(s, diag, "merchant", None, checkout_id, started)
                error = GatewayError(400, {"detail": "unsupported profile", "diagnostic": diag.to_dict()})
            if error is None:
                mp = body.get("merchant_presentation") or {}
                presentation = Presentation(profile_name, profile.version, "merchant", mp, merchant["website"],
                                            tap.nonce or "", co.checkout_hash)
                expect = VerifyExpectations(role="merchant", audience=merchant["website"], now=now, nonce=tap.nonce,
                                            expected_checkout_jwt=co.checkout_jwt)
                pv = profile.verify(presentation, trust, expect, expected_intermediate_aud=f"urn:aaw:agent:{tap.agent_id}")
                diag.details["merchant_verification"] = {
                    "crypto_valid": pv.crypto_valid,
                    "protocol_valid": pv.protocol_valid,
                    "constraints": [c.__dict__ for c in pv.constraint_results],
                    "errors": pv.details.get("errors", []),
                    "mode": pv.mode,
                    "agent_key_thumbprint": pv.agent_key_thumbprint,
                }
                for r in pv.reasons:
                    diag.add(r)
                crypto_ok = pv.crypto_valid and pv.protocol_valid
                diag.delegation_verification = CheckStatus.VALID if crypto_ok else CheckStatus.FAILED
                diag.constraint_verification = CheckStatus.VALID if pv.constraints_satisfied else CheckStatus.FAILED
                diag.binding_verification = CheckStatus.VALID if (crypto_ok and pv.checkout_hash == co.checkout_hash) \
                    else CheckStatus.FAILED
                if not pv.constraints_satisfied:
                    for c in pv.constraint_results:
                        if not c.satisfied:
                            diag.add(_constraint_reason(c.type), constraint=c.type, detail=c.detail)
                decide(diag)
                self._record(s, diag, "merchant", body.get("grant_id"), checkout_id, started)
                if diag.decision != Decision.ALLOW:
                    receipt = self._error_receipt(s, profile_name, pv.final_artifact_hash, diag, trace_id)
                    co.status = "rejected"
                    audit(s, actor="gateway", action="CHECKOUT_MANDATE_REJECTED", target_type="checkout", target_id=co.id,
                          trace_id=trace_id, clock=self.rt.clock, reasons=diag.reason_codes)
                    error = GatewayError(403, {"detail": "checkout mandate rejected by merchant",
                                               "diagnostic": diag.to_dict(), "checkout_receipt": receipt})
        if error:
            raise error

        # 4. hand off to the coordinator (payment verifier + atomic claim + execution)
        forward = {
            "trace_id": trace_id,
            "grant_id": body.get("grant_id"),
            "profile": profile_name,
            "checkout_jwt": co.checkout_jwt,
            "checkout_id": co.id,
            "merchant_presentation": mp,
            "payment_presentation": body.get("payment_presentation") or {},
            "request_authentication": tap.to_dict(),
            "merchant_verification": diag.details["merchant_verification"],
            "merchant_final_artifact_hash": pv.final_artifact_hash,
            "fault": body.get("fault"),
        }
        result = self.coordinator_execute(forward)
        with self.rt.session() as s:
            co2 = s.get(MerchantCheckout, checkout_id)
            claim = result.get("claim") or {}
            if claim.get("state") == "consumed":
                co2.status = "completed"
                co2.order_id = claim.get("order_id")
            elif (result.get("diagnostic") or {}).get("decision") in ("DENY", "REQUIRE_NEW_AUTHORIZATION"):
                co2.status = "rejected"
            audit(s, actor="gateway", action="EXECUTION_RESULT", target_type="checkout", target_id=checkout_id,
                  trace_id=trace_id, clock=self.rt.clock, decision=result.get("diagnostic", {}).get("decision"))
        return result

    # -- helpers --------------------------------------------------------------

    def _record(self, s, diag: Diagnostic, role: str, grant_id: Optional[str], checkout_id: str, started: float) -> None:
        s.add(VerificationAttempt(
            id=new_id("ver"), grant_id=grant_id, checkout_reference=checkout_id, trace_id=diag.trace_id or "",
            verifier_role=role, profile=diag.profile, ruleset_version=RULESET_VERSION, decision=diag.decision.value,
            reason_codes=list(diag.reason_codes), diagnostic_json=diag.to_dict(),
            latency_ms=int((time.perf_counter() - started) * 1000), verified_at=self.rt.now(),
        ))

    def _error_receipt(self, s, profile: str, reference: Optional[str], diag: Diagnostic, trace_id: str) -> str:
        code = receipt_error_code(diag.reason_codes)
        token = sign_receipt(self.handle, self.gateway_id, profile, "checkout", reference or "", "Error", self.rt.now(),
                             error=code, error_description="; ".join(diag.reason_codes))
        s.add(Receipt(id=new_id("rcpt"), claim_id=f"none:{trace_id}", receipt_type="checkout", issuer_id=self.gateway_id,
                      status="Error", reference=reference or "", jwt=token, created_at=self.rt.now()))
        return token


def _constraint_reason(ctype: str) -> Reason:
    if "merchant" in ctype:
        return Reason.MERCHANT_NOT_ALLOWED
    if "line_items" in ctype:
        return Reason.SKU_NOT_ALLOWED
    return Reason.UNKNOWN_CONSTRAINT
