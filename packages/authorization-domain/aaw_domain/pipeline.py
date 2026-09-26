"""Deterministic verification pipeline (plan §11), profile-agnostic parts.

The profile adapters perform steps 3-8 for their own artifacts (signatures,
disclosures, key binding, mandate rules). This module performs the steps that
belong to the application:

* profile / mode identification and size limits
* application copies of amount, merchant, payee and SKU constraints
* checkout ↔ payment binding across the two role views
* grant state (expiry, cancellation, claim state) with an injected clock

The result is a :class:`Diagnostic`; the execution coordinator performs the
atomic reservation (step 12) only for ``ALLOW``.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional

from .constraints import GrantConstraints
from .models import AuthorizationGrant
from .outcomes import CheckStatus, Decision, Diagnostic, Reason, decide
from .profiles import CheckoutSummary, ProfileVerification

MAX_PRESENTATION_BYTES = 512 * 1024
SUPPORTED_PROFILES = {"ap2", "vi"}


def check_input_limits(payload: Dict[str, Any]) -> Optional[Reason]:
    import json

    size = len(json.dumps(payload))
    if size > MAX_PRESENTATION_BYTES:
        return Reason.INPUT_TOO_LARGE
    return None


def line_items_satisfy(requirements: List[Dict[str, Any]], checkout_items: List[Dict[str, Any]]) -> bool:
    """AP2 ``checkout.line_items`` evaluation: every requirement is met by distinct
    checkout items whose id is in its acceptable set, and no checkout item is left
    over. Implemented as exhaustive assignment (small inputs; a max-flow gives the
    same answer)."""
    units: List[str] = []
    for it in checkout_items:
        units.extend([str(it.get("id"))] * int(it.get("quantity", 1)))
    slots: List[set] = []
    for req in requirements:
        acceptable = {str(a.get("id")) for a in req.get("acceptable_items", []) if isinstance(a, dict) and "id" in a}
        slots.extend([acceptable] * int(req.get("quantity", 1)))
    if len(units) != len(slots):
        return False
    if len(units) > 8:
        # Greedy bipartite matching for larger inputs (Kuhn's algorithm).
        match: Dict[int, int] = {}

        def try_slot(u: int, seen: set) -> bool:
            for s, acc in enumerate(slots):
                if units[u] in acc and s not in seen:
                    seen.add(s)
                    if s not in match or try_slot(match[s], seen):
                        match[s] = u
                        return True
            return False

        return all(try_slot(u, set()) for u in range(len(units)))
    for perm in itertools.permutations(range(len(units))):
        if all(units[perm[i]] in slots[i] for i in range(len(slots))):
            return True
    return False


def grant_state_reason(grant: AuthorizationGrant, now: int) -> Optional[Reason]:
    if grant.status == "cancelled":
        return Reason.AUTHORIZATION_CANCELLED
    if grant.status == "consumed":
        return Reason.AUTHORIZATION_CONSUMED
    if grant.status == "claimed":
        return Reason.AUTHORIZATION_ALREADY_CLAIMED
    if grant.status == "execution_unknown":
        return Reason.EXECUTION_UNCERTAIN
    if grant.status == "requires_new_authorization":
        return Reason.AUTHORIZATION_REQUIRES_RENEWAL
    if grant.status == "expired" or now >= grant.expires_at:
        return Reason.EXPIRED_AUTHORIZATION
    if now < grant.not_before:
        return Reason.AUTHORIZATION_NOT_YET_VALID
    if grant.status != "active":
        return Reason.GRANT_NOT_FOUND
    return None


def evaluate(
    diag: Diagnostic,
    *,
    grant: Optional[AuthorizationGrant],
    merchant_pv: ProfileVerification,
    payment_pv: ProfileVerification,
    checkout: CheckoutSummary,
    now: int,
    profile: str,
) -> Diagnostic:
    """Combine protocol verification with application policy and grant state."""

    # ---- delegation (cryptographic + protocol) -----------------------------
    crypto_ok = merchant_pv.crypto_valid and payment_pv.crypto_valid
    protocol_ok = merchant_pv.protocol_valid and payment_pv.protocol_valid
    for r in merchant_pv.reasons + payment_pv.reasons:
        diag.add(r)
    diag.delegation_verification = CheckStatus.VALID if (crypto_ok and protocol_ok) else CheckStatus.FAILED
    diag.details["merchant_view"] = {
        "crypto_valid": merchant_pv.crypto_valid,
        "protocol_valid": merchant_pv.protocol_valid,
        "constraints": [c.__dict__ for c in merchant_pv.constraint_results],
        "errors": merchant_pv.details.get("errors", []),
    }
    diag.details["payment_view"] = {
        "crypto_valid": payment_pv.crypto_valid,
        "protocol_valid": payment_pv.protocol_valid,
        "constraints": [c.__dict__ for c in payment_pv.constraint_results],
        "errors": payment_pv.details.get("errors", []),
    }

    if profile not in SUPPORTED_PROFILES:
        diag.add(Reason.UNSUPPORTED_PROFILE)

    # ---- grant state -------------------------------------------------------
    if grant is None:
        diag.add(Reason.GRANT_NOT_FOUND)
        diag.execution_state = CheckStatus.FAILED
    else:
        if grant.profile != profile:
            diag.add(Reason.PROFILE_MISMATCH, grant=grant.profile, presented=profile)
        state_reason = grant_state_reason(grant, now)
        if state_reason:
            diag.add(state_reason, status=grant.status, expires_at=grant.expires_at, now=now)
            diag.execution_state = CheckStatus.FAILED
        else:
            diag.execution_state = CheckStatus.VALID
        if merchant_pv.mode and merchant_pv.mode != grant.mode:
            diag.add(Reason.MODE_MISMATCH, grant=grant.mode, presented=merchant_pv.mode)
        # agent key binding: the closed mandates must be signed by the key the user delegated to
        if grant.mode == "autonomous":
            for pv in (merchant_pv, payment_pv):
                if pv.agent_key_thumbprint and pv.agent_key_thumbprint != grant.agent_key_thumbprint:
                    diag.add(Reason.AGENT_KEY_MISMATCH)
        if grant.mode == "direct" and grant.bound_checkout_digest and grant.bound_checkout_digest != checkout.checkout_hash:
            diag.add(Reason.DIRECT_CHECKOUT_MISMATCH)

    # ---- binding -----------------------------------------------------------
    binding_ok = True
    if merchant_pv.checkout_hash != checkout.checkout_hash:
        diag.add(Reason.CHECKOUT_BINDING_MISMATCH, mandate=merchant_pv.checkout_hash, checkout=checkout.checkout_hash)
        binding_ok = False
    if payment_pv.transaction_id != checkout.checkout_hash:
        diag.add(Reason.PAYMENT_BINDING_MISMATCH, mandate=payment_pv.transaction_id, checkout=checkout.checkout_hash)
        binding_ok = False
    if payment_pv.reference_digest and merchant_pv.open_mandate_digest:
        if payment_pv.reference_digest != merchant_pv.open_mandate_digest:
            diag.add(Reason.REFERENCE_MISMATCH)
            binding_ok = False
    if payment_pv.amount_minor is not None and payment_pv.amount_minor != checkout.total_minor:
        diag.add(Reason.PAYMENT_BINDING_MISMATCH, payment_amount=payment_pv.amount_minor, checkout_total=checkout.total_minor)
        binding_ok = False
    if payment_pv.currency and payment_pv.currency != checkout.currency:
        diag.add(Reason.CURRENCY_MISMATCH)
        binding_ok = False
    if payment_pv.payee and payment_pv.payee.get("id") != checkout.merchant.get("id"):
        diag.add(Reason.PAYEE_MISMATCH, payee=payment_pv.payee.get("id"), merchant=checkout.merchant.get("id"))
        binding_ok = False
    diag.binding_verification = CheckStatus.VALID if binding_ok else CheckStatus.FAILED

    # ---- constraints (protocol results + application copy) ----------------
    constraints_ok = merchant_pv.constraints_satisfied and payment_pv.constraints_satisfied
    for c in merchant_pv.constraint_results + payment_pv.constraint_results:
        if not c.satisfied:
            diag.add(_constraint_reason(c.type), constraint=c.type, detail=c.detail)

    diag.evaluated_total_minor = str(checkout.total_minor)
    diag.currency = checkout.currency
    if grant is not None:
        gc = GrantConstraints.model_validate(grant.constraints_json)
        diag.authorized_max_minor = gc.max_total_minor
        if checkout.currency != gc.currency:
            diag.add(Reason.CURRENCY_MISMATCH, grant=gc.currency, checkout=checkout.currency)
            constraints_ok = False
        if checkout.total_minor > gc.max_minor:
            diag.add(Reason.DELIVERED_TOTAL_EXCEEDS_LIMIT)
            constraints_ok = False
        if checkout.total_minor < gc.min_minor:
            diag.add(Reason.AMOUNT_BELOW_MINIMUM)
            constraints_ok = False
        if checkout.merchant.get("id") not in gc.merchant_ids():
            diag.add(Reason.MERCHANT_NOT_ALLOWED, merchant=checkout.merchant.get("id"))
            constraints_ok = False
        if gc.line_items:
            reqs = [li.model_dump() for li in gc.line_items]
            if not line_items_satisfy(reqs, checkout.line_items):
                diag.add(Reason.SKU_NOT_ALLOWED)
                constraints_ok = False
        if payment_pv.details.get("payment_instrument") and \
                payment_pv.details["payment_instrument"].get("id") != gc.payment_instrument.id:
            diag.add(Reason.PAYMENT_INSTRUMENT_NOT_ALLOWED)
            constraints_ok = False
    diag.constraint_verification = CheckStatus.VALID if constraints_ok else CheckStatus.FAILED

    return decide(diag)


def _constraint_reason(ctype: str) -> Reason:
    if "amount" in ctype or "budget" in ctype:
        return Reason.DELIVERED_TOTAL_EXCEEDS_LIMIT
    if "merchant" in ctype:
        return Reason.MERCHANT_NOT_ALLOWED
    if "payee" in ctype:
        return Reason.PAYEE_MISMATCH
    if "line_items" in ctype:
        return Reason.SKU_NOT_ALLOWED
    if "reference" in ctype:
        return Reason.REFERENCE_MISMATCH
    if "instrument" in ctype:
        return Reason.PAYMENT_INSTRUMENT_NOT_ALLOWED
    return Reason.UNKNOWN_CONSTRAINT


__all__ = ["evaluate", "line_items_satisfy", "grant_state_reason", "check_input_limits", "Decision"]
