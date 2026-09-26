"""Verifiable Intent profile adapter.

Version pin: agent-intent/verifiable-intent draft v0.1, commit
356c29635f1c44df7de02edb58699ca9f29bece6 (2026-04-20). The Python reference
implementation from that commit is vendored unmodified under
``packages/vi-profile/vendor/verifiable_intent`` (Apache-2.0) and performs all
VI issuance and chain verification. This adapter maps the wallet's grant model
onto VI's L1/L2/L3 layers, selects role-specific disclosures, and converts VI
results into the application's :class:`ProfileVerification`.

VI differences from AP2 that this adapter respects (never shared code paths):

* header ``typ`` values ``sd+jwt`` / ``kb-sd-jwt+kb`` / ``kb-sd-jwt``
* constraint types prefixed ``mandate.`` (``mandate.payment.amount_range`` …)
* split L3: L3a (payment) and L3b (checkout) are separate agent-signed SD-JWTs
* L2 ``sd_hash`` covers the L1 presentation; L3 ``sd_hash`` covers the
  role-specific L2 presentation
* one L3a+L3b pair per mandate pair; a failed attempt requires a new L2
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from aaw_domain.checkout import CheckoutError, checkout_hash, parse_checkout_jwt
from aaw_domain.outcomes import Reason
from aaw_domain.profiles import (
    CheckoutSummary,
    ConstraintResult,
    GrantArtifacts,
    IssuanceContext,
    Presentation,
    ProfileVerification,
    VerifyExpectations,
)
from aaw_domain.trust import PARTICIPANT_ISSUER, TrustError, TrustStore
from aaw_signer import KeyHandle, jwk_thumbprint
from aaw_signer.keys import jwk_to_public_key

from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes, hash_disclosure
from verifiable_intent.crypto.sd_jwt import SdJwt, create_sd_jwt, decode_sd_jwt
from verifiable_intent.issuance.issuer import create_layer1
from verifiable_intent.issuance.user import create_layer2_autonomous, create_layer2_immediate
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import CheckoutMandate, MandateMode, PaymentMandate, UserMandate
from verifiable_intent.verification import chain as vi_chain
from verifiable_intent.verification.chain import verify_chain
from verifiable_intent.verification.constraint_checker import StrictnessMode, check_constraints
from verifiable_intent.verification.integrity import verify_checkout_hash_binding

PROFILE_NAME = "vi"
PROFILE_VERSION = "verifiable-intent-draft-v0.1@356c296"
L1_VCT = "urn:aaw:test:vi-user-credential:1"
VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
VCT_PAYMENT_OPEN = "mandate.payment.open.1"
VCT_CHECKOUT = "mandate.checkout.1"
VCT_PAYMENT = "mandate.payment.1"
WILDCARD_QUANTITY_CAP = 100

_clock_lock = threading.Lock()


class _FakeTime:
    def __init__(self, now: int):
        self._now = now

    def time(self) -> float:
        return float(self._now)


@contextmanager
def _pinned_clock(now: int):
    """The reference verifier reads ``time.time()``; pin it to the injected clock so
    expiry boundaries are deterministic. Serialised because it swaps a module attribute."""
    with _clock_lock:
        original = vi_chain.time
        vi_chain.time = _FakeTime(now)  # type: ignore[assignment]
        try:
            yield
        finally:
            vi_chain.time = original  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Test issuer: Layer 1
# --------------------------------------------------------------------------- #


def build_user_credential(
    issuer_handle: KeyHandle,
    issuer_id: str,
    user_id: str,
    user_public_jwk: Dict[str, Any],
    now: int,
    exp: int,
    email: Optional[str] = None,
    pan_last_four: str = "4242",
    scheme: str = "TestScheme",
) -> str:
    cred = IssuerCredential(
        iss=issuer_id,
        sub=user_id,
        iat=now,
        exp=exp,
        vct=L1_VCT,
        cnf_jwk={k: v for k, v in user_public_jwk.items() if k in ("kty", "crv", "x", "y")},
        pan_last_four=pan_last_four,
        scheme=scheme,
        email=email,
    )
    l1 = create_layer1(cred, issuer_handle.ec_private_key(), kid=issuer_handle.kid)
    return l1.serialize()


def _disclosure_for(sd_jwt: SdJwt, predicate) -> Optional[str]:
    for disc_str, disc_val in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
        value = disc_val[-1] if disc_val else None
        if predicate(value):
            return disc_str
    return None


class VIProfile:
    name = PROFILE_NAME
    version = PROFILE_VERSION

    def __init__(self, payment_audience: str = "urn:aaw:verifier:payment", l1_vct: str = L1_VCT):
        self.default_payment_audience = payment_audience
        self.l1_vct = l1_vct

    # -- issuance -------------------------------------------------------------

    def issue(self, ctx: IssuanceContext, user_handle: KeyHandle) -> GrantArtifacts:
        l1 = decode_sd_jwt(ctx.issuer_credential)
        # Present L1 without its identity disclosures: the user signs sd_hash over the
        # base JWT only, so the agent cannot add them later.
        l1_presented = l1.issuer_jwt + "~"
        nonce = ctx.consent_snapshot_digest[:32]
        merchants = [m.as_protocol() for m in ctx.constraints.merchants]
        instrument = ctx.constraints.payment_instrument.as_protocol()
        objects: Dict[str, Any] = {"l1_full": ctx.issuer_credential, "l1_presented": l1_presented}

        if ctx.mode == "autonomous":
            items: List[Dict[str, Any]] = []
            checkout_constraints = [AllowedMerchantConstraint(allowed=merchants)]
            if ctx.constraints.line_items:
                reqs = []
                for req in ctx.constraints.line_items:
                    acceptable = [{"id": it.id, "title": it.title} for it in req.acceptable_items]
                    items.extend(acceptable)
                    reqs.append({"id": req.id, "acceptable_items": acceptable, "quantity": req.quantity})
                checkout_constraints.append(CheckoutLineItemsConstraint(items=reqs))
            else:
                # VI requires a line_items constraint in every open checkout mandate. A grant
                # without SKU restrictions uses the reference implementation's wildcard form
                # (empty acceptable_items) with a total-quantity cap.
                checkout_constraints.append(CheckoutLineItemsConstraint(
                    items=[{"id": "any-item", "acceptable_items": [], "quantity": WILDCARD_QUANTITY_CAP}]))
            mandate = UserMandate(
                nonce=nonce,
                aud=ctx.agent_audience,
                iat=ctx.now,
                iss=ctx.wallet_issuer,
                exp=ctx.constraints.expires_ts,
                mode=MandateMode.AUTONOMOUS,
                sd_hash=hash_bytes(l1_presented.encode("ascii")),
                checkout_mandate=CheckoutMandate(
                    vct=VCT_CHECKOUT_OPEN,
                    cnf_jwk={k: v for k, v in ctx.agent_public_jwk.items() if k in ("kty", "crv", "x", "y")},
                    cnf_kid=ctx.agent_public_jwk.get("kid"),
                    constraints=checkout_constraints,
                ),
                payment_mandate=PaymentMandate(
                    vct=VCT_PAYMENT_OPEN,
                    cnf_jwk={k: v for k, v in ctx.agent_public_jwk.items() if k in ("kty", "crv", "x", "y")},
                    cnf_kid=ctx.agent_public_jwk.get("kid"),
                    payment_instrument=instrument,
                    constraints=[
                        PaymentAmountConstraint(currency=ctx.constraints.currency, min=ctx.constraints.min_minor,
                                                max=ctx.constraints.max_minor),
                        AllowedPayeeConstraint(allowed=merchants),
                    ],
                ),
                merchants=merchants,
                acceptable_items=items,
            )
            l2 = create_layer2_autonomous(mandate, user_handle.ec_private_key(), kid=user_handle.kid)
            objects["l2"] = l2.serialize()
            summary = {"vct": [VCT_CHECKOUT_OPEN, VCT_PAYMENT_OPEN], "typ": "kb-sd-jwt+kb"}
        else:
            if ctx.checkout is None:
                raise ValueError("immediate mode requires the final checkout")
            co = ctx.checkout
            mandate = UserMandate(
                nonce=nonce,
                aud=co.merchant.get("website") or f"urn:aaw:merchant:{co.merchant['id']}",
                iat=ctx.now,
                iss=ctx.wallet_issuer,
                exp=ctx.constraints.expires_ts,
                mode=MandateMode.IMMEDIATE,
                sd_hash=hash_bytes(l1_presented.encode("ascii")),
                checkout_mandate=CheckoutMandate(vct=VCT_CHECKOUT, checkout_jwt=co.checkout_jwt,
                                                 checkout_hash=co.checkout_hash),
                payment_mandate=PaymentMandate(vct=VCT_PAYMENT, payee=co.merchant, currency=co.currency,
                                               amount=co.total_minor, transaction_id=co.checkout_hash,
                                               payment_instrument=instrument),
            )
            l2 = create_layer2_immediate(mandate, user_handle.ec_private_key(), kid=user_handle.kid).sd_jwt
            objects["l2"] = l2.serialize()
            summary = {"vct": [VCT_CHECKOUT, VCT_PAYMENT], "typ": "kb-sd-jwt", "checkout_hash": co.checkout_hash}
        summary.update({
            "issuer_kid": l1.header.get("kid"),
            "user_kid": user_handle.kid,
            "consent_nonce": nonce,
            "sd_hash_over_l1": hash_bytes(l1_presented.encode("ascii")),
            "l2_delegate_digests": [d.get("...") for d in l2.payload.get("delegate_payload", []) if isinstance(d, dict)],
        })
        return GrantArtifacts(self.name, self.version, ctx.mode, objects, summary, jwk_thumbprint(ctx.agent_public_jwk))

    # -- presentation ---------------------------------------------------------

    def build_presentations(
        self,
        artifacts: GrantArtifacts,
        checkout: CheckoutSummary,
        agent_handle: KeyHandle,
        merchant_audience: str,
        payment_audience: str,
        nonce: str,
        now: int,
        tamper: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Presentation]:
        tamper = tamper or {}
        l1_presented = artifacts.objects["l1_presented"]
        l2 = decode_sd_jwt(artifacts.objects["l2"])
        l2_base = l2.issuer_jwt
        signer = tamper.get("agent_handle_override") or agent_handle
        exp = now + 300

        if artifacts.mode == "autonomous":
            checkout_disc = _disclosure_for(l2, lambda v: isinstance(v, dict) and v.get("vct") == VCT_CHECKOUT_OPEN)
            payment_disc = _disclosure_for(l2, lambda v: isinstance(v, dict) and v.get("vct") == VCT_PAYMENT_OPEN)
            merchant_disc = _disclosure_for(l2, lambda v: isinstance(v, dict) and v.get("id") == checkout.merchant["id"]
                                            and "name" in v and "vct" not in v)
            item_ids = {li["id"] for li in checkout.line_items}
            item_discs = [d for d, v in zip(l2.disclosures, l2.disclosure_values)
                          if isinstance(v[-1], dict) and v[-1].get("id") in item_ids and "title" in v[-1] and "vct" not in v[-1]]
            merchant_l2_discs = [d for d in [checkout_disc, merchant_disc] if d] + item_discs
            payment_l2_discs = [d for d in [payment_disc, merchant_disc] if d]
            l2_for_merchant = build_selective_presentation(l2_base, merchant_l2_discs)
            l2_for_payment = build_selective_presentation(l2_base, payment_l2_discs)

            payment_content = {
                "vct": VCT_PAYMENT,
                "transaction_id": checkout.checkout_hash,
                "payee": tamper.get("payee_override") or checkout.merchant,
                "payment_amount": {"currency": checkout.currency,
                                   "amount": int(tamper.get("payment_amount_minor", checkout.total_minor))},
                "payment_instrument": tamper.get("payment_instrument_override")
                or self._l2_payment_instrument(l2, payment_disc),
            }
            l3a = self._create_l3(signer, l2_for_payment, [checkout.merchant, payment_content], payment_audience,
                                  nonce, now, exp)
            checkout_content = {
                "vct": VCT_CHECKOUT,
                "checkout_jwt": tamper.get("checkout_jwt_override", checkout.checkout_jwt),
                "checkout_hash": checkout_hash(tamper.get("checkout_jwt_override", checkout.checkout_jwt)),
            }
            l3b = self._create_l3(signer, l2_for_merchant, [checkout_content], merchant_audience, nonce, now, exp)
            merchant_payload = {"l1": l1_presented, "l2": l2_for_merchant, "l3": l3b.serialize()}
            payment_payload = {"l1": l1_presented, "l2": l2_for_payment, "l3": l3a.serialize()}
        else:
            # VI Immediate mode: the reference verifier requires both final mandates to be
            # disclosed together ("Immediate mode requires both checkout and payment mandate
            # disclosures"), so both roles receive the complete L2. Role-scoping of
            # disclosures in VI applies to Autonomous mode (split L3).
            full = l2.serialize()
            merchant_payload = {"l1": l1_presented, "l2": full}
            payment_payload = {"l1": l1_presented, "l2": full}

        self._apply_tamper(tamper, merchant_payload, payment_payload)
        return {
            "merchant": Presentation(self.name, self.version, "merchant", merchant_payload, merchant_audience, nonce,
                                     checkout.checkout_hash),
            "payment": Presentation(self.name, self.version, "payment", payment_payload, payment_audience, nonce,
                                    checkout.checkout_hash),
        }

    @staticmethod
    def _l2_payment_instrument(l2: SdJwt, payment_disc: Optional[str]) -> Dict[str, Any]:
        for d, v in zip(l2.disclosures, l2.disclosure_values):
            if d == payment_disc and isinstance(v[-1], dict):
                return v[-1].get("payment_instrument") or {}
        return {}

    @staticmethod
    def _create_l3(signer: KeyHandle, l2_presentation: str, contents: List[Dict[str, Any]], aud: str, nonce: str,
                   now: int, exp: int) -> SdJwt:
        """Build an L3 SD-JWT exactly as the reference ``create_layer3_*`` functions do,
        but with an arbitrary number of L2 disclosures covered by ``sd_hash``."""
        from verifiable_intent.crypto.disclosure import create_delegate_ref, create_disclosure

        disclosures = [create_disclosure(None, c) for c in contents]
        payload = {
            "nonce": nonce,
            "aud": aud,
            "sd_hash": hash_bytes(l2_presentation.encode("ascii")),
            "iat": now,
            "exp": exp,
            "iss": f"urn:aaw:agent-key:{signer.kid}",
            "delegate_payload": [create_delegate_ref(hash_disclosure(d)) for d in disclosures],
            "_sd_alg": "sha-256",
        }
        header = {"alg": "ES256", "typ": "kb-sd-jwt", "kid": signer.kid}
        return create_sd_jwt(header, payload, disclosures, signer.ec_private_key())

    @staticmethod
    def _apply_tamper(tamper: Dict[str, Any], merchant_payload: Dict[str, Any], payment_payload: Dict[str, Any]) -> None:
        import json

        from aaw_signer import b64url_decode, b64url_encode

        def alter(serialized: str, predicate, mutate) -> str:
            parts = serialized.split("~")
            out = [parts[0]]
            for d in parts[1:]:
                if not d:
                    out.append(d)
                    continue
                arr = json.loads(b64url_decode(d))
                if predicate(arr[-1]):
                    arr[-1] = mutate(arr[-1])
                    d = b64url_encode(json.dumps(arr, separators=(",", ":")).encode())
                out.append(d)
            return "~".join(out)

        if "alter_payment_amount_after_signing" in tamper:
            amt = int(tamper["alter_payment_amount_after_signing"])
            pkey = "l3" if "l3" in payment_payload else "l2"
            payment_payload[pkey] = alter(payment_payload[pkey],
                                          lambda v: isinstance(v, dict) and v.get("vct") == VCT_PAYMENT,
                                          lambda v: dict(v, payment_amount=dict(v["payment_amount"], amount=amt)))
        if "alter_payee_after_signing" in tamper:
            payee = tamper["alter_payee_after_signing"]
            pkey = "l3" if "l3" in payment_payload else "l2"
            payment_payload[pkey] = alter(payment_payload[pkey],
                                          lambda v: isinstance(v, dict) and v.get("vct") == VCT_PAYMENT,
                                          lambda v: dict(v, payee=payee))
        if "swap_checkout_jwt_after_signing" in tamper:
            other = tamper["swap_checkout_jwt_after_signing"]
            key = "l3" if "l3" in merchant_payload else "l2"
            merchant_payload[key] = alter(merchant_payload[key],
                                          lambda v: isinstance(v, dict) and v.get("vct") == VCT_CHECKOUT,
                                          lambda v: dict(v, checkout_jwt=other))
        if tamper.get("drop_checkout_jwt"):
            key = "l3" if "l3" in merchant_payload else "l2"
            merchant_payload[key] = alter(merchant_payload[key],
                                          lambda v: isinstance(v, dict) and v.get("vct") == VCT_CHECKOUT,
                                          lambda v: {k: x for k, x in v.items() if k != "checkout_jwt"})
        if tamper.get("extra_disclosure"):
            from verifiable_intent.crypto.disclosure import create_disclosure

            key = "l3" if "l3" in merchant_payload else "l2"
            merchant_payload[key] = merchant_payload[key] + create_disclosure(None, {"unrelated": True}) + "~"

    # -- verification ---------------------------------------------------------

    def verify(self, presentation: Presentation, trust: TrustStore, expect: VerifyExpectations,
               **_: Any) -> ProfileVerification:
        pv = ProfileVerification()
        payload = presentation.payload
        try:
            l1 = decode_sd_jwt(payload["l1"])
            l2 = decode_sd_jwt(payload["l2"])
            l3 = decode_sd_jwt(payload["l3"]) if payload.get("l3") else None
        except Exception as exc:
            return pv.fail(Reason.MALFORMED_ARTIFACT, f"undecodable VI presentation: {exc}")
        for name, sd in (("l1", l1), ("l2", l2), ("l3", l3)):
            if sd is None:
                continue
            if len(sd.disclosures) > 64:
                return pv.fail(Reason.INPUT_TOO_LARGE, "too many disclosures")
            stray, missing = _unreferenced_disclosures(sd)
            if stray:
                reason = Reason.DISCLOSURE_DIGEST_MISMATCH if missing else Reason.UNEXPECTED_DISCLOSURE
                return pv.fail(reason, f"{name} carries disclosures not referenced by any digest")
        # issuer trust: kid is a hint, the allowlist decides
        iss = l1.payload.get("iss") if isinstance(l1.payload, dict) else None
        if not isinstance(iss, str):
            return pv.fail(Reason.UNKNOWN_ISSUER, "L1 has no iss")
        try:
            key = trust.resolve(PARTICIPANT_ISSUER, iss, l1.header.get("kid"), "ES256", at=expect.now,
                                allow_retired=expect.allow_retired_keys)
        except TrustError as exc:
            return pv.fail(exc.reason, str(exc))
        if l1.header.get("alg") != "ES256" or l2.header.get("alg") != "ES256" or (l3 and l3.header.get("alg") != "ES256"):
            return pv.fail(Reason.UNSUPPORTED_ALGORITHM, "VI artifacts must use ES256")
        issuer_pub = jwk_to_public_key(key.public_jwk)
        pv.issuer_id = iss

        role = presentation.role
        kwargs: Dict[str, Any] = dict(
            issuer_public_key=issuer_pub,
            l1_serialized=payload["l1"],
            l2_serialized=payload["l2"],
            clock_skew_seconds=expect.max_clock_skew,
            expected_l1_vct=self.l1_vct,
        )
        if l3 is not None:
            if role == "merchant":
                kwargs.update(l3_checkout=l3, l2_checkout_serialized=payload["l2"],
                              expected_l3_checkout_aud=expect.audience, expected_l3_checkout_nonce=expect.nonce)
            else:
                kwargs.update(l3_payment=l3, l2_payment_serialized=payload["l2"],
                              expected_l3_payment_aud=expect.audience, expected_l3_payment_nonce=expect.nonce)
        with _pinned_clock(expect.now):
            result = verify_chain(l1, l2, **kwargs)
        pv.details["vi_checks_performed"] = result.checks_performed
        pv.details["vi_checks_skipped"] = result.checks_skipped
        if not result.valid:
            for e in result.errors:
                pv.fail(_map_error(e), e)
            return pv
        pv.crypto_valid = True
        l2_claims = result.l2_claims
        l2_delegates = [d for d in l2_claims.get("delegate_payload", []) if isinstance(d, dict)]
        is_autonomous = l3 is not None
        pv.mode = "autonomous" if is_autonomous else "direct"
        cnf = l1.payload.get("cnf", {}).get("jwk")
        if isinstance(cnf, dict):
            pv.user_key_thumbprint = jwk_thumbprint(cnf)
        pv.details["final_nonce"] = (l3.payload if l3 else l2.payload).get("nonce")
        pv.disclosed = {
            "l1": {"header": l1.header, "payload": l1.payload},
            "l2": {"header": l2.header, "payload": l2.payload, "resolved": l2_claims},
        }
        if l3 is not None:
            l3_claims = result.l3_checkout_claims if role == "merchant" else result.l3_payment_claims
            pv.disclosed["l3"] = {"header": l3.header, "payload": l3.payload, "resolved": l3_claims}
            closed_list = [d for d in l3_claims.get("delegate_payload", []) if isinstance(d, dict) and d.get("vct")]
            open_vct = VCT_CHECKOUT_OPEN if role == "merchant" else VCT_PAYMENT_OPEN
            open_mandate = next((d for d in l2_delegates if d.get("vct") == open_vct), None)
            if open_mandate is None:
                return pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, f"L2 does not disclose {open_vct}")
            agent_jwk = (open_mandate.get("cnf") or {}).get("jwk")
            if isinstance(agent_jwk, dict):
                pv.agent_key_thumbprint = jwk_thumbprint({k: v for k, v in agent_jwk.items() if k != "kid"})
            pv.final_artifact_hash = hash_bytes(payload["l3"].encode("ascii"))
            # digest of the disclosed open checkout mandate (reference binding target)
            for d, v in zip(l2.disclosures, l2.disclosure_values):
                if isinstance(v[-1], dict) and v[-1].get("vct") == VCT_CHECKOUT_OPEN:
                    pv.open_mandate_digest = hash_disclosure(d)
        else:
            closed_list = l2_delegates
            open_mandate = None
            pv.final_artifact_hash = hash_bytes(payload["l2"].encode("ascii"))

        closed_vct = VCT_CHECKOUT if role == "merchant" else VCT_PAYMENT
        closed = next((d for d in closed_list if d.get("vct") == closed_vct), None)
        if closed is None:
            return pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, f"presentation does not disclose {closed_vct}")
        other_vct = VCT_PAYMENT if role == "merchant" else VCT_CHECKOUT
        if any(d.get("vct") in (other_vct, VCT_PAYMENT_OPEN if role == "merchant" else VCT_CHECKOUT_OPEN)
               for d in closed_list + l2_delegates):
            pv.details.setdefault("warnings", []).append("presentation discloses claims not needed by this role")
        pv.closed_claims = closed
        pv.expires_at = (l3.payload if l3 else l2.payload).get("exp")

        if role == "merchant":
            self._merchant_checks(pv, closed, open_mandate, l2, trust, expect)
        else:
            self._payment_checks(pv, closed, open_mandate, l2, expect)
        pv.protocol_valid = not pv.reasons
        return pv

    def _merchant_checks(self, pv, closed, open_mandate, l2, trust, expect) -> None:
        cj = closed.get("checkout_jwt")
        if not isinstance(cj, str):
            pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, "checkout_jwt not disclosed to merchant")
            return
        ok, err = verify_checkout_hash_binding(closed, {"transaction_id": closed.get("checkout_hash")})
        if not ok:
            pv.fail(Reason.CHECKOUT_BINDING_MISMATCH, err)
        pv.checkout_hash = closed.get("checkout_hash")
        if expect.expected_checkout_jwt is not None and cj != expect.expected_checkout_jwt:
            pv.fail(Reason.CHECKOUT_BINDING_MISMATCH, "disclosed checkout_jwt is not the checkout this merchant issued")
        try:
            summary = parse_checkout_jwt(cj, trust, expect.now, allow_retired=expect.allow_retired_keys)
        except CheckoutError as exc:
            pv.fail(exc.reason, f"checkout_jwt: {exc}")
            return
        pv.merchant = summary.merchant
        pv.checkout_line_items = summary.line_items
        pv.amount_minor = summary.total_minor
        pv.currency = summary.currency
        if open_mandate is None:
            return
        constraints = _resolve_refs_deep(l2, open_mandate.get("constraints") or [])
        pv.open_constraints = constraints
        allowed_merchants = _resolved_refs(l2, constraints, "mandate.checkout.allowed_merchants", "allowed")
        fulfillment = {"merchant": summary.merchant, "allowed_merchants": allowed_merchants,
                       "line_items": [{"id": li["id"], "quantity": li["quantity"]} for li in summary.line_items]}
        _check_each(pv, constraints, fulfillment)

    def _payment_checks(self, pv, closed, open_mandate, l2, expect) -> None:
        tx = closed.get("transaction_id")
        amount = closed.get("payment_amount") or {}
        payee = closed.get("payee") or {}
        if not isinstance(tx, str) or not isinstance(amount.get("amount"), int) or not isinstance(payee, dict):
            pv.fail(Reason.MALFORMED_ARTIFACT, "closed payment mandate missing required fields")
            return
        pv.transaction_id = tx
        pv.amount_minor = int(amount["amount"])
        pv.currency = amount.get("currency")
        pv.payee = payee
        pv.details["payment_instrument"] = closed.get("payment_instrument") or {}
        if expect.expected_checkout_hash is not None and tx != expect.expected_checkout_hash:
            pv.fail(Reason.PAYMENT_BINDING_MISMATCH, "transaction_id does not match the checkout hash")
        if open_mandate is None:
            return
        constraints = _resolve_refs_deep(l2, open_mandate.get("constraints") or [])
        pv.open_constraints = constraints
        for c in constraints:
            if isinstance(c, dict) and c.get("type") == "mandate.payment.reference":
                pv.reference_digest = c.get("conditional_transaction_id")
        allowed = _resolved_refs(l2, constraints, "mandate.payment.allowed_payees", "allowed")
        fulfillment = dict(closed)
        fulfillment["allowed_merchants"] = allowed
        _check_each(pv, constraints, fulfillment)
        l2_pi = open_mandate.get("payment_instrument") or {}
        if l2_pi and (l2_pi.get("id") != (closed.get("payment_instrument") or {}).get("id")):
            pv.fail(Reason.PAYMENT_INSTRUMENT_NOT_ALLOWED, "L3 payment instrument differs from L2")

    # -- evidence -------------------------------------------------------------

    def evidence_view(self, presentation: Presentation) -> Dict[str, Any]:
        out: Dict[str, Any] = {"profile": self.name, "version": self.version, "role": presentation.role, "layers": {}}
        for name in ("l1", "l2", "l3"):
            ser = presentation.payload.get(name)
            if not ser:
                continue
            try:
                sd = decode_sd_jwt(ser)
                out["layers"][name] = {
                    "header": sd.header,
                    "payload": sd.payload,
                    "disclosures": [
                        {"digest": hash_disclosure(d), "claim_name": v[1] if len(v) == 3 else None, "value": v[-1]}
                        for d, v in zip(sd.disclosures, sd.disclosure_values)
                    ],
                }
            except Exception as exc:  # pragma: no cover
                out["layers"][name] = {"error": str(exc)}
        return out

    def reuse_after_rejection_allowed(self) -> bool:
        # VI: each mandate pair is expected to produce exactly one L3a + L3b pair
        # (spec/README.md §11, security-model.md §4.2). A failed attempt needs a new L2.
        return False


def _resolve_refs_deep(l2: SdJwt, obj: Any) -> Any:
    """Replace ``{"...": digest}`` references inside constraint arrays with the disclosed
    values. Undisclosed references are kept as references: the reference checker then
    sees a non-empty, unresolved ``acceptable_items`` and fails closed instead of
    treating the emptied list as a wildcard."""
    by_hash = {hash_disclosure(d): v[-1] for d, v in zip(l2.disclosures, l2.disclosure_values)}

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if set(node.keys()) == {"..."} and node["..."] in by_hash:
                return walk(by_hash[node["..."]])
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(el) for el in node]
        return node

    return walk(obj)


def _referenced_digests(obj: Any) -> set:
    out: set = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for dg in node.get("_sd", []) or []:
                out.add(dg)
            for k, v in node.items():
                if k == "..." and isinstance(v, str) and len(node) == 1:
                    out.add(v)
                elif k != "_sd":
                    walk(v)
        elif isinstance(node, list):
            for el in node:
                walk(el)

    walk(obj)
    return out


def _unreferenced_disclosures(sd: SdJwt):
    """Application hardening beyond the reference verifier: every presented disclosure
    must be reachable from the payload (directly or through another disclosure).
    Returns ``(stray_digests, missing_referenced_digests)``; a stray disclosure together
    with a missing referenced digest indicates an altered disclosure."""
    referenced = _referenced_digests(sd.payload)
    for v in sd.disclosure_values:
        referenced |= _referenced_digests(v[-1])
    available = {hash_disclosure(d) for d in sd.disclosures}
    stray = [dg for dg in available if dg not in referenced]
    missing = [dg for dg in referenced if dg not in available]
    return stray, missing


def _resolved_refs(l2: SdJwt, constraints: List[Dict[str, Any]], ctype: str, key: str) -> List[Dict[str, Any]]:
    by_hash = {hash_disclosure(d): v[-1] for d, v in zip(l2.disclosures, l2.disclosure_values)}
    out: List[Dict[str, Any]] = []
    for c in constraints:
        if isinstance(c, dict) and c.get("type") == ctype:
            for ref in c.get(key) or []:
                if isinstance(ref, dict) and "..." in ref and ref["..."] in by_hash:
                    out.append(by_hash[ref["..."]])
                elif isinstance(ref, dict) and "id" in ref:
                    out.append(ref)
    return out


def _check_each(pv: ProfileVerification, constraints: List[Dict[str, Any]], fulfillment: Dict[str, Any]) -> None:
    """Evaluate constraints one at a time with the reference checker (strict mode, open
    mandate semantics) so each gets its own satisfied/violation record. Unknown
    constraint types fail closed."""
    if not isinstance(constraints, list):
        pv.fail(Reason.MALFORMED_ARTIFACT, "constraints must be an array")
        return
    for c in constraints:
        ctype = c.get("type") if isinstance(c, dict) else None
        res = check_constraints([c], fulfillment, mode=StrictnessMode.STRICT, is_open_mandate=True)
        if any(v.startswith("Unknown constraint type") for v in res.violations):
            pv.constraint_results.append(ConstraintResult(str(ctype), False, "unknown constraint type"))
            pv.fail(Reason.UNKNOWN_CONSTRAINT, f"constraint {ctype!r}")
            continue
        skipped_marker = [x for x in res.checked if "(skipped" in x]
        if skipped_marker:
            # The reference checker treats "all allowed entries are undisclosed SD references"
            # as a skip. A verifier must fail closed: the agent has to reveal the entry that
            # authorises this merchant/payee.
            pv.constraint_results.append(ConstraintResult(str(ctype), False, skipped_marker[0]))
            pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, f"{ctype}: no allowed entry disclosed")
            continue
        detail = "; ".join(res.violations) if res.violations else "satisfied"
        pv.constraint_results.append(ConstraintResult(str(ctype), res.satisfied, detail))
        if res.violations:
            pv.details.setdefault("vi_constraint_violations", []).extend(res.violations)


def _map_error(message: str) -> Reason:
    m = message.lower()
    if "signature" in m:
        return Reason.INVALID_SIGNATURE if "l1" in m else Reason.AGENT_KEY_MISMATCH if "l3" in m else Reason.INVALID_SIGNATURE
    if "expired" in m:
        return Reason.EXPIRED_AUTHORIZATION
    if "sd_hash" in m or "binding" in m:
        return Reason.CHAIN_BINDING_MISMATCH
    if "aud" in m:
        return Reason.AUDIENCE_MISMATCH
    if "nonce" in m:
        return Reason.NONCE_MISMATCH
    if "vct" in m:
        return Reason.MANDATE_TYPE_MISMATCH
    if "disclos" in m or "delegate_payload" in m:
        return Reason.DISCLOSURE_DIGEST_MISMATCH
    if "alg" in m or "typ" in m:
        return Reason.UNSUPPORTED_ALGORITHM
    if "cnf" in m:
        return Reason.AGENT_KEY_MISMATCH
    if "future" in m:
        return Reason.AUTHORIZATION_NOT_YET_VALID
    if "checkout_hash" in m or "transaction_id" in m:
        return Reason.CHECKOUT_BINDING_MISMATCH
    return Reason.MALFORMED_ARTIFACT
