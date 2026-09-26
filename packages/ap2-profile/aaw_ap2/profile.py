"""AP2 profile adapter: issue → present → verify.

Version pin: AP2 specification v0.2 as published at ap2-protocol.org and in
google-agentic-commerce/AP2 @ e1ea56db72a6385bce3e5c1112b3a56ce60acb43, with the
mandate chain encoded per draft-gco-oauth-delegate-sd-jwt-00.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aaw_domain.profiles import (
    CheckoutSummary,
    GrantArtifacts,
    IssuanceContext,
    Presentation,
    ProfileVerification,
    VerifyExpectations,
)
from aaw_domain.trust import TrustStore
from aaw_signer import KeyHandle, b64url_decode, b64url_encode, jwk_thumbprint

from . import mandates as M
from .sdjwt import Link, decode_disclosure, digest_disclosure, parse_chain, serialize_chain
from .verify import verify_presentation

PROFILE_NAME = "ap2"
PROFILE_VERSION = "ap2-v0.2@e1ea56d+draft-gco-oauth-delegate-sd-jwt-00"


def _decode_jwt_unverified(token: str) -> Dict[str, Any]:
    h, p, _ = token.split(".")
    return {"header": json.loads(b64url_decode(h)), "payload": json.loads(b64url_decode(p))}


def _alter_disclosure(disc: str, mutate) -> str:
    """Post-signature tamper helper: re-encode a disclosure with a changed value while
    keeping its salt (so the digest no longer matches)."""
    arr = decode_disclosure(disc)
    arr[-1] = mutate(arr[-1])
    return b64url_encode(json.dumps(arr, separators=(",", ":")).encode("utf-8"))


class AP2Profile:
    name = PROFILE_NAME
    version = PROFILE_VERSION

    def __init__(self, payment_audience: str = "urn:aaw:verifier:payment"):
        self.default_payment_audience = payment_audience

    # -- issuance (trusted surface + user signing component) ------------------

    def issue(self, ctx: IssuanceContext, user_handle: KeyHandle) -> GrantArtifacts:
        l1_links = parse_chain(ctx.issuer_credential)
        if len(l1_links) != 1:
            raise ValueError("issuer credential must be a single SD-JWT")
        l1_full = l1_links[0]
        l1_presented = Link(l1_full.jwt)  # verifiers never receive the credential's identity disclosures
        nonce = ctx.consent_snapshot_digest[:32]  # binds the signed artifact to the reviewed snapshot
        objects: Dict[str, Any] = {
            "l1_full": l1_full.serialize(),
            "l1_presented": l1_presented.serialize(),
        }
        if ctx.mode == "autonomous":
            oms = M.build_open_mandates(
                user_handle, l1_presented, ctx.constraints, ctx.agent_public_jwk, ctx.now, ctx.agent_audience, nonce
            )
            objects["user_link"] = oms.link.serialize()
            objects["index"] = oms.index()
            summary = {
                "delegate_digests": [oms.checkout_digest, oms.payment_digest],
                "vct": [M.VCT_CHECKOUT_OPEN, M.VCT_PAYMENT_OPEN],
                "typ": M.TYP_KB_SD_JWT_KB,
            }
        else:
            if ctx.checkout is None:
                raise ValueError("direct mode requires the final checkout")
            dms = M.build_closed_mandates_direct(
                user_handle,
                l1_presented,
                ctx.checkout.checkout_jwt,
                ctx.checkout.merchant,
                ctx.checkout.total_minor,
                ctx.checkout.currency,
                ctx.constraints.payment_instrument.as_protocol(),
                ctx.now,
                ctx.constraints.expires_ts,
                [self._merchant_aud(ctx.checkout.merchant), self.default_payment_audience],
                nonce,
            )
            objects["user_link"] = dms.link.serialize()
            objects["index"] = dms.index()
            summary = {
                "delegate_digests": [dms.checkout_digest, dms.payment_digest],
                "vct": [M.VCT_CHECKOUT, M.VCT_PAYMENT],
                "typ": M.TYP_KB_SD_JWT,
                "checkout_hash": ctx.checkout.checkout_hash,
            }
        summary.update({
            "issuer_kid": l1_full.header.get("kid"),
            "user_kid": user_handle.kid,
            "consent_nonce": nonce,
            "sd_hash_over_l1": l1_presented.sd_hash(),
        })
        return GrantArtifacts(
            profile=self.name,
            version=self.version,
            mode=ctx.mode,
            objects=objects,
            public_summary=summary,
            agent_key_thumbprint=jwk_thumbprint(ctx.agent_public_jwk),
        )

    @staticmethod
    def _merchant_aud(merchant: Dict[str, Any]) -> str:
        return merchant.get("website") or f"urn:aaw:merchant:{merchant.get('id')}"

    # -- presentation (agent) -------------------------------------------------

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
        l1 = parse_chain(artifacts.objects["l1_presented"])[0]
        user_link = parse_chain(artifacts.objects["user_link"])[0]
        index = artifacts.objects["index"]
        signer = tamper.get("agent_handle_override") or agent_handle
        exp = now + 300
        instrument = tamper.get("payment_instrument_override")

        if artifacts.mode == "autonomous":
            # merchant view of the open mandate: open checkout mandate + this merchant + present items
            merchant_digests = {index["checkout_digest"]}
            md = index["merchant_checkout_digests"].get(checkout.merchant["id"])
            if md:
                merchant_digests.add(md)
            for li in checkout.line_items:
                d = index["item_digests"].get(li["id"])
                if d:
                    merchant_digests.add(d)
            open_for_merchant = user_link.select(merchant_digests)
            closed_checkout = M.build_closed_checkout(
                signer, open_for_merchant, tamper.get("checkout_jwt_override", checkout.checkout_jwt),
                merchant_audience, nonce, now, exp
            )
            # payment view: open payment mandate + this payee
            payment_digests = {index["payment_digest"]}
            pd = index["merchant_payee_digests"].get(checkout.merchant["id"])
            if pd:
                payment_digests.add(pd)
            open_for_payment = user_link.select(payment_digests)
            payee = tamper.get("payee_override") or checkout.merchant
            amount = int(tamper.get("payment_amount_minor", checkout.total_minor))
            if instrument is None:
                instrument = self._open_payment_instrument(open_for_payment, index["payment_digest"])
            closed_payment = M.build_closed_payment(
                signer, open_for_payment, checkout.checkout_hash, payee, amount, checkout.currency,
                instrument, payment_audience, nonce, now, exp
            )
            merchant_chain = [l1, open_for_merchant, closed_checkout]
            payment_chain = [l1, open_for_payment, closed_payment]
        else:
            merchant_chain = [l1, user_link.select({index["checkout_digest"], index["checkout_jwt_digest"]})]
            payment_chain = [l1, user_link.select({index["payment_digest"]})]

        self._apply_tamper(tamper, merchant_chain, payment_chain)
        return {
            "merchant": Presentation(self.name, self.version, "merchant", {"chain": serialize_chain(merchant_chain)},
                                     merchant_audience, nonce, checkout.checkout_hash),
            "payment": Presentation(self.name, self.version, "payment", {"chain": serialize_chain(payment_chain)},
                                    payment_audience, nonce, checkout.checkout_hash),
        }

    @staticmethod
    def _open_payment_instrument(open_link: Link, payment_digest: str) -> Dict[str, Any]:
        for d in open_link.disclosures:
            if digest_disclosure(d) == payment_digest:
                content = decode_disclosure(d)[-1]
                return content.get("payment_instrument") or {"id": "unknown", "type": "unknown", "description": ""}
        return {"id": "unknown", "type": "unknown", "description": ""}

    @staticmethod
    def _apply_tamper(tamper: Dict[str, Any], merchant_chain: List[Link], payment_chain: List[Link]) -> None:
        if tamper.get("drop_checkout_jwt"):
            final = merchant_chain[-1]
            final.disclosures = [d for d in final.disclosures
                                 if not (len(decode_disclosure(d)) == 3 and decode_disclosure(d)[1] == "checkout_jwt")]
        if "alter_payment_amount_after_signing" in tamper:
            final = payment_chain[-1]
            new_amount = int(tamper["alter_payment_amount_after_signing"])

            def mut(v):
                v = dict(v)
                v["payment_amount"] = dict(v["payment_amount"], amount=new_amount)
                return v

            final.disclosures = [_alter_disclosure(d, mut) if isinstance(decode_disclosure(d)[-1], dict)
                                 and decode_disclosure(d)[-1].get("vct") == M.VCT_PAYMENT else d for d in final.disclosures]
        if "alter_payee_after_signing" in tamper:
            final = payment_chain[-1]
            new_payee = tamper["alter_payee_after_signing"]

            def mut2(v):
                v = dict(v)
                v["payee"] = new_payee
                return v

            final.disclosures = [_alter_disclosure(d, mut2) if isinstance(decode_disclosure(d)[-1], dict)
                                 and decode_disclosure(d)[-1].get("vct") == M.VCT_PAYMENT else d for d in final.disclosures]
        if "swap_checkout_jwt_after_signing" in tamper:
            final = merchant_chain[-1]
            other = tamper["swap_checkout_jwt_after_signing"]
            final.disclosures = [_alter_disclosure(d, lambda _v: other) if len(decode_disclosure(d)) == 3
                                 and decode_disclosure(d)[1] == "checkout_jwt" else d for d in final.disclosures]
        if tamper.get("reveal_all_merchants") and len(merchant_chain) == 3:
            pass  # the agent may legitimately reveal more; kept for demos of the privacy test
        if tamper.get("extra_disclosure"):
            merchant_chain[-1].disclosures.append(M.make_disclosure({"unrelated": True}))

    # -- verification ---------------------------------------------------------

    def verify(self, presentation: Presentation, trust: TrustStore, expect: VerifyExpectations,
               *, expected_intermediate_aud: Optional[str] = None,
               skip_issuer_signature: bool = False) -> ProfileVerification:
        chain = presentation.payload.get("chain")
        if not isinstance(chain, str):
            pv = ProfileVerification()
            from aaw_domain.outcomes import Reason

            return pv.fail(Reason.MALFORMED_ARTIFACT, "presentation has no chain")
        return verify_presentation(presentation.role, chain, trust, expect,
                                   expected_intermediate_aud=expected_intermediate_aud,
                                   skip_issuer_signature=skip_issuer_signature)

    # -- evidence -------------------------------------------------------------

    def evidence_view(self, presentation: Presentation) -> Dict[str, Any]:
        chain = presentation.payload.get("chain", "")
        out: List[Dict[str, Any]] = []
        try:
            links = parse_chain(chain)
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}
        for i, link in enumerate(links):
            entry = _decode_jwt_unverified(link.jwt)
            entry["disclosures"] = []
            for d in link.disclosures:
                arr = decode_disclosure(d)
                entry["disclosures"].append({
                    "digest": digest_disclosure(d),
                    "claim_name": arr[1] if len(arr) == 3 else None,
                    "value": arr[-1],
                })
            entry["link"] = i
            out.append(entry)
        return {"profile": self.name, "version": self.version, "role": presentation.role, "links": out}

    def reuse_after_rejection_allowed(self) -> bool:
        # AP2: a Shopping Agent MUST NOT present a subsequent open Mandate without a
        # rejection receipt for the previous one; after a rejection receipt it may.
        return True
