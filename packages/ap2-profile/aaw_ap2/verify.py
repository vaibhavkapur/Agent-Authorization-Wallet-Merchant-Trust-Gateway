"""AP2 verification: Delegate SD-JWT chain processing (draft §6) followed by the
AP2 Verification and Processing Rules (agent_authorization.md) and the
role-specific mandate rules (checkout_mandate.md, payment_mandate.md).

Cryptographic validity (``crypto_valid``) and protocol validity
(``protocol_valid``) are reported separately from application policy, which
the domain pipeline applies afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from aaw_domain.checkout import CheckoutError, checkout_hash, parse_checkout_jwt
from aaw_domain.outcomes import Reason
from aaw_domain.pipeline import line_items_satisfy
from aaw_domain.profiles import ConstraintResult, ProfileVerification, VerifyExpectations
from aaw_domain.trust import PARTICIPANT_ISSUER, TrustError, TrustStore
from aaw_signer import SignatureError, jwk_thumbprint
from aaw_signer.jws import verify_compact_json

from . import mandates as M
from .sdjwt import Link, SdJwtError, digests_in, parse_chain, resolve_claims, sd_alg_ok

ALLOWED_ALGS = ("ES256",)
KNOWN_CHECKOUT_CONSTRAINTS = {M.CT_ALLOWED_MERCHANTS, M.CT_LINE_ITEMS}
KNOWN_PAYMENT_CONSTRAINTS = {M.CT_AMOUNT_RANGE, M.CT_ALLOWED_PAYEES, M.CT_REFERENCE, M.CT_EXECUTION_DATE,
                             M.CT_ALLOWED_INSTRUMENTS}
# Present in the specification but not supported by this single-purchase profile.
UNSUPPORTED_PAYMENT_CONSTRAINTS = {M.CT_AGENT_RECURRENCE, M.CT_BUDGET, M.CT_ALLOWED_PISPS}


@dataclass
class VerifiedLink:
    link: Link
    header: Dict[str, Any]
    payload: Dict[str, Any]
    claims: Dict[str, Any]  # resolved (disclosures applied)
    content: Dict[str, Any]  # mandate content (disclosed delegate) or credential claims
    content_digest: Optional[str]  # digest of the disclosed delegate element, if any
    signer_jwk: Dict[str, Any]


@dataclass
class ChainResult:
    links: List[VerifiedLink] = field(default_factory=list)
    errors: List[Tuple[Reason, str]] = field(default_factory=list)
    issuer_id: Optional[str] = None
    crypto_valid: bool = False

    def fail(self, reason: Reason, detail: str) -> "ChainResult":
        self.errors.append((reason, detail))
        return self

    @property
    def ok(self) -> bool:
        return not self.errors


def _aud_matches(aud: Any, expected: str) -> bool:
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, list):
        return expected in aud
    return False


def verify_chain(
    compact: str,
    trust: TrustStore,
    expect: VerifyExpectations,
    *,
    expected_intermediate_aud: Optional[str] = None,
    skip_issuer_signature: bool = False,
) -> ChainResult:
    """Delegate SD-JWT chain verification (draft-gco-oauth-delegate-sd-jwt-00 §6).

    ``skip_issuer_signature`` exists only for replaying published specification
    fixtures whose issuer key is not available; production paths never set it.
    """
    res = ChainResult()
    try:
        links = parse_chain(compact)
    except SdJwtError as exc:
        return res.fail(Reason(exc.code) if exc.code in Reason.__members__ else Reason.MALFORMED_ARTIFACT, str(exc))
    if len(links) < 2:
        return res.fail(Reason.MALFORMED_ARTIFACT, "a mandate chain needs a credential and at least one KB-SD-JWT")

    now = expect.now
    # ---- link 0: issuer-signed SD-JWT --------------------------------------
    first = links[0]
    try:
        header = first.header
        raw_payload = first.payload
    except Exception as exc:
        return res.fail(Reason.MALFORMED_ARTIFACT, f"link 0 undecodable: {exc}")
    if header.get("alg") not in ALLOWED_ALGS:
        return res.fail(Reason.UNSUPPORTED_ALGORITHM, f"link 0 alg {header.get('alg')!r}")
    issuer_id = raw_payload.get("iss")
    signer_jwk: Dict[str, Any] = {}
    if not skip_issuer_signature:
        if not isinstance(issuer_id, str):
            return res.fail(Reason.UNKNOWN_ISSUER, "credential has no iss")
        try:
            key = trust.resolve(PARTICIPANT_ISSUER, issuer_id, header.get("kid"), "ES256", at=now,
                                allow_retired=expect.allow_retired_keys)
        except TrustError as exc:
            return res.fail(exc.reason, str(exc))
        signer_jwk = key.public_jwk
        try:
            _, raw_payload = verify_compact_json(first.jwt, signer_jwk, allowed_algs=ALLOWED_ALGS)
        except SignatureError as exc:
            return res.fail(Reason(exc.code) if exc.code in Reason.__members__ else Reason.INVALID_SIGNATURE,
                            f"link 0: {exc}")
    res.issuer_id = issuer_id
    if not sd_alg_ok(raw_payload):
        return res.fail(Reason.UNSUPPORTED_ALGORITHM, "unsupported _sd_alg in credential")
    try:
        resolved = resolve_claims(raw_payload, first.disclosures)
    except SdJwtError as exc:
        return res.fail(Reason(exc.code) if exc.code in Reason.__members__ else Reason.MALFORMED_ARTIFACT, str(exc))
    if resolved.unused():
        return res.fail(_unused_reason(raw_payload, resolved), "credential presented disclosures that are not referenced")
    claims = resolved.claims
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and now > exp + expect.max_clock_skew:
        return res.fail(Reason.EXPIRED_AUTHORIZATION, "credential expired")
    content, content_digest = _select_content(claims, resolved, raw_payload)
    if content is None:
        return res.fail(Reason.MISSING_REQUIRED_DISCLOSURE, "link 0 must disclose exactly one delegate_payload element")
    res.links.append(VerifiedLink(first, header, raw_payload, claims, content, content_digest, signer_jwk))

    # ---- subsequent links: KB-SD-JWT(+KB) ------------------------------------
    for idx in range(1, len(links)):
        link = links[idx]
        prev = res.links[idx - 1]
        is_final = idx == len(links) - 1
        cnf = prev.content.get("cnf") if isinstance(prev.content, dict) else None
        cnf_jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(cnf_jwk, dict):
            return res.fail(Reason.AGENT_KEY_MISMATCH, f"link {idx - 1} content has no cnf.jwk to bind link {idx}")
        try:
            header = link.header
        except Exception as exc:
            return res.fail(Reason.MALFORMED_ARTIFACT, f"link {idx} undecodable: {exc}")
        if header.get("alg") not in ALLOWED_ALGS:
            return res.fail(Reason.UNSUPPORTED_ALGORITHM, f"link {idx} alg {header.get('alg')!r}")
        expected_typ = M.TYP_KB_SD_JWT if is_final else M.TYP_KB_SD_JWT_KB
        if header.get("typ") != expected_typ:
            return res.fail(Reason.MALFORMED_ARTIFACT, f"link {idx} typ {header.get('typ')!r}, expected {expected_typ!r}")
        try:
            _, payload = verify_compact_json(link.jwt, cnf_jwk, allowed_algs=ALLOWED_ALGS)
        except SignatureError as exc:
            reason = Reason(exc.code) if exc.code in Reason.__members__ else Reason.INVALID_SIGNATURE
            if reason == Reason.INVALID_SIGNATURE:
                reason = Reason.AGENT_KEY_MISMATCH if idx == len(links) - 1 and len(links) == 3 else Reason.INVALID_SIGNATURE
            return res.fail(reason, f"link {idx}: {exc}")
        if not sd_alg_ok(payload):
            return res.fail(Reason.UNSUPPORTED_ALGORITHM, f"link {idx}: unsupported _sd_alg")
        # binding to the preceding link (§5.1.4 / §8.1)
        if "sd_hash" in payload:
            if payload["sd_hash"] != prev.link.sd_hash():
                return res.fail(Reason.CHAIN_BINDING_MISMATCH, f"link {idx} sd_hash does not cover the preceding presentation")
        elif "issuer_jwt_hash" in payload:
            if payload["issuer_jwt_hash"] != prev.link.issuer_jwt_hash():
                return res.fail(Reason.CHAIN_BINDING_MISMATCH, f"link {idx} issuer_jwt_hash mismatch")
        else:
            return res.fail(Reason.CHAIN_BINDING_MISMATCH, f"link {idx} has neither sd_hash nor issuer_jwt_hash")
        iat = payload.get("iat")
        if not isinstance(iat, int):
            return res.fail(Reason.MALFORMED_ARTIFACT, f"link {idx} missing iat")
        if iat > now + expect.max_clock_skew:
            return res.fail(Reason.AUTHORIZATION_NOT_YET_VALID, f"link {idx} iat in the future")
        if "nonce" not in payload or "aud" not in payload:
            return res.fail(Reason.MALFORMED_ARTIFACT, f"link {idx} missing nonce/aud")
        if is_final:
            if not _aud_matches(payload.get("aud"), expect.audience):
                return res.fail(Reason.AUDIENCE_MISMATCH, f"final link aud {payload.get('aud')!r} != {expect.audience!r}")
            # A user-signed final link (direct mode: the preceding link is the bare credential)
            # carries the consent nonce and is bounded by the mandate exp; an agent-signed final
            # link (the preceding link is an open mandate container) must carry the
            # verifier/request nonce and be fresh.
            delegated = "delegate_payload" in prev.payload
            if delegated and expect.nonce is not None and payload.get("nonce") != expect.nonce:
                return res.fail(Reason.NONCE_MISMATCH, "final link nonce does not match the request nonce")
            if delegated and now - iat > expect.max_presentation_age:
                return res.fail(Reason.EXPIRED_AUTHORIZATION, "presentation too old")
        elif expected_intermediate_aud is not None and not _aud_matches(payload.get("aud"), expected_intermediate_aud):
            return res.fail(Reason.AUDIENCE_MISMATCH, f"link {idx} aud {payload.get('aud')!r} is not the delegate agent")
        try:
            resolved = resolve_claims(payload, link.disclosures)
        except SdJwtError as exc:
            return res.fail(Reason(exc.code) if exc.code in Reason.__members__ else Reason.MALFORMED_ARTIFACT,
                            f"link {idx}: {exc}")
        if resolved.unused():
            return res.fail(_unused_reason(payload, resolved), f"link {idx} carries disclosures that are not referenced")
        content, content_digest = _select_content(resolved.claims, resolved, payload)
        if content is None:
            return res.fail(Reason.MISSING_REQUIRED_DISCLOSURE,
                            f"link {idx} must disclose exactly one delegate_payload element")
        if not is_final and not isinstance(content.get("cnf"), dict):
            return res.fail(Reason.AGENT_KEY_MISMATCH, f"link {idx} (kb+sd-jwt+kb) content must include cnf")
        c_exp = content.get("exp")
        if isinstance(c_exp, (int, float)) and now > c_exp + expect.max_clock_skew:
            return res.fail(Reason.EXPIRED_AUTHORIZATION, f"link {idx} mandate expired")
        c_iat = content.get("iat")
        if isinstance(c_iat, (int, float)) and c_iat > now + expect.max_clock_skew:
            return res.fail(Reason.AUTHORIZATION_NOT_YET_VALID, f"link {idx} mandate iat in the future")
        res.links.append(VerifiedLink(link, header, payload, resolved.claims, content, content_digest, cnf_jwk))

    res.crypto_valid = True
    return res


def _unused_reason(payload: Dict[str, Any], resolved) -> Reason:
    """A presented-but-unreferenced disclosure is either an altered disclosure (its
    digest no longer matches a referenced digest → DISCLOSURE_DIGEST_MISMATCH) or an
    extraneous one (UNEXPECTED_DISCLOSURE)."""
    referenced = set(digests_in(payload))
    # nested digests inside disclosed values are referenced too
    for dg in resolved.used:
        referenced.update(digests_in(resolved.available[dg][-1]))
    missing = referenced - set(resolved.available)
    return Reason.DISCLOSURE_DIGEST_MISMATCH if missing else Reason.UNEXPECTED_DISCLOSURE


def _select_content(claims: Dict[str, Any], resolved, raw_payload: Dict[str, Any]):
    """Return (content, digest). For a KB-SD-JWT the content is the single disclosed
    ``delegate_payload`` element; for a plain credential it is the claim set."""
    if "delegate_payload" not in raw_payload:
        return claims, None
    dp_raw = raw_payload.get("delegate_payload")
    dp = claims.get("delegate_payload")
    if not isinstance(dp_raw, list) or not isinstance(dp, list):
        return None, None
    if len(dp_raw) > 1:
        # all elements must be disclosures and exactly one disclosed
        if not all(isinstance(e, dict) and set(e.keys()) == {"..."} for e in dp_raw):
            return None, None
        if len(dp) != 1:
            return None, None
        disclosed_digest = next(d for d in (e["..."] for e in dp_raw) if d in resolved.used)
        return dp[0], disclosed_digest
    if len(dp_raw) == 1:
        if len(dp) != 1 or not isinstance(dp[0], dict):
            return None, None
        e = dp_raw[0]
        dg = e["..."] if isinstance(e, dict) and set(e.keys()) == {"..."} else None
        return dp[0], dg
    return None, None


# --------------------------------------------------------------------------- #
# AP2 mandate rules per role
# --------------------------------------------------------------------------- #

_OPEN_META_KEYS = {"vct", "constraints", "cnf", "iat", "exp", "_sd", "_sd_alg"}


def _unchanged_claims(open_content: Dict[str, Any], closed: Dict[str, Any]) -> Optional[str]:
    """Agent Authorization rule 2: claims present in the open mandate must be unchanged
    in the closed mandate."""
    for k, v in open_content.items():
        if k in _OPEN_META_KEYS:
            continue
        if closed.get(k) != v:
            return k
    return None


def verify_presentation(
    role: str,
    compact: str,
    trust: TrustStore,
    expect: VerifyExpectations,
    *,
    expected_intermediate_aud: Optional[str] = None,
    skip_issuer_signature: bool = False,
) -> ProfileVerification:
    pv = ProfileVerification()
    chain = verify_chain(compact, trust, expect, expected_intermediate_aud=expected_intermediate_aud,
                         skip_issuer_signature=skip_issuer_signature)
    for reason, detail in chain.errors:
        pv.fail(reason, detail)
    if not chain.ok:
        return pv
    pv.crypto_valid = True
    pv.issuer_id = chain.issuer_id
    final = chain.links[-1]
    opens = chain.links[1:-1]
    pv.mode = "autonomous" if opens else "direct"
    pv.final_artifact_hash = final.link.sd_hash()
    credential = chain.links[0]
    cred_cnf = credential.content.get("cnf", {}).get("jwk") if isinstance(credential.content, dict) else None
    if isinstance(cred_cnf, dict) and cred_cnf.get("kty"):
        pv.user_key_thumbprint = jwk_thumbprint(cred_cnf)
    if opens:
        pv.agent_key_thumbprint = jwk_thumbprint(final.signer_jwk)
        pv.open_mandate_digest = opens[-1].content_digest
    else:
        pv.agent_key_thumbprint = None
    closed = final.content
    pv.closed_claims = closed
    pv.details["final_nonce"] = final.payload.get("nonce")
    pv.details["final_aud"] = final.payload.get("aud")
    pv.disclosed = {
        "links": [
            {"header": vl.header, "payload": vl.payload, "resolved": vl.claims} for vl in chain.links
        ]
    }
    if opens and len(opens) > 1:
        return pv.fail(Reason.MALFORMED_ARTIFACT, "AP2 defines a single delegation step; agent-to-agent chains are out of scope")

    open_content = opens[0].content if opens else None
    if role == "merchant":
        _verify_checkout_side(pv, closed, open_content, trust, expect)
    elif role == "payment":
        _verify_payment_side(pv, closed, open_content, expect)
    else:
        return pv.fail(Reason.MALFORMED_ARTIFACT, f"unknown role {role}")
    pv.protocol_valid = not pv.reasons
    return pv


def _verify_checkout_side(pv: ProfileVerification, closed: Dict[str, Any], open_content: Optional[Dict[str, Any]],
                          trust: TrustStore, expect: VerifyExpectations) -> None:
    if closed.get("vct") != M.VCT_CHECKOUT:
        pv.fail(Reason.MANDATE_TYPE_MISMATCH, f"closed checkout mandate vct {closed.get('vct')!r}")
        return
    cj = closed.get("checkout_jwt")
    if not isinstance(cj, str):
        pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, "checkout_jwt is not disclosed to the merchant")
        return
    ch = closed.get("checkout_hash")
    if ch != checkout_hash(cj):
        pv.fail(Reason.CHECKOUT_BINDING_MISMATCH, "checkout_hash does not match the disclosed checkout_jwt")
    pv.checkout_hash = ch if isinstance(ch, str) else None
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
    pv.expires_at = closed.get("exp") if isinstance(closed.get("exp"), int) else None
    if open_content is None:
        return
    if open_content.get("vct") != M.VCT_CHECKOUT_OPEN:
        pv.fail(Reason.MANDATE_TYPE_MISMATCH, f"open checkout mandate vct {open_content.get('vct')!r}")
        return
    changed = _unchanged_claims(open_content, closed)
    if changed:
        pv.fail(Reason.CHECKOUT_BINDING_MISMATCH, f"closed mandate changed open claim {changed!r}")
    constraints = open_content.get("constraints") or []
    pv.open_constraints = constraints
    if not isinstance(constraints, list):
        pv.fail(Reason.MALFORMED_ARTIFACT, "constraints must be an array")
        return
    for c in constraints:
        ctype = c.get("type") if isinstance(c, dict) else None
        if ctype == M.CT_ALLOWED_MERCHANTS:
            allowed = [m for m in (c.get("allowed") or []) if isinstance(m, dict) and "id" in m]
            ok = any(m.get("id") == summary.merchant["id"] and m.get("name", summary.merchant["name"]) == summary.merchant["name"]
                     for m in allowed)
            pv.constraint_results.append(ConstraintResult(ctype, ok,
                                                          "merchant present in revealed allowed[]" if ok else
                                                          "merchant not among revealed allowed merchants"))
        elif ctype == M.CT_LINE_ITEMS:
            items = c.get("items") or []
            ok = line_items_satisfy(items, summary.line_items)
            pv.constraint_results.append(ConstraintResult(ctype, ok, "line items match" if ok else
                                                          "checkout line items do not satisfy the requirement set"))
        else:
            pv.constraint_results.append(ConstraintResult(str(ctype), False, "unknown constraint type"))
            pv.fail(Reason.UNKNOWN_CONSTRAINT, f"checkout constraint {ctype!r}")
    if not any(cr.type == M.CT_ALLOWED_MERCHANTS for cr in pv.constraint_results):
        pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, "open checkout mandate has no allowed_merchants constraint")


def _verify_payment_side(pv: ProfileVerification, closed: Dict[str, Any], open_content: Optional[Dict[str, Any]],
                         expect: VerifyExpectations) -> None:
    if closed.get("vct") != M.VCT_PAYMENT:
        pv.fail(Reason.MANDATE_TYPE_MISMATCH, f"closed payment mandate vct {closed.get('vct')!r}")
        return
    tx = closed.get("transaction_id")
    payee = closed.get("payee")
    amount = closed.get("payment_amount")
    instrument = closed.get("payment_instrument")
    if not isinstance(tx, str) or not isinstance(payee, dict) or not isinstance(amount, dict) or not isinstance(instrument, dict):
        pv.fail(Reason.MALFORMED_ARTIFACT, "closed payment mandate missing required fields")
        return
    if not isinstance(amount.get("amount"), int) or isinstance(amount.get("amount"), bool) or \
            not isinstance(amount.get("currency"), str):
        pv.fail(Reason.MALFORMED_ARTIFACT, "payment_amount must be {amount: integer minor units, currency}")
        return
    pv.transaction_id = tx
    pv.payee = payee
    pv.amount_minor = int(amount["amount"])
    pv.currency = amount["currency"]
    pv.details["payment_instrument"] = instrument
    pv.expires_at = closed.get("exp") if isinstance(closed.get("exp"), int) else None
    if expect.expected_checkout_hash is not None and tx != expect.expected_checkout_hash:
        pv.fail(Reason.PAYMENT_BINDING_MISMATCH, "transaction_id does not match the checkout hash")
    if open_content is None:
        return
    if open_content.get("vct") != M.VCT_PAYMENT_OPEN:
        pv.fail(Reason.MANDATE_TYPE_MISMATCH, f"open payment mandate vct {open_content.get('vct')!r}")
        return
    changed = _unchanged_claims(open_content, closed)
    if changed:
        pv.fail(Reason.PAYMENT_INSTRUMENT_NOT_ALLOWED if changed == "payment_instrument" else Reason.PAYMENT_BINDING_MISMATCH,
                f"closed mandate changed open claim {changed!r}")
    constraints = open_content.get("constraints") or []
    pv.open_constraints = constraints
    if not isinstance(constraints, list):
        pv.fail(Reason.MALFORMED_ARTIFACT, "constraints must be an array")
        return
    for c in constraints:
        ctype = c.get("type") if isinstance(c, dict) else None
        if ctype == M.CT_AMOUNT_RANGE:
            ok = (c.get("currency") == pv.currency and isinstance(c.get("max"), (int, float))
                  and pv.amount_minor <= c["max"] and pv.amount_minor >= (c.get("min") or 0))
            pv.constraint_results.append(ConstraintResult(ctype, ok, f"amount {pv.amount_minor} within [{c.get('min', 0)}, {c.get('max')}] {c.get('currency')}"
                                                          if ok else f"amount {pv.amount_minor} {pv.currency} outside [{c.get('min', 0)}, {c.get('max')}] {c.get('currency')}"))
        elif ctype == M.CT_ALLOWED_PAYEES:
            allowed = [m for m in (c.get("allowed") or []) if isinstance(m, dict)]
            ok = any(m.get("id") == payee.get("id") and m.get("name") == payee.get("name") for m in allowed)
            pv.constraint_results.append(ConstraintResult(ctype, ok, "payee present in revealed allowed[]" if ok else
                                                          "payee not among revealed allowed payees"))
        elif ctype == M.CT_REFERENCE:
            ref = c.get("conditional_transaction_id")
            ok = isinstance(ref, str) and bool(ref)
            pv.reference_digest = ref if ok else None
            pv.constraint_results.append(ConstraintResult(ctype, ok, "reference recorded for cross-view binding"
                                                          if ok else "missing conditional_transaction_id"))
        elif ctype == M.CT_EXECUTION_DATE:
            from aaw_domain.clock import parse_iso8601

            try:
                nb = c.get("not_before")
                na = c.get("not_after")
                ok = True
                if nb:
                    ok = ok and expect.now >= int(parse_iso8601(nb).timestamp())
                if na:
                    ok = ok and expect.now <= int(parse_iso8601(na).timestamp())
            except ValueError:
                ok = False
            pv.constraint_results.append(ConstraintResult(ctype, ok, "execution time within window" if ok else
                                                          "execution time outside window"))
        elif ctype == M.CT_ALLOWED_INSTRUMENTS:
            allowed = [m for m in (c.get("allowed") or []) if isinstance(m, dict)]
            ok = any(m.get("id") == instrument.get("id") and m.get("type") == instrument.get("type") for m in allowed)
            pv.constraint_results.append(ConstraintResult(ctype, ok, "instrument allowed" if ok else "instrument not allowed"))
        elif ctype in UNSUPPORTED_PAYMENT_CONSTRAINTS:
            pv.constraint_results.append(ConstraintResult(str(ctype), False, "constraint defined by AP2 but unsupported by this single-purchase profile"))
            pv.fail(Reason.UNKNOWN_CONSTRAINT, f"payment constraint {ctype!r} unsupported")
        else:
            pv.constraint_results.append(ConstraintResult(str(ctype), False, "unknown constraint type"))
            pv.fail(Reason.UNKNOWN_CONSTRAINT, f"payment constraint {ctype!r}")
    if not any(cr.type == M.CT_AMOUNT_RANGE for cr in pv.constraint_results):
        pv.fail(Reason.MISSING_REQUIRED_DISCLOSURE, "open payment mandate has no amount_range constraint")
