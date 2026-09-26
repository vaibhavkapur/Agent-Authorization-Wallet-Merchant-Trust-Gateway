"""AP2 v0.2 mandate construction (Checkout Mandate, Payment Mandate) as a
Delegate SD-JWT chain under the *User Credential* delegation model:

    issuer SD-JWT (user credential, cnf = user device key)
      ~~ KB-SD-JWT(+KB) signed by the user device key
           delegate_payload = [open/closed checkout mandate, open/closed payment mandate]
      ~~ KB-SD-JWT signed by the agent key (autonomous mode only)
           delegate_payload = [closed mandate]

Normative references pinned in docs/protocol-versions/ap2.md. Constraint types
and ``vct`` values are copied verbatim from the specification pages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aaw_domain.checkout import checkout_hash
from aaw_domain.constraints import GrantConstraints
from aaw_signer import KeyHandle, sign_compact

from .sdjwt import SD_ALG, Link, digest_disclosure, make_disclosure, sd_ref

VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
VCT_CHECKOUT = "mandate.checkout.1"
VCT_PAYMENT_OPEN = "mandate.payment.open.1"
VCT_PAYMENT = "mandate.payment.1"

CT_ALLOWED_MERCHANTS = "checkout.allowed_merchants"
CT_LINE_ITEMS = "checkout.line_items"
CT_AMOUNT_RANGE = "payment.amount_range"
CT_ALLOWED_PAYEES = "payment.allowed_payees"
CT_REFERENCE = "payment.reference"
CT_EXECUTION_DATE = "payment.execution_date"
CT_ALLOWED_INSTRUMENTS = "payment.allowed_payment_instruments"
CT_ALLOWED_PISPS = "payment.allowed_pisps"
CT_AGENT_RECURRENCE = "payment.agent_recurrence"
CT_BUDGET = "payment.budget"

USER_CREDENTIAL_VCT = "urn:aaw:test:user-credential:1"
TYP_SD_JWT = "dc+sd-jwt"
TYP_KB_SD_JWT = "kb+sd-jwt"
TYP_KB_SD_JWT_KB = "kb+sd-jwt+kb"


def public_only(jwk: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in jwk.items() if k in ("kty", "crv", "x", "y", "kid")}


# --------------------------------------------------------------------------- #
# Test issuer: user credential
# --------------------------------------------------------------------------- #


def build_user_credential(
    issuer_handle: KeyHandle,
    issuer_id: str,
    user_id: str,
    user_public_jwk: Dict[str, Any],
    now: int,
    exp: int,
    disclosable_claims: Optional[Dict[str, Any]] = None,
) -> Link:
    disclosures = [make_disclosure(v, name=k) for k, v in (disclosable_claims or {}).items()]
    payload: Dict[str, Any] = {
        "iss": issuer_id,
        "sub": user_id,
        "iat": now,
        "exp": exp,
        "vct": USER_CREDENTIAL_VCT,
        "cnf": {"jwk": public_only(user_public_jwk)},
        "_sd_alg": SD_ALG,
    }
    if disclosures:
        payload["_sd"] = sorted(digest_disclosure(d) for d in disclosures)
    jwt = sign_compact(issuer_handle, {"typ": TYP_SD_JWT, "kid": issuer_handle.kid}, payload)
    return Link(jwt, disclosures)


# --------------------------------------------------------------------------- #
# User signing component: open mandates (autonomous)
# --------------------------------------------------------------------------- #


@dataclass
class OpenMandateSet:
    link: Link
    checkout_digest: str
    payment_digest: str
    merchant_checkout_digests: Dict[str, str] = field(default_factory=dict)  # merchant id -> allowed[] digest
    merchant_payee_digests: Dict[str, str] = field(default_factory=dict)
    item_digests: Dict[str, str] = field(default_factory=dict)  # item id -> acceptable_items[] digest

    def index(self) -> Dict[str, Any]:
        return {
            "checkout_digest": self.checkout_digest,
            "payment_digest": self.payment_digest,
            "merchant_checkout_digests": self.merchant_checkout_digests,
            "merchant_payee_digests": self.merchant_payee_digests,
            "item_digests": self.item_digests,
        }


def build_open_mandates(
    user_handle: KeyHandle,
    l1_presented: Link,
    constraints: GrantConstraints,
    agent_public_jwk: Dict[str, Any],
    now: int,
    aud: str,
    nonce: str,
) -> OpenMandateSet:
    exp = constraints.expires_ts
    cnf = {"jwk": public_only(agent_public_jwk)}

    merchant_checkout_digests: Dict[str, str] = {}
    merchant_payee_digests: Dict[str, str] = {}
    item_digests: Dict[str, str] = {}
    disclosures: List[str] = []

    allowed_refs = []
    for m in constraints.merchants:
        d = make_disclosure(m.as_protocol())
        disclosures.append(d)
        merchant_checkout_digests[m.id] = digest_disclosure(d)
        allowed_refs.append(sd_ref(digest_disclosure(d)))

    checkout_constraints: List[Dict[str, Any]] = [{"type": CT_ALLOWED_MERCHANTS, "allowed": allowed_refs}]
    if constraints.line_items:
        items = []
        for req in constraints.line_items:
            acceptable = []
            for it in req.acceptable_items:
                d = make_disclosure({"id": it.id, "title": it.title})
                disclosures.append(d)
                item_digests[it.id] = digest_disclosure(d)
                acceptable.append(sd_ref(digest_disclosure(d)))
            items.append({"id": req.id, "acceptable_items": acceptable, "quantity": req.quantity})
        checkout_constraints.append({"type": CT_LINE_ITEMS, "items": items})

    open_checkout = {
        "vct": VCT_CHECKOUT_OPEN,
        "constraints": checkout_constraints,
        "cnf": cnf,
        "iat": now,
        "exp": exp,
    }
    co_disc = make_disclosure(open_checkout)
    disclosures.append(co_disc)
    checkout_digest = digest_disclosure(co_disc)

    payee_refs = []
    for m in constraints.merchants:
        d = make_disclosure(m.as_protocol())
        disclosures.append(d)
        merchant_payee_digests[m.id] = digest_disclosure(d)
        payee_refs.append(sd_ref(digest_disclosure(d)))

    open_payment = {
        "vct": VCT_PAYMENT_OPEN,
        "constraints": [
            {"type": CT_AMOUNT_RANGE, "currency": constraints.currency, "max": constraints.max_minor,
             "min": constraints.min_minor},
            {"type": CT_ALLOWED_PAYEES, "allowed": payee_refs},
            {"type": CT_REFERENCE, "conditional_transaction_id": checkout_digest},
            {"type": CT_EXECUTION_DATE, "not_before": constraints.not_before, "not_after": constraints.expires_at},
        ],
        "payment_instrument": constraints.payment_instrument.as_protocol(),
        "cnf": cnf,
        "iat": now,
        "exp": exp,
    }
    po_disc = make_disclosure(open_payment)
    disclosures.append(po_disc)
    payment_digest = digest_disclosure(po_disc)

    payload = {
        "delegate_payload": [sd_ref(checkout_digest), sd_ref(payment_digest)],
        "iat": now,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": l1_presented.sd_hash(),
        "_sd_alg": SD_ALG,
    }
    jwt = sign_compact(user_handle, {"typ": TYP_KB_SD_JWT_KB, "kid": user_handle.kid}, payload)
    return OpenMandateSet(
        link=Link(jwt, disclosures),
        checkout_digest=checkout_digest,
        payment_digest=payment_digest,
        merchant_checkout_digests=merchant_checkout_digests,
        merchant_payee_digests=merchant_payee_digests,
        item_digests=item_digests,
    )


# --------------------------------------------------------------------------- #
# Closed mandate content
# --------------------------------------------------------------------------- #


def closed_checkout_content(checkout_jwt: str, now: int, exp: int) -> Dict[str, Any]:
    """Returns ``(content_with_sd, checkout_jwt_disclosure)`` packed in a dict."""
    cj_disc = make_disclosure(checkout_jwt, name="checkout_jwt")
    content = {
        "_sd": [digest_disclosure(cj_disc)],
        "vct": VCT_CHECKOUT,
        "checkout_hash": checkout_hash(checkout_jwt),
        "iat": now,
        "exp": exp,
    }
    return {"content": content, "checkout_jwt_disclosure": cj_disc}


def closed_payment_content(
    transaction_id: str,
    payee: Dict[str, Any],
    amount_minor: int,
    currency: str,
    payment_instrument: Dict[str, Any],
    now: int,
    exp: int,
) -> Dict[str, Any]:
    return {
        "vct": VCT_PAYMENT,
        "transaction_id": transaction_id,
        "payee": payee,
        "payment_amount": {"amount": int(amount_minor), "currency": currency},
        "payment_instrument": payment_instrument,
        "iat": now,
        "exp": exp,
    }


# --------------------------------------------------------------------------- #
# User signing component: closed mandates (direct / human present)
# --------------------------------------------------------------------------- #


@dataclass
class DirectMandateSet:
    link: Link
    checkout_digest: str
    payment_digest: str
    checkout_jwt_digest: str

    def index(self) -> Dict[str, Any]:
        return {
            "checkout_digest": self.checkout_digest,
            "payment_digest": self.payment_digest,
            "checkout_jwt_digest": self.checkout_jwt_digest,
        }


def build_closed_mandates_direct(
    user_handle: KeyHandle,
    l1_presented: Link,
    checkout_jwt: str,
    payee: Dict[str, Any],
    amount_minor: int,
    currency: str,
    payment_instrument: Dict[str, Any],
    now: int,
    exp: int,
    aud: List[str],
    nonce: str,
) -> DirectMandateSet:
    co = closed_checkout_content(checkout_jwt, now, exp)
    co_disc = make_disclosure(co["content"])
    po_disc = make_disclosure(
        closed_payment_content(checkout_hash(checkout_jwt), payee, amount_minor, currency, payment_instrument, now, exp)
    )
    payload = {
        "delegate_payload": [sd_ref(digest_disclosure(co_disc)), sd_ref(digest_disclosure(po_disc))],
        "iat": now,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": l1_presented.sd_hash(),
        "_sd_alg": SD_ALG,
    }
    jwt = sign_compact(user_handle, {"typ": TYP_KB_SD_JWT, "kid": user_handle.kid}, payload)
    return DirectMandateSet(
        link=Link(jwt, [co_disc, co["checkout_jwt_disclosure"], po_disc]),
        checkout_digest=digest_disclosure(co_disc),
        payment_digest=digest_disclosure(po_disc),
        checkout_jwt_digest=digest_disclosure(co["checkout_jwt_disclosure"]),
    )


# --------------------------------------------------------------------------- #
# Agent signer: closed mandates (autonomous)
# --------------------------------------------------------------------------- #


def build_closed_checkout(
    agent_handle: KeyHandle,
    open_presented: Link,
    checkout_jwt: str,
    aud: str,
    nonce: str,
    now: int,
    exp: int,
) -> Link:
    co = closed_checkout_content(checkout_jwt, now, exp)
    co_disc = make_disclosure(co["content"])
    payload = {
        "delegate_payload": [sd_ref(digest_disclosure(co_disc))],
        "iat": now,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": open_presented.sd_hash(),
        "_sd_alg": SD_ALG,
    }
    jwt = sign_compact(agent_handle, {"typ": TYP_KB_SD_JWT, "kid": agent_handle.kid}, payload)
    return Link(jwt, [co_disc, co["checkout_jwt_disclosure"]])


def build_closed_payment(
    agent_handle: KeyHandle,
    open_presented: Link,
    transaction_id: str,
    payee: Dict[str, Any],
    amount_minor: int,
    currency: str,
    payment_instrument: Dict[str, Any],
    aud: str,
    nonce: str,
    now: int,
    exp: int,
) -> Link:
    po_disc = make_disclosure(
        closed_payment_content(transaction_id, payee, amount_minor, currency, payment_instrument, now, exp)
    )
    payload = {
        "delegate_payload": [sd_ref(digest_disclosure(po_disc))],
        "iat": now,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": open_presented.sd_hash(),
        "_sd_alg": SD_ALG,
    }
    jwt = sign_compact(agent_handle, {"typ": TYP_KB_SD_JWT, "kid": agent_handle.kid}, payload)
    return Link(jwt, [po_disc])
