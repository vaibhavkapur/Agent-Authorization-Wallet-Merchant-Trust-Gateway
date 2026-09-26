"""Merchant-signed final checkout JWT.

The checkout object is outside the scope of AP2, VI and TAP (it belongs to the
commerce protocol). Both profiles bind to it by ``base64url(sha-256(checkout_jwt))``.
The merchant signs with ES256 (AP2 requires a non-deterministic signature scheme
for the checkout JWT to prevent rainbow-table attacks on the hash).

Payload (``typ: "JWT"``)::

    {
      "iss": "<merchant website>", "sub": "checkout", "jti": "<checkout id>",
      "iat": ..., "exp": ...,
      "merchant": {"id", "name", "website"},
      "line_items": [{"id", "title", "quantity", "unit_price_minor", "currency"}],
      "total_minor": 12000, "currency": "USD"
    }
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from aaw_signer import KeyHandle, SignatureError, b64url_encode, peek_header, peek_payload, sign_compact
from aaw_signer.jws import verify_compact_json

from .models import new_id
from .outcomes import Reason
from .profiles import CheckoutSummary
from .trust import PARTICIPANT_MERCHANT, TrustError, TrustStore

CHECKOUT_TTL_SECONDS = 3600
MAX_CHECKOUT_BYTES = 64 * 1024


def checkout_hash(checkout_jwt: str) -> str:
    return b64url_encode(hashlib.sha256(checkout_jwt.encode("ascii")).digest())


def build_checkout_jwt(
    merchant_handle: KeyHandle,
    merchant: Dict[str, Any],
    line_items: List[Dict[str, Any]],
    currency: str,
    now: int,
    checkout_id: Optional[str] = None,
    ttl: int = CHECKOUT_TTL_SECONDS,
) -> str:
    items = []
    total = 0
    for li in line_items:
        qty = int(li["quantity"])
        unit = int(li["unit_price_minor"])
        if qty <= 0 or unit < 0:
            raise ValueError("invalid line item")
        total += qty * unit
        items.append({"id": str(li["id"]), "title": str(li["title"]), "quantity": qty,
                      "unit_price_minor": unit, "currency": currency})
    payload = {
        "iss": merchant["website"],
        "sub": "checkout",
        "jti": checkout_id or new_id("co"),
        "iat": now,
        "exp": now + ttl,
        "merchant": {"id": merchant["id"], "name": merchant["name"], "website": merchant["website"]},
        "line_items": items,
        "total_minor": total,
        "currency": currency,
    }
    return sign_compact(merchant_handle, {"typ": "JWT", "kid": merchant_handle.kid}, payload)


class CheckoutError(Exception):
    def __init__(self, reason: Reason, message: str):
        super().__init__(message)
        self.reason = reason


def parse_checkout_jwt(checkout_jwt: str, trust: TrustStore, now: int, allow_retired: bool = False) -> CheckoutSummary:
    """Verify merchant signature via the trust store and resolve all amounts deterministically."""
    if not isinstance(checkout_jwt, str) or len(checkout_jwt) > MAX_CHECKOUT_BYTES:
        raise CheckoutError(Reason.INPUT_TOO_LARGE, "checkout jwt too large or not a string")
    try:
        header = peek_header(checkout_jwt)
        unverified = peek_payload(checkout_jwt)
    except SignatureError as exc:
        raise CheckoutError(Reason.MALFORMED_ARTIFACT, str(exc)) from exc
    merchant = unverified.get("merchant") if isinstance(unverified, dict) else None
    if not isinstance(merchant, dict) or not merchant.get("id"):
        raise CheckoutError(Reason.MALFORMED_ARTIFACT, "checkout missing merchant.id")
    try:
        key = trust.resolve(PARTICIPANT_MERCHANT, str(merchant["id"]), header.get("kid"), "ES256", at=now,
                            allow_retired=allow_retired, unknown_reason=Reason.UNKNOWN_MERCHANT_KEY)
    except TrustError as exc:
        raise CheckoutError(exc.reason, str(exc)) from exc
    try:
        _, payload = verify_compact_json(checkout_jwt, key.public_jwk, allowed_algs=("ES256",), expected_typ="JWT")
    except SignatureError as exc:
        raise CheckoutError(Reason(exc.code) if exc.code in Reason.__members__ else Reason.INVALID_SIGNATURE,
                            str(exc)) from exc
    try:
        items = payload["line_items"]
        currency = payload["currency"]
        total = int(payload["total_minor"])
        if not isinstance(items, list) or not items:
            raise ValueError("line_items must be a non-empty array")
        computed = 0
        norm_items = []
        for li in items:
            qty = int(li["quantity"])
            unit = int(li["unit_price_minor"])
            if qty <= 0 or unit < 0 or li.get("currency", currency) != currency:
                raise ValueError("invalid line item")
            computed += qty * unit
            norm_items.append({"id": str(li["id"]), "title": str(li["title"]), "quantity": qty, "unit_price_minor": unit})
        if computed != total:
            raise ValueError("total_minor does not equal the sum of line items")
        if not isinstance(currency, str) or len(currency) != 3:
            raise ValueError("invalid currency")
        exp = int(payload["exp"])
        iat = int(payload["iat"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CheckoutError(Reason.MALFORMED_ARTIFACT, f"invalid checkout payload: {exc}") from exc
    if now > exp:
        raise CheckoutError(Reason.EXPIRED_AUTHORIZATION, "checkout expired")
    return CheckoutSummary(
        checkout_jwt=checkout_jwt,
        checkout_hash=checkout_hash(checkout_jwt),
        merchant={"id": str(merchant["id"]), "name": str(merchant.get("name", "")), "website": str(merchant.get("website", ""))},
        merchant_kid=str(header.get("kid")),
        line_items=norm_items,
        total_minor=total,
        currency=currency,
        checkout_id=str(payload.get("jti", "")),
        issued_at=iat,
        expires_at=exp,
    )


def checkout_payload_unverified(checkout_jwt: str) -> Dict[str, Any]:
    return peek_payload(checkout_jwt)


__all__ = ["build_checkout_jwt", "parse_checkout_jwt", "checkout_hash", "CheckoutError", "checkout_payload_unverified"]
