"""AP2 Checkout Receipt and Payment Receipt (verifier-signed JWTs).

Schema per checkout_mandate.md / payment_mandate.md: ``status`` (Success|Error),
``iss``, ``iat``, ``reference`` (sd_hash-style digest of the closed mandate
presentation), ``error``/``error_description`` iff Error, ``order_id`` iff a
successful checkout receipt, ``payment_id`` (+ ``psp_confirmation_id``) for
payment receipts.

Error codes follow agent_authorization.md: ``invalid_credential``,
``unresolved_constraint``, ``invalid_mandate``, ``mandates_not_supported``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aaw_domain.outcomes import Reason
from aaw_domain.trust import PARTICIPANT_VERIFIER, TrustError, TrustStore
from aaw_signer import KeyHandle, SignatureError, peek_header, sign_compact
from aaw_signer.jws import verify_compact_json

TYP_RECEIPT = "ap2-receipt+jwt"

RECEIPT_ERROR_FOR_REASON = {
    Reason.UNKNOWN_CONSTRAINT: "unresolved_constraint",
    Reason.UNSUPPORTED_PROFILE: "mandates_not_supported",
}
CRYPTO_REASONS = {
    Reason.INVALID_SIGNATURE, Reason.UNSUPPORTED_ALGORITHM, Reason.UNKNOWN_ISSUER, Reason.DISCLOSURE_DIGEST_MISMATCH,
    Reason.MISSING_REQUIRED_DISCLOSURE, Reason.UNEXPECTED_DISCLOSURE, Reason.CHAIN_BINDING_MISMATCH,
    Reason.AGENT_KEY_MISMATCH, Reason.MALFORMED_ARTIFACT, Reason.AUDIENCE_MISMATCH, Reason.NONCE_MISMATCH,
    Reason.EXPIRED_AUTHORIZATION, Reason.MANDATE_TYPE_MISMATCH, Reason.INPUT_TOO_LARGE,
}


def receipt_error_code(reason_codes: list) -> str:
    reasons = [Reason(r) for r in reason_codes if r in Reason.__members__]
    for r in reasons:
        if r in RECEIPT_ERROR_FOR_REASON:
            return RECEIPT_ERROR_FOR_REASON[r]
    if any(r in CRYPTO_REASONS for r in reasons):
        return "invalid_credential"
    return "invalid_mandate"


def _sign(handle: KeyHandle, payload: Dict[str, Any]) -> str:
    return sign_compact(handle, {"typ": TYP_RECEIPT, "kid": handle.kid}, payload)


def sign_checkout_receipt(
    handle: KeyHandle,
    iss: str,
    reference: str,
    now: int,
    *,
    order_id: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
) -> str:
    payload: Dict[str, Any] = {"iss": iss, "iat": now, "reference": reference, "receipt_type": "checkout"}
    if error:
        payload.update({"status": "Error", "error": error, "error_description": error_description or error})
    else:
        payload.update({"status": "Success", "order_id": order_id})
    return _sign(handle, payload)


def sign_payment_receipt(
    handle: KeyHandle,
    iss: str,
    reference: str,
    now: int,
    payment_id: str,
    *,
    psp_confirmation_id: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
) -> str:
    payload: Dict[str, Any] = {"iss": iss, "iat": now, "reference": reference, "payment_id": payment_id,
                               "receipt_type": "payment"}
    if error:
        payload.update({"status": "Error", "error": error, "error_description": error_description or error})
    else:
        payload.update({"status": "Success", "psp_confirmation_id": psp_confirmation_id})
    return _sign(handle, payload)


def verify_receipt(token: str, trust: TrustStore, expected_issuer: str, now: int,
                   expected_reference: Optional[str] = None) -> Dict[str, Any]:
    header = peek_header(token)
    try:
        key = trust.resolve(PARTICIPANT_VERIFIER, expected_issuer, header.get("kid"), "ES256", at=now, allow_retired=True)
    except TrustError as exc:
        raise SignatureError(str(exc), code=exc.reason.value) from exc
    _, payload = verify_compact_json(token, key.public_jwk, allowed_algs=("ES256",), expected_typ=TYP_RECEIPT)
    if payload.get("iss") != expected_issuer:
        raise SignatureError("receipt iss mismatch", code="INVALID_SIGNATURE")
    if payload.get("status") not in ("Success", "Error"):
        raise SignatureError("receipt status invalid", code="MALFORMED_ARTIFACT")
    if (payload["status"] == "Error") != ("error" in payload):
        raise SignatureError("receipt error fields inconsistent with status", code="MALFORMED_ARTIFACT")
    if expected_reference is not None and payload.get("reference") != expected_reference:
        raise SignatureError("receipt reference does not match the closed mandate", code="CHAIN_BINDING_MISMATCH")
    return payload
