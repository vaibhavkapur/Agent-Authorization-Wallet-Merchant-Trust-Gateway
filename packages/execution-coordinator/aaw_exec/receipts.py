"""Receipt signing for the coordinator.

AP2 defines Checkout/Payment Receipts (verifier-signed JWTs referencing the
closed mandate hash). Verifiable Intent leaves receipts/transport out of scope,
so for VI the same fields are issued as an *application* receipt with a
distinct ``typ`` so nobody mistakes it for a protocol artifact.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aaw_ap2.receipts import TYP_RECEIPT as AP2_TYP_RECEIPT
from aaw_ap2.receipts import sign_checkout_receipt, sign_payment_receipt
from aaw_signer import KeyHandle, sign_compact

APP_TYP_RECEIPT = "aaw-receipt+jwt"


def sign_receipt(
    handle: KeyHandle,
    issuer_id: str,
    profile: str,
    kind: str,
    reference: str,
    status: str,
    now: int,
    *,
    order_id: Optional[str] = None,
    payment_id: Optional[str] = None,
    psp_confirmation_id: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
) -> str:
    if profile == "ap2":
        if kind == "checkout":
            return sign_checkout_receipt(handle, issuer_id, reference, now, order_id=order_id,
                                         error=error if status == "Error" else None,
                                         error_description=error_description)
        return sign_payment_receipt(handle, issuer_id, reference, now, payment_id or "",
                                    psp_confirmation_id=psp_confirmation_id,
                                    error=error if status == "Error" else None,
                                    error_description=error_description)
    payload: Dict[str, Any] = {
        "iss": issuer_id,
        "iat": now,
        "reference": reference,
        "profile": profile,
        "receipt_type": kind,
        "status": status,
    }
    if status == "Error":
        payload["error"] = error or "invalid_mandate"
        payload["error_description"] = error_description or payload["error"]
    else:
        if kind == "checkout":
            payload["order_id"] = order_id
        else:
            payload["psp_confirmation_id"] = psp_confirmation_id
    if kind == "payment":
        payload["payment_id"] = payment_id
    return sign_compact(handle, {"typ": APP_TYP_RECEIPT, "kid": handle.kid}, payload)


RECEIPT_TYPS = {"ap2": AP2_TYP_RECEIPT, "vi": APP_TYP_RECEIPT}
