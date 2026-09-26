"""Application-level grant constraints and the deterministic consent snapshot.

The consent snapshot is the immutable representation the user reviews. It is
rendered from validated data only (plan §8) and its digest is bound to the
consent challenge and to every protocol artifact produced from it.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .clock import parse_iso8601, to_utc_iso

SNAPSHOT_SCHEMA = "aaw.consent_snapshot.1"

MERCHANT_FIELDS = ["checkout (line items, quantities, merchant total)", "authorization evidence for this checkout",
                   "your delegated agent's public key"]
PAYMENT_FIELDS = ["payee identity", "payment amount and currency", "payment instrument reference",
                  "checkout transaction identifier (hash only)"]
NEVER_SHARED = ["your other permitted merchants", "your identity claims in the issuer credential",
                "your spending cap (payment participants receive only the exact amount)"]


class MerchantRef(BaseModel):
    id: str
    name: str
    website: Optional[str] = None

    def as_protocol(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "name": self.name}
        if self.website:
            d["website"] = self.website
        return d


class ItemRef(BaseModel):
    id: str
    title: str


class LineItemRequirement(BaseModel):
    id: str
    acceptable_items: List[ItemRef] = Field(min_length=1)
    quantity: int = Field(ge=1, le=100)


class PaymentInstrument(BaseModel):
    id: str = "test-instrument-1"
    type: str = "card"
    description: str = "Test card ···· 4242"

    def as_protocol(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type, "description": self.description}


class GrantConstraints(BaseModel):
    """Validated constraints stored in ``authorization_grants.constraints_json``."""

    purchase_count: Literal[1] = 1
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    max_total_minor: str = Field(pattern=r"^[0-9]{1,12}$")
    min_total_minor: str = Field(default="0", pattern=r"^[0-9]{1,12}$")
    merchants: List[MerchantRef] = Field(min_length=1, max_length=10)
    not_before: str
    expires_at: str
    line_items: Optional[List[LineItemRequirement]] = None
    payment_instrument: PaymentInstrument = Field(default_factory=PaymentInstrument)

    @field_validator("not_before", "expires_at")
    @classmethod
    def _tz_required(cls, v: str) -> str:
        parse_iso8601(v)
        return v

    @model_validator(mode="after")
    def _window(self) -> "GrantConstraints":
        if parse_iso8601(self.expires_at) <= parse_iso8601(self.not_before):
            raise ValueError("expires_at must be after not_before")
        if int(self.min_total_minor) > int(self.max_total_minor):
            raise ValueError("min_total_minor exceeds max_total_minor")
        return self

    # helpers -----------------------------------------------------------------
    @property
    def max_minor(self) -> int:
        return int(self.max_total_minor)

    @property
    def min_minor(self) -> int:
        return int(self.min_total_minor)

    @property
    def not_before_ts(self) -> int:
        return int(parse_iso8601(self.not_before).timestamp())

    @property
    def expires_ts(self) -> int:
        return int(parse_iso8601(self.expires_at).timestamp())

    def merchant_ids(self) -> List[str]:
        return [m.id for m in self.merchants]


class ProposalRequest(BaseModel):
    """Body of ``POST /v1/authorization-proposals`` (application API, not a protocol message)."""

    user_id: str
    agent_id: str
    profile: Literal["ap2", "vi"]
    mode: Literal["direct", "autonomous"]
    purchase_count: Literal[1] = 1
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    max_total_minor: Optional[str] = Field(default=None, pattern=r"^[0-9]{1,12}$")
    min_total_minor: str = Field(default="0", pattern=r"^[0-9]{1,12}$")
    merchant_ids: List[str] = Field(default_factory=list, max_length=10)
    not_before: Optional[str] = None
    expires_at: Optional[str] = None
    line_items: Optional[List[LineItemRequirement]] = None
    payment_instrument: Optional[PaymentInstrument] = None
    # direct mode: the exact final checkout the user will approve
    checkout_reference: Optional[str] = None
    merchant_id: Optional[str] = None
    display_time_zone: str = Field(default="+05:30", pattern=r"^[+-][0-9]{2}:[0-9]{2}$")

    @model_validator(mode="after")
    def _mode_fields(self) -> "ProposalRequest":
        if self.mode == "autonomous":
            if not self.max_total_minor:
                raise ValueError("autonomous proposals require max_total_minor")
            if not self.merchant_ids:
                raise ValueError("autonomous proposals require merchant_ids")
            if not self.expires_at:
                raise ValueError("autonomous proposals require expires_at")
        else:
            if not self.checkout_reference:
                raise ValueError("direct proposals require checkout_reference")
            if not self.merchant_id:
                raise ValueError("direct proposals require merchant_id")
        return self


def format_amount(minor: int, currency: str) -> str:
    return f"{currency} {minor // 100}.{minor % 100:02d}"


def render_consent_snapshot(
    *,
    profile: str,
    profile_version: str,
    mode: str,
    agent: Dict[str, Any],
    constraints: GrantConstraints,
    display_time_zone: str,
    exact_checkout: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Deterministic review data (plan §8). Keys sorted at digest time."""
    from datetime import timedelta

    sign = 1 if display_time_zone[0] != "-" else -1
    hh, mm = display_time_zone[1:].split(":")
    tz = timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))

    def local(v: str) -> str:
        return parse_iso8601(v).astimezone(tz).isoformat()

    snapshot: Dict[str, Any] = {
        "schema": SNAPSHOT_SCHEMA,
        "profile": profile,
        "profile_version": profile_version,
        "mode": mode,
        "agent": {
            "id": agent["id"],
            "display_name": agent["display_name"],
            "provider": agent["provider"],
            "mandate_key_thumbprint": agent["mandate_key_thumbprint"],
        },
        "purchase_count": 1,
        "permitted_merchants": [m.model_dump(exclude_none=True) for m in constraints.merchants],
        "maximum_delivered_total": {
            "minor": constraints.max_total_minor,
            "currency": constraints.currency,
            "display": format_amount(constraints.max_minor, constraints.currency),
        },
        "validity": {
            "not_before_utc": to_utc_iso(parse_iso8601(constraints.not_before)),
            "expires_at_utc": to_utc_iso(parse_iso8601(constraints.expires_at)),
            "not_before_local": local(constraints.not_before),
            "expires_at_local": local(constraints.expires_at),
            "display_time_zone": display_time_zone,
        },
        "approval_type": "exact_items" if mode == "direct" else "constraints",
        "payment_instrument": constraints.payment_instrument.model_dump(),
        "data_sharing": {
            "merchant_receives": MERCHANT_FIELDS,
            "payment_receives": PAYMENT_FIELDS,
            "never_shared": NEVER_SHARED,
        },
        "simulated_participants_notice": (
            "Issuer, registry, merchants and payment processor are local test participants. "
            "Local verification is not network accreditation."
        ),
    }
    if constraints.line_items:
        snapshot["required_line_items"] = [li.model_dump() for li in constraints.line_items]
    if exact_checkout is not None:
        snapshot["exact_checkout"] = exact_checkout
    return snapshot
