"""Application outcomes and reason codes (plan §12).

Cryptographic validity, protocol validity and application-policy eligibility are
reported separately: a valid signature can accompany an ineligible purchase.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

RULESET_VERSION = "aaw-ruleset-2026-09-26"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_NEW_AUTHORIZATION = "REQUIRE_NEW_AUTHORIZATION"
    DENY = "DENY"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class CheckStatus(str, Enum):
    VALID = "valid"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class Reason(str, Enum):
    # request authentication (TAP)
    REQUEST_SIGNATURE_MISSING = "REQUEST_SIGNATURE_MISSING"
    REQUEST_SIGNATURE_INVALID = "REQUEST_SIGNATURE_INVALID"
    REQUEST_SIGNATURE_MALFORMED = "REQUEST_SIGNATURE_MALFORMED"
    REQUEST_COVERAGE_INSUFFICIENT = "REQUEST_COVERAGE_INSUFFICIENT"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    REQUEST_NOT_YET_VALID = "REQUEST_NOT_YET_VALID"
    REQUEST_LIFETIME_TOO_LONG = "REQUEST_LIFETIME_TOO_LONG"
    REQUEST_REPLAY = "REQUEST_REPLAY"
    UNKNOWN_AGENT_KEY = "UNKNOWN_AGENT_KEY"
    AGENT_KEY_INACTIVE = "AGENT_KEY_INACTIVE"
    CONTENT_DIGEST_MISMATCH = "CONTENT_DIGEST_MISMATCH"
    OPERATION_CONTEXT_MISMATCH = "OPERATION_CONTEXT_MISMATCH"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    # delegation / cryptographic
    UNSUPPORTED_PROFILE = "UNSUPPORTED_PROFILE"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    MALFORMED_ARTIFACT = "MALFORMED_ARTIFACT"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    UNKNOWN_MERCHANT_KEY = "UNKNOWN_MERCHANT_KEY"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    DISCLOSURE_DIGEST_MISMATCH = "DISCLOSURE_DIGEST_MISMATCH"
    MISSING_REQUIRED_DISCLOSURE = "MISSING_REQUIRED_DISCLOSURE"
    UNEXPECTED_DISCLOSURE = "UNEXPECTED_DISCLOSURE"
    CHAIN_BINDING_MISMATCH = "CHAIN_BINDING_MISMATCH"
    AGENT_KEY_MISMATCH = "AGENT_KEY_MISMATCH"
    EXPIRED_AUTHORIZATION = "EXPIRED_AUTHORIZATION"
    AUTHORIZATION_NOT_YET_VALID = "AUTHORIZATION_NOT_YET_VALID"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    MANDATE_TYPE_MISMATCH = "MANDATE_TYPE_MISMATCH"
    UNKNOWN_CONSTRAINT = "UNKNOWN_CONSTRAINT"
    # binding
    CHECKOUT_BINDING_MISMATCH = "CHECKOUT_BINDING_MISMATCH"
    PAYMENT_BINDING_MISMATCH = "PAYMENT_BINDING_MISMATCH"
    REFERENCE_MISMATCH = "REFERENCE_MISMATCH"
    # constraints / application policy
    DELIVERED_TOTAL_EXCEEDS_LIMIT = "DELIVERED_TOTAL_EXCEEDS_LIMIT"
    AMOUNT_BELOW_MINIMUM = "AMOUNT_BELOW_MINIMUM"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    MERCHANT_NOT_ALLOWED = "MERCHANT_NOT_ALLOWED"
    PAYEE_MISMATCH = "PAYEE_MISMATCH"
    SKU_NOT_ALLOWED = "SKU_NOT_ALLOWED"
    LINE_ITEMS_MISMATCH = "LINE_ITEMS_MISMATCH"
    PAYMENT_INSTRUMENT_NOT_ALLOWED = "PAYMENT_INSTRUMENT_NOT_ALLOWED"
    # state
    GRANT_NOT_FOUND = "GRANT_NOT_FOUND"
    AUTHORIZATION_CANCELLED = "AUTHORIZATION_CANCELLED"
    AUTHORIZATION_CONSUMED = "AUTHORIZATION_CONSUMED"
    AUTHORIZATION_ALREADY_CLAIMED = "AUTHORIZATION_ALREADY_CLAIMED"
    AUTHORIZATION_REQUIRES_RENEWAL = "AUTHORIZATION_REQUIRES_RENEWAL"
    EXECUTION_UNCERTAIN = "EXECUTION_UNCERTAIN"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    MODE_MISMATCH = "MODE_MISMATCH"
    DIRECT_CHECKOUT_MISMATCH = "DIRECT_CHECKOUT_MISMATCH"


# Reason codes that mean "the grant would allow a different purchase": new authorization instead of DENY.
RENEWAL_REASONS = {
    Reason.DELIVERED_TOTAL_EXCEEDS_LIMIT,
    Reason.AMOUNT_BELOW_MINIMUM,
    Reason.MERCHANT_NOT_ALLOWED,
    Reason.SKU_NOT_ALLOWED,
    Reason.LINE_ITEMS_MISMATCH,
    Reason.EXPIRED_AUTHORIZATION,
    Reason.AUTHORIZATION_CONSUMED,
    Reason.AUTHORIZATION_REQUIRES_RENEWAL,
    Reason.CURRENCY_MISMATCH,
}


@dataclass
class Diagnostic:
    """Verification result. Not a wire-format mandate or receipt."""

    decision: Decision = Decision.DENY
    request_authentication: CheckStatus = CheckStatus.SKIPPED
    delegation_verification: CheckStatus = CheckStatus.SKIPPED
    constraint_verification: CheckStatus = CheckStatus.SKIPPED
    binding_verification: CheckStatus = CheckStatus.SKIPPED
    execution_state: CheckStatus = CheckStatus.SKIPPED
    reason_codes: List[str] = field(default_factory=list)
    evaluated_total_minor: Optional[str] = None
    authorized_max_minor: Optional[str] = None
    currency: Optional[str] = None
    profile: Optional[str] = None
    profile_version: Optional[str] = None
    ruleset_version: str = RULESET_VERSION
    trace_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def add(self, reason: "Reason | str", **detail: Any) -> None:
        code = reason.value if isinstance(reason, Reason) else str(reason)
        if code not in self.reason_codes:
            self.reason_codes.append(code)
        if detail:
            self.details.setdefault("reasons", {})[code] = detail

    @property
    def ok(self) -> bool:
        return self.decision == Decision.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("decision", "request_authentication", "delegation_verification", "constraint_verification",
                  "binding_verification", "execution_state"):
            v = d[k]
            d[k] = v.value if isinstance(v, Enum) else v
        return d


def decide(diag: Diagnostic) -> Diagnostic:
    """Derive the decision from the accumulated check statuses and reason codes."""
    if Reason.EXECUTION_UNCERTAIN.value in diag.reason_codes:
        diag.decision = Decision.RECONCILIATION_REQUIRED
        return diag
    if not diag.reason_codes and all(
        s in (CheckStatus.VALID, CheckStatus.NOT_APPLICABLE)
        for s in (
            diag.request_authentication,
            diag.delegation_verification,
            diag.constraint_verification,
            diag.binding_verification,
            diag.execution_state,
        )
    ):
        diag.decision = Decision.ALLOW
        return diag
    hard = [
        c for c in diag.reason_codes
        if c not in {r.value for r in RENEWAL_REASONS}
    ]
    if hard:
        diag.decision = Decision.DENY
    else:
        diag.decision = Decision.REQUIRE_NEW_AUTHORIZATION
    return diag
