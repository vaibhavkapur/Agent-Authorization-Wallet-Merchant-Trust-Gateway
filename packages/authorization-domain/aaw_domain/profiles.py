"""Profile adapter interface.

AP2 and Verifiable Intent are implemented as separate profiles with their own
parsers, fixtures and verification rules. The application talks to them only
through these types; nothing here is a wire format of either protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from aaw_signer import KeyHandle

from .constraints import GrantConstraints
from .outcomes import Reason
from .trust import TrustStore

ROLE_MERCHANT = "merchant"
ROLE_PAYMENT = "payment"


@dataclass
class CheckoutSummary:
    """Merchant-signed final checkout, after the application verified its source."""

    checkout_jwt: str
    checkout_hash: str  # base64url(sha-256(checkout_jwt))
    merchant: Dict[str, Any]  # {id, name, website}
    merchant_kid: str
    line_items: List[Dict[str, Any]]  # [{id, title, quantity, unit_price_minor}]
    total_minor: int
    currency: str
    checkout_id: str
    issued_at: int
    expires_at: int

    def as_review(self) -> Dict[str, Any]:
        return {
            "checkout_id": self.checkout_id,
            "checkout_hash": self.checkout_hash,
            "merchant": self.merchant,
            "line_items": self.line_items,
            "total": {"minor": str(self.total_minor), "currency": self.currency},
        }


@dataclass
class IssuanceContext:
    user_id: str
    agent_id: str
    agent_public_jwk: Dict[str, Any]
    mode: str  # direct | autonomous
    constraints: GrantConstraints
    issuer_credential: str  # profile-specific user credential (compact serialization)
    issuer_id: str
    wallet_issuer: str  # iss for user-signed artifacts
    agent_audience: str  # aud for user-signed open mandates
    consent_snapshot_digest: str
    now: int
    checkout: Optional[CheckoutSummary] = None  # direct mode only


@dataclass
class GrantArtifacts:
    profile: str
    version: str
    mode: str
    objects: Dict[str, Any]  # confidential: serialized credentials, disclosure indexes
    public_summary: Dict[str, Any]  # digests / kids / vct list only
    agent_key_thumbprint: str


@dataclass
class Presentation:
    profile: str
    version: str
    role: str  # merchant | payment
    payload: Dict[str, Any]  # profile-specific presentation (compact strings)
    aud: str
    nonce: str
    checkout_hash: Optional[str] = None


@dataclass
class VerifyExpectations:
    role: str
    audience: str
    now: int
    nonce: Optional[str] = None  # if the verifier issued a nonce
    expected_checkout_jwt: Optional[str] = None  # merchant verifies against the checkout it created
    expected_checkout_hash: Optional[str] = None  # payment verifier gets the hash from the gateway
    max_clock_skew: int = 120
    max_presentation_age: int = 600
    allow_retired_keys: bool = False


@dataclass
class ConstraintResult:
    type: str
    satisfied: bool
    detail: str = ""


@dataclass
class ProfileVerification:
    crypto_valid: bool = False
    protocol_valid: bool = False
    reasons: List[Reason] = field(default_factory=list)
    mode: Optional[str] = None
    issuer_id: Optional[str] = None
    user_key_thumbprint: Optional[str] = None
    agent_key_thumbprint: Optional[str] = None
    checkout_hash: Optional[str] = None
    transaction_id: Optional[str] = None
    amount_minor: Optional[int] = None
    currency: Optional[str] = None
    payee: Optional[Dict[str, Any]] = None
    merchant: Optional[Dict[str, Any]] = None
    checkout_line_items: Optional[List[Dict[str, Any]]] = None
    open_constraints: List[Dict[str, Any]] = field(default_factory=list)
    constraint_results: List[ConstraintResult] = field(default_factory=list)
    closed_claims: Dict[str, Any] = field(default_factory=dict)
    open_mandate_digest: Optional[str] = None
    reference_digest: Optional[str] = None
    expires_at: Optional[int] = None
    final_artifact_hash: Optional[str] = None  # receipt reference (sd_hash style over the final SD-JWT)
    disclosed: Dict[str, Any] = field(default_factory=dict)  # role-scoped decoded view for evidence
    details: Dict[str, Any] = field(default_factory=dict)

    def fail(self, reason: Reason, detail: str = "") -> "ProfileVerification":
        if reason not in self.reasons:
            self.reasons.append(reason)
        if detail:
            self.details.setdefault("errors", []).append(f"{reason.value}: {detail}")
        return self

    @property
    def constraints_satisfied(self) -> bool:
        return all(c.satisfied for c in self.constraint_results)


class AuthorizationProfile(Protocol):
    name: str
    version: str

    def issue(self, ctx: IssuanceContext, user_handle: KeyHandle) -> GrantArtifacts: ...

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
    ) -> Dict[str, Presentation]: ...

    def verify(self, presentation: Presentation, trust: TrustStore, expect: VerifyExpectations) -> ProfileVerification: ...

    def evidence_view(self, presentation: Presentation) -> Dict[str, Any]: ...

    def reuse_after_rejection_allowed(self) -> bool: ...


_REGISTRY: Dict[str, AuthorizationProfile] = {}


def register_profile(profile: AuthorizationProfile) -> None:
    _REGISTRY[profile.name] = profile


def get_profile(name: str) -> AuthorizationProfile:
    if name not in _REGISTRY:
        raise KeyError(f"unsupported profile {name!r}")
    return _REGISTRY[name]


def supported_profiles() -> Dict[str, str]:
    return {n: p.version for n, p in _REGISTRY.items()}
