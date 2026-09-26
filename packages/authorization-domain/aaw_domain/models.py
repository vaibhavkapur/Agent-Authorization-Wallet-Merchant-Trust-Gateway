"""Persistence model (plan §13).

All timestamps are integer Unix epoch seconds (UTC) so that SQLite (tests) and
PostgreSQL (compose) behave identically. Confidential protocol artifacts are
stored encrypted in ``artifact_blobs`` and referenced from
``protocol_artifacts``; operational tables never contain raw mandates.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Index, Integer, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Participants (all simulated test participants)
# --------------------------------------------------------------------------- #


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128))
    api_token: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[int] = mapped_column(Integer)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(128))
    mandate_public_jwk: Mapped[Dict[str, Any]] = mapped_column(JSON)
    mandate_key_thumbprint: Mapped[str] = mapped_column(String(64))
    tap_key_id: Mapped[str] = mapped_column(String(128))
    api_token: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[int] = mapped_column(Integer)


class Merchant(Base):
    __tablename__ = "merchants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    website: Mapped[str] = mapped_column(String(256))
    authority: Mapped[str] = mapped_column(String(256))  # host[:port] the gateway serves this merchant under
    checkout_kid: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[int] = mapped_column(Integer)


class TrustedKey(Base):
    """Gateway/verifier trust store. A ``key_id`` is a lookup hint; trust comes from
    ``source`` (which registry/issuer configuration inserted it) and ``local_status``."""

    __tablename__ = "trusted_keys"
    __table_args__ = (UniqueConstraint("participant_type", "issuer_or_agent_id", "key_id", name="uq_trusted_key"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("tk"))
    participant_type: Mapped[str] = mapped_column(String(32))  # issuer | agent_mandate | agent_tap | merchant | verifier
    issuer_or_agent_id: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str] = mapped_column(String(128))
    public_key: Mapped[Dict[str, Any]] = mapped_column(JSON)  # JWK
    algorithm: Mapped[str] = mapped_column(String(32))  # ES256 | ed25519 | rsa-pss-sha256
    source: Mapped[str] = mapped_column(String(64))  # test-registry | test-issuer | local-config
    valid_from: Mapped[int] = mapped_column(Integer)
    valid_until: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    local_status: Mapped[str] = mapped_column(String(32), default="active")  # active | retired | revoked
    fetched_at: Mapped[int] = mapped_column(Integer)


# --------------------------------------------------------------------------- #
# Consent and authorization
# --------------------------------------------------------------------------- #


class AuthorizationProposal(Base):
    __tablename__ = "authorization_proposals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("prop"))
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    profile: Mapped[str] = mapped_column(String(16))
    profile_version: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16))  # direct | autonomous
    constraints_json: Mapped[Dict[str, Any]] = mapped_column(JSON)
    checkout_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    checkout_jwt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    consent_snapshot_json: Mapped[Dict[str, Any]] = mapped_column(JSON)
    consent_snapshot_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    version: Mapped[int] = mapped_column(Integer, default=1)
    grant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class ConsentChallenge(Base):
    __tablename__ = "consent_challenges"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("chal"))
    proposal_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64))
    snapshot_digest: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[int] = mapped_column(Integer)
    consumed_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    invalidated_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[int] = mapped_column(Integer)


class AuthorizationGrant(Base):
    __tablename__ = "authorization_grants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("grant"))
    proposal_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_key_thumbprint: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(16))
    profile_version: Mapped[str] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16))
    constraints_json: Mapped[Dict[str, Any]] = mapped_column(JSON)
    consent_snapshot_digest: Mapped[str] = mapped_column(String(64))
    bound_checkout_digest: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # direct mode
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    expires_at: Mapped[int] = mapped_column(Integer)
    not_before: Mapped[int] = mapped_column(Integer)
    cancelled_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class ProtocolArtifact(Base):
    __tablename__ = "protocol_artifacts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("art"))
    grant_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    claim_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    artifact_type: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(16))
    issuer_id: Mapped[str] = mapped_column(String(128))
    encrypted_object_reference: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64))
    allowed_reader_roles: Mapped[List[str]] = mapped_column(JSON)
    created_at: Mapped[int] = mapped_column(Integer)
    retention_until: Mapped[int] = mapped_column(Integer)


class ArtifactBlob(Base):
    __tablename__ = "artifact_blobs"
    reference: Mapped[str] = mapped_column(String(64), primary_key=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[int] = mapped_column(Integer)


# --------------------------------------------------------------------------- #
# Verification and execution
# --------------------------------------------------------------------------- #


class VerificationAttempt(Base):
    __tablename__ = "verification_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("ver"))
    grant_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    claim_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    checkout_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    verifier_role: Mapped[str] = mapped_column(String(32))  # gateway | merchant | payment | coordinator
    profile: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    ruleset_version: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(32))
    reason_codes: Mapped[List[str]] = mapped_column(JSON)
    diagnostic_json: Mapped[Dict[str, Any]] = mapped_column(JSON)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    verified_at: Mapped[int] = mapped_column(Integer)
    redacted_evidence_reference: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class ExecutionClaim(Base):
    """One claim per grant per purchase. ``grant_id`` is unique among non-terminal
    claims via the compare-and-swap on ``authorization_grants.status``; the
    ``idempotency_key`` makes repeated delivery of the same business operation
    return the same result."""

    __tablename__ = "execution_claims"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_claim_idempotency"),
        Index("ix_claim_grant_state", "grant_id", "state"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("exec"))
    grant_id: Mapped[str] = mapped_column(String(64), index=True)
    checkout_digest: Mapped[str] = mapped_column(String(128))
    checkout_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    payment_attempt_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    trace_id: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(16))
    amount_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    payee_id: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(32))
    diagnostic_json: Mapped[Dict[str, Any]] = mapped_column(JSON)
    claimed_at: Mapped[int] = mapped_column(Integer)
    resolved_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    order_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class PaymentAttempt(Base):
    __tablename__ = "payment_attempts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("pay"))
    claim_id: Mapped[str] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    amount_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    payee_id: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32))  # submitted | succeeded | declined | unknown | not_executed
    psp_confirmation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fault: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class ProcessorLedgerEntry(Base):
    """The simulated processor's own durable ledger, separate from the wallet's
    ``payment_attempts``. Reconciliation queries it by idempotency key. A lost
    response leaves a ledger entry without a wallet-side result."""

    __tablename__ = "processor_ledger"
    idempotency_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    amount_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    payee_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))  # succeeded | declined
    psp_confirmation_id: Mapped[str] = mapped_column(String(64))
    executed_at: Mapped[int] = mapped_column(Integer)


class Receipt(Base):
    __tablename__ = "receipts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rcpt"))
    claim_id: Mapped[str] = mapped_column(String(64), index=True)
    receipt_type: Mapped[str] = mapped_column(String(32))  # checkout | payment
    issuer_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16))  # Success | Error
    reference: Mapped[str] = mapped_column(String(64))
    jwt: Mapped[str] = mapped_column(Text)
    created_at: Mapped[int] = mapped_column(Integer)


class RequestReplayRecord(Base):
    __tablename__ = "request_replay_records"
    __table_args__ = (UniqueConstraint("key_id", "nonce", name="uq_replay_key_nonce"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rr"))
    key_id: Mapped[str] = mapped_column(String(128))
    nonce: Mapped[str] = mapped_column(String(128))
    created: Mapped[int] = mapped_column(Integer)
    expires: Mapped[int] = mapped_column(Integer)
    first_seen_at: Mapped[int] = mapped_column(Integer)
    trace_id: Mapped[str] = mapped_column(String(64))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("evt"))
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    at: Mapped[int] = mapped_column(Integer)
    details_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class MerchantCheckout(Base):
    """Merchant-side record of a final checkout (merchant gateway)."""

    __tablename__ = "merchant_checkouts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("co"))
    merchant_id: Mapped[str] = mapped_column(String(64), index=True)
    checkout_jwt: Mapped[str] = mapped_column(Text)
    checkout_hash: Mapped[str] = mapped_column(String(64), index=True)
    total_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3))
    line_items_json: Mapped[List[Dict[str, Any]]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | completed | rejected
    order_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int] = mapped_column(Integer)
