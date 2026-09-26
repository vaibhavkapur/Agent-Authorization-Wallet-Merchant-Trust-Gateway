"""Gateway / verifier trust store (plan §7).

A ``kid`` inside an artifact is a lookup hint. Trust is decided by an explicit
allowlist row in ``trusted_keys`` with a matching participant type, identifier,
key type, algorithm, validity window and ``local_status``. Historical keys stay
resolvable (``retired``) for verifying retained evidence, but only ``active``
keys may authorize new use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .clock import Clock, SystemClock
from .models import TrustedKey, new_id
from .outcomes import Reason

PARTICIPANT_ISSUER = "issuer"
PARTICIPANT_AGENT_MANDATE = "agent_mandate"
PARTICIPANT_AGENT_TAP = "agent_tap"
PARTICIPANT_MERCHANT = "merchant"
PARTICIPANT_VERIFIER = "verifier"

JWK_KTY_FOR_ALG = {"ES256": "EC", "ed25519": "OKP", "EdDSA": "OKP", "rsa-pss-sha256": "RSA"}


class TrustError(Exception):
    def __init__(self, reason: Reason, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass
class ResolvedKey:
    participant_type: str
    participant_id: str
    key_id: str
    public_jwk: Dict[str, Any]
    algorithm: str
    local_status: str
    source: str

    @property
    def usable_for_new_use(self) -> bool:
        return self.local_status == "active"


class TrustStore:
    def __init__(self, session: Session, clock: Optional[Clock] = None):
        self.session = session
        self.clock = clock or SystemClock()

    # -- administration -------------------------------------------------------

    def register(
        self,
        participant_type: str,
        participant_id: str,
        key_id: str,
        public_jwk: Dict[str, Any],
        algorithm: str,
        source: str,
        valid_from: Optional[int] = None,
        valid_until: Optional[int] = None,
        local_status: str = "active",
    ) -> TrustedKey:
        if "d" in public_jwk:
            raise ValueError("refusing to store a private key in the trust store")
        expected_kty = JWK_KTY_FOR_ALG.get(algorithm)
        if expected_kty is None or public_jwk.get("kty") != expected_kty:
            raise ValueError(f"key type {public_jwk.get('kty')} does not match algorithm {algorithm}")
        now = self.clock.now_ts()
        row = self.session.execute(
            select(TrustedKey).where(
                TrustedKey.participant_type == participant_type,
                TrustedKey.issuer_or_agent_id == participant_id,
                TrustedKey.key_id == key_id,
            )
        ).scalar_one_or_none()
        if row is None:
            row = TrustedKey(id=new_id("tk"), participant_type=participant_type, issuer_or_agent_id=participant_id,
                             key_id=key_id)
            self.session.add(row)
        row.public_key = {k: v for k, v in public_jwk.items() if k != "d"}
        row.algorithm = algorithm
        row.source = source
        row.valid_from = valid_from if valid_from is not None else now
        row.valid_until = valid_until
        row.local_status = local_status
        row.fetched_at = now
        self.session.flush()
        return row

    def set_status(self, participant_type: str, participant_id: str, key_id: str, status: str) -> None:
        row = self._row(participant_type, participant_id, key_id)
        if row is None:
            raise TrustError(Reason.UNKNOWN_ISSUER, "key not in trust store")
        row.local_status = status
        self.session.flush()

    def retire_others(self, participant_type: str, participant_id: str, keep_key_id: str) -> None:
        rows = self.session.execute(
            select(TrustedKey).where(
                TrustedKey.participant_type == participant_type, TrustedKey.issuer_or_agent_id == participant_id
            )
        ).scalars()
        for r in rows:
            if r.key_id != keep_key_id and r.local_status == "active":
                r.local_status = "retired"
        self.session.flush()

    # -- resolution -----------------------------------------------------------

    def _row(self, participant_type: str, participant_id: str, key_id: str) -> Optional[TrustedKey]:
        return self.session.execute(
            select(TrustedKey).where(
                TrustedKey.participant_type == participant_type,
                TrustedKey.issuer_or_agent_id == participant_id,
                TrustedKey.key_id == key_id,
            )
        ).scalar_one_or_none()

    def resolve(
        self,
        participant_type: str,
        participant_id: str,
        key_id: Optional[str],
        expected_algorithm: str,
        at: Optional[int] = None,
        allow_retired: bool = False,
        unknown_reason: Reason = Reason.UNKNOWN_ISSUER,
    ) -> ResolvedKey:
        """Resolve a trusted key or raise :class:`TrustError`.

        ``allow_retired`` is used when verifying retained historical evidence
        (plan §16); new authorizations require ``active``.
        """
        at = at if at is not None else self.clock.now_ts()
        row = self._row(participant_type, participant_id, key_id) if key_id else None
        if row is None and key_id is None:
            rows = list(
                self.session.execute(
                    select(TrustedKey).where(
                        TrustedKey.participant_type == participant_type,
                        TrustedKey.issuer_or_agent_id == participant_id,
                        TrustedKey.local_status == "active",
                    )
                ).scalars()
            )
            row = rows[0] if len(rows) == 1 else None
        if row is None:
            raise TrustError(unknown_reason, f"no trusted key for {participant_type}:{participant_id} kid={key_id}")
        if row.algorithm != expected_algorithm:
            raise TrustError(Reason.UNSUPPORTED_ALGORITHM,
                             f"key {key_id} registered for {row.algorithm}, artifact uses {expected_algorithm}")
        if row.public_key.get("kty") != JWK_KTY_FOR_ALG.get(expected_algorithm):
            raise TrustError(Reason.UNSUPPORTED_ALGORITHM, "key type does not match algorithm")
        if row.local_status == "revoked":
            raise TrustError(Reason.AGENT_KEY_INACTIVE if participant_type == PARTICIPANT_AGENT_TAP else unknown_reason,
                             f"key {key_id} is revoked")
        if row.local_status == "retired" and not allow_retired:
            raise TrustError(Reason.AGENT_KEY_INACTIVE if participant_type == PARTICIPANT_AGENT_TAP else unknown_reason,
                             f"key {key_id} is retired and cannot authorize new use")
        if at < row.valid_from or (row.valid_until is not None and at > row.valid_until and not allow_retired):
            raise TrustError(unknown_reason, f"key {key_id} outside validity window")
        return ResolvedKey(
            participant_type=row.participant_type,
            participant_id=row.issuer_or_agent_id,
            key_id=row.key_id,
            public_jwk=row.public_key,
            algorithm=row.algorithm,
            local_status=row.local_status,
            source=row.source,
        )

    def resolve_tap_key(self, key_id: str, at: Optional[int] = None) -> ResolvedKey:
        """TAP request signatures carry only ``keyId``; the registry maps it to an agent."""
        at = at if at is not None else self.clock.now_ts()
        row = self.session.execute(
            select(TrustedKey).where(TrustedKey.participant_type == PARTICIPANT_AGENT_TAP, TrustedKey.key_id == key_id)
        ).scalar_one_or_none()
        if row is None:
            raise TrustError(Reason.UNKNOWN_AGENT_KEY, f"TAP key {key_id} not in registry trust store")
        if row.local_status != "active":
            raise TrustError(Reason.AGENT_KEY_INACTIVE, f"TAP key {key_id} is {row.local_status}")
        if at < row.valid_from or (row.valid_until is not None and at > row.valid_until):
            raise TrustError(Reason.AGENT_KEY_INACTIVE, f"TAP key {key_id} outside validity window")
        return ResolvedKey(row.participant_type, row.issuer_or_agent_id, row.key_id, row.public_key, row.algorithm,
                           row.local_status, row.source)

    def list_keys(self):
        return list(self.session.execute(select(TrustedKey)).scalars())
