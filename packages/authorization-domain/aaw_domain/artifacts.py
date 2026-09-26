"""Encrypted artifact vault + audit events.

Confidential protocol artifacts (credentials, mandates, presentations) are
AES-256-GCM encrypted at rest with ``AAW_ARTIFACT_KEY`` (dev default derived
from a fixed string; rotate in any real deployment) and referenced from
``protocol_artifacts`` with the reader roles allowed to see them.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from .clock import Clock, SystemClock
from .models import ArtifactBlob, AuditEvent, ProtocolArtifact, new_id

DEFAULT_RETENTION_SECONDS = 400 * 24 * 3600


def _key() -> bytes:
    raw = os.environ.get("AAW_ARTIFACT_KEY", "dev-only-artifact-key-not-for-production")
    return hashlib.sha256(raw.encode("utf-8")).digest()


def digest_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class ArtifactVault:
    def __init__(self, session: Session, clock: Optional[Clock] = None):
        self.session = session
        self.clock = clock or SystemClock()

    def store(
        self,
        *,
        artifact_type: str,
        profile: str,
        issuer_id: str,
        obj: Any,
        allowed_reader_roles: List[str],
        grant_id: Optional[str] = None,
        claim_id: Optional[str] = None,
    ) -> ProtocolArtifact:
        plaintext = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)
        ct = AESGCM(_key()).encrypt(nonce, plaintext, artifact_type.encode("utf-8"))
        ref = new_id("blob")
        now = self.clock.now_ts()
        self.session.add(ArtifactBlob(reference=ref, ciphertext=nonce + ct, created_at=now))
        art = ProtocolArtifact(
            id=new_id("art"),
            grant_id=grant_id,
            claim_id=claim_id,
            artifact_type=artifact_type,
            profile=profile,
            issuer_id=issuer_id,
            encrypted_object_reference=ref,
            digest=hashlib.sha256(plaintext).hexdigest(),
            allowed_reader_roles=list(allowed_reader_roles),
            created_at=now,
            retention_until=now + DEFAULT_RETENTION_SECONDS,
        )
        self.session.add(art)
        self.session.flush()
        return art

    def load(self, art: ProtocolArtifact, reader_role: str) -> Any:
        if reader_role not in art.allowed_reader_roles and reader_role != "system":
            raise PermissionError(f"role {reader_role} may not read artifact {art.artifact_type}")
        blob = self.session.get(ArtifactBlob, art.encrypted_object_reference)
        if blob is None:
            raise KeyError("artifact blob missing")
        data = bytes(blob.ciphertext)
        pt = AESGCM(_key()).decrypt(data[:12], data[12:], art.artifact_type.encode("utf-8"))
        return json.loads(pt)

    def for_grant(self, grant_id: str) -> List[ProtocolArtifact]:
        return list(self.session.execute(select(ProtocolArtifact).where(ProtocolArtifact.grant_id == grant_id)).scalars())

    def for_claim(self, claim_id: str) -> List[ProtocolArtifact]:
        return list(self.session.execute(select(ProtocolArtifact).where(ProtocolArtifact.claim_id == claim_id)).scalars())

    def load_type(self, grant_id: str, artifact_type: str, reader_role: str = "system") -> Any:
        for art in self.for_grant(grant_id):
            if art.artifact_type == artifact_type:
                return self.load(art, reader_role)
        raise KeyError(f"no artifact {artifact_type} for grant {grant_id}")


def audit(
    session: Session,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    trace_id: Optional[str] = None,
    clock: Optional[Clock] = None,
    **details: Any,
) -> AuditEvent:
    evt = AuditEvent(
        id=new_id("evt"),
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        trace_id=trace_id,
        at=(clock or SystemClock()).now_ts(),
        details_json=details,
    )
    session.add(evt)
    return evt
