"""Simulated user signing component (the "trusted surface" signer).

The component signs only when handed an :class:`ApprovedConsent` capability
whose ``snapshot_digest`` equals the digest of the immutable reviewed
representation the caller wants to sign. The consent service (apps/api)
produces ``ApprovedConsent`` after validating a fresh challenge; the agent
code path never obtains a ``UserSigningComponent`` instance.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, TypeVar

from .keys import KeyHandle

T = TypeVar("T")


class ConsentBindingError(Exception):
    pass


@dataclass(frozen=True)
class ApprovedConsent:
    """Capability proving that a user approved exactly one reviewed snapshot."""

    user_id: str
    proposal_id: str
    challenge_id: str
    snapshot_digest: str
    approved_at: int

    def assert_fresh(self, max_age_seconds: int = 120) -> None:
        if time.time() - self.approved_at > max_age_seconds:
            raise ConsentBindingError("approved consent is stale")


def canonical_digest(obj: Any) -> str:
    """Stable digest of a JSON-serialisable object (sorted keys, compact separators)."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class UserSigningComponent:
    def __init__(self, handle: KeyHandle):
        self._handle = handle

    @property
    def kid(self) -> str:
        return self._handle.kid

    def public_jwk(self) -> Dict[str, Any]:
        return self._handle.public_jwk()

    def sign_reviewed(self, consent: ApprovedConsent, snapshot: Dict[str, Any], build: Callable[[KeyHandle], T]) -> T:
        """Run ``build`` with the user key handle, but only if ``snapshot`` is the exact
        representation the user approved."""
        consent.assert_fresh()
        digest = canonical_digest(snapshot)
        if digest != consent.snapshot_digest:
            raise ConsentBindingError("snapshot digest does not match approved consent; proposal changed after review")
        return build(self._handle)
