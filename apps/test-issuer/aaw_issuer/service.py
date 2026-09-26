"""Test credential issuer.

Issues the profile-specific user credential (AP2: SD-JWT VC with ``cnf`` = user
device key; VI: Layer 1) only through an authenticated enrollment call. This is
a **test participant**; verifiers trust it because its key is on their issuer
allowlist, not because it is a real issuer.
"""

from __future__ import annotations

from typing import Any, Dict

from aaw_ap2 import build_user_credential as ap2_credential
from aaw_domain.artifacts import audit
from aaw_domain.runtime import Runtime
from aaw_vi import build_user_credential as vi_credential

CREDENTIAL_TTL = 365 * 24 * 3600


class IssuerService:
    def __init__(self, rt: Runtime, issuer_id: str):
        self.rt = rt
        self.issuer_id = issuer_id

    @property
    def handle(self):
        return self.rt.keys.get("test_issuer")

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [self.handle.public_jwk()]}

    def issue(self, profile: str, user_id: str, user_public_jwk: Dict[str, Any], actor: str) -> Dict[str, Any]:
        now = self.rt.now()
        if user_public_jwk.get("kty") != "EC" or "d" in user_public_jwk:
            raise ValueError("user key must be a public EC JWK")
        if profile == "ap2":
            cred = ap2_credential(self.handle, self.issuer_id, user_id, user_public_jwk, now, now + CREDENTIAL_TTL,
                                  {"email": f"{user_id}@users.aaw.test", "card_last_four": "4242"}).serialize()
            fmt = "dc+sd-jwt"
        elif profile == "vi":
            cred = vi_credential(self.handle, self.issuer_id, user_id, user_public_jwk, now, now + CREDENTIAL_TTL,
                                 email=f"{user_id}@users.aaw.test")
            fmt = "sd+jwt"
        else:
            raise ValueError(f"unsupported profile {profile}")
        with self.rt.session() as s:
            audit(s, actor=actor, action="CREDENTIAL_ISSUED", target_type="user", target_id=user_id, clock=self.rt.clock,
                  profile=profile, issuer=self.issuer_id, kid=self.handle.kid)
        return {"profile": profile, "format": fmt, "issuer": self.issuer_id, "kid": self.handle.kid, "credential": cred,
                "expires_at": now + CREDENTIAL_TTL,
                "notice": "Test issuer credential. Local verification is not network accreditation."}
