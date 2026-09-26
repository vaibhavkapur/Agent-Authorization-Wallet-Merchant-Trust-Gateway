"""Test agent registry (TAP public keys).

Mirrors the shape of the Visa sample registry (``GET /keys/{key_id}`` returning
``key_id``, ``is_active``, ``public_key``, ``algorithm``, ``agent_id``) but is
backed by the shared ``trusted_keys`` table so the merchant gateway resolves
keys through registry configuration rather than request contents. Enrollment
and status changes require the admin token. Test participant only.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from aaw_domain.artifacts import audit
from aaw_domain.bootstrap import bootstrap
from aaw_domain.models import Agent, TrustedKey
from aaw_domain.runtime import Runtime
from aaw_domain.trust import PARTICIPANT_AGENT_TAP, TrustError


class EnrollKeyRequest(BaseModel):
    key_id: str
    public_jwk: Dict[str, Any]
    algorithm: Literal["ed25519", "rsa-pss-sha256"]
    valid_until: Optional[int] = None


class KeyStatusRequest(BaseModel):
    status: Literal["active", "retired", "revoked"]


def _row_to_dict(row: TrustedKey, agent: Optional[Agent]) -> Dict[str, Any]:
    return {
        "key_id": row.key_id,
        "is_active": "true" if row.local_status == "active" else "false",
        "local_status": row.local_status,
        "public_key": row.public_key,
        "algorithm": row.algorithm,
        "agent_id": row.issuer_or_agent_id,
        "agent_name": agent.display_name if agent else None,
        "agent_provider": agent.provider if agent else None,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "source": row.source,
    }


def build_router(rt: Runtime, admin_token: str) -> APIRouter:
    router = APIRouter(prefix="/registry", tags=["test-registry"])

    def require_admin(authorization: str = Header(default="")) -> str:
        if authorization != f"Bearer {admin_token}":
            raise HTTPException(status_code=401, detail="registry administration requires the admin token")
        return "registry-admin"

    @router.get("/agents")
    def agents() -> List[Dict[str, Any]]:
        with rt.session() as s:
            out = []
            for a in s.execute(select(Agent)).scalars():
                keys = s.execute(select(TrustedKey).where(TrustedKey.participant_type == PARTICIPANT_AGENT_TAP,
                                                          TrustedKey.issuer_or_agent_id == a.id)).scalars()
                out.append({"agent_id": a.id, "display_name": a.display_name, "provider": a.provider,
                            "mandate_key_thumbprint": a.mandate_key_thumbprint,
                            "tap_keys": [_row_to_dict(k, a) for k in keys]})
            return out

    @router.get("/keys/{key_id}")
    def key(key_id: str) -> Dict[str, Any]:
        with rt.session() as s:
            row = s.execute(select(TrustedKey).where(TrustedKey.participant_type == PARTICIPANT_AGENT_TAP,
                                                     TrustedKey.key_id == key_id)).scalar_one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail=f"Key not found for ID: {key_id}")
            return _row_to_dict(row, s.get(Agent, row.issuer_or_agent_id))

    @router.post("/agents/{agent_id}/keys")
    def enroll(agent_id: str, req: EnrollKeyRequest, actor: str = Depends(require_admin)) -> Dict[str, Any]:
        with rt.session() as s:
            if s.get(Agent, agent_id) is None:
                raise HTTPException(status_code=404, detail="unknown agent")
            try:
                row = rt.trust(s).register(PARTICIPANT_AGENT_TAP, agent_id, req.key_id, req.public_jwk, req.algorithm,
                                           "test-registry", valid_until=req.valid_until)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            audit(s, actor=actor, action="TAP_KEY_ENROLLED", target_type="agent", target_id=agent_id, clock=rt.clock,
                  key_id=req.key_id, algorithm=req.algorithm)
            return _row_to_dict(row, s.get(Agent, agent_id))

    @router.post("/keys/{key_id}/status")
    def set_status(key_id: str, req: KeyStatusRequest, actor: str = Depends(require_admin)) -> Dict[str, Any]:
        with rt.session() as s:
            row = s.execute(select(TrustedKey).where(TrustedKey.participant_type == PARTICIPANT_AGENT_TAP,
                                                     TrustedKey.key_id == key_id)).scalar_one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown key")
            try:
                rt.trust(s).set_status(PARTICIPANT_AGENT_TAP, row.issuer_or_agent_id, key_id, req.status)
            except TrustError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            audit(s, actor=actor, action="TAP_KEY_STATUS", target_type="key", target_id=key_id, clock=rt.clock,
                  status=req.status)
            return _row_to_dict(row, s.get(Agent, row.issuer_or_agent_id))

    return router


def create_app() -> FastAPI:  # pragma: no cover - standalone entrypoint
    rt = Runtime()
    bootstrap(rt, issuer_id=os.environ.get("AAW_ISSUER_ID", "https://issuer.aaw.test"),
              gateway_id=os.environ.get("AAW_GATEWAY_ID", "urn:aaw:merchant-gateway"),
              processor_id=os.environ.get("AAW_PROCESSOR_ID", "urn:aaw:payment-processor"))
    app = FastAPI(title="AAW Test Agent Registry")
    app.include_router(build_router(rt, os.environ.get("AAW_ADMIN_TOKEN", "dev-admin-token")))
    return app

