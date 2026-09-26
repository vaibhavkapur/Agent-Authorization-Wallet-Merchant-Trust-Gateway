"""FastAPI surface for the test issuer. Mountable (embedded) or standalone."""

from __future__ import annotations

import os
from typing import Any, Dict, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from aaw_domain.bootstrap import bootstrap
from aaw_domain.runtime import Runtime

from .service import IssuerService


class IssueRequest(BaseModel):
    profile: Literal["ap2", "vi"]
    user_id: str
    user_public_jwk: Dict[str, Any]


def build_router(service: IssuerService, admin_token: str) -> APIRouter:
    router = APIRouter(prefix="/issuer", tags=["test-issuer"])

    def require_admin(authorization: str = Header(default="")) -> str:
        if authorization != f"Bearer {admin_token}":
            raise HTTPException(status_code=401, detail="issuer enrollment requires the admin token")
        return "issuer-admin"

    @router.get("/jwks")
    def jwks() -> Dict[str, Any]:
        return service.jwks()

    @router.get("/about")
    def about() -> Dict[str, Any]:
        return {"issuer": service.issuer_id, "kid": service.handle.kid, "role": "test credential issuer",
                "notice": "Test participant. Verifiers trust an explicit allowlist, not this endpoint."}

    @router.post("/credentials")
    def issue(req: IssueRequest, actor: str = Depends(require_admin)) -> Dict[str, Any]:
        try:
            return service.issue(req.profile, req.user_id, req.user_public_jwk, actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    return router


def create_app() -> FastAPI:  # pragma: no cover - standalone entrypoint
    rt = Runtime()
    issuer_id = os.environ.get("AAW_ISSUER_ID", "https://issuer.aaw.test")
    bootstrap(rt, issuer_id=issuer_id, gateway_id=os.environ.get("AAW_GATEWAY_ID", "urn:aaw:merchant-gateway"),
              processor_id=os.environ.get("AAW_PROCESSOR_ID", "urn:aaw:payment-processor"))
    app = FastAPI(title="AAW Test Credential Issuer")
    app.include_router(build_router(IssuerService(rt, issuer_id), os.environ.get("AAW_ADMIN_TOKEN", "dev-admin-token")))
    return app

