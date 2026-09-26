"""FastAPI surface of the merchant gateway. Mountable or standalone."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aaw_domain.bootstrap import bootstrap
from aaw_domain.runtime import Runtime
from aaw_tap import TapRequest

from .service import GatewayError, GatewayService


class CheckoutItem(BaseModel):
    id: str
    quantity: int = Field(default=1, ge=1, le=100)


class CreateCheckoutRequest(BaseModel):
    line_items: List[CheckoutItem] = Field(min_length=1, max_length=20)


MAX_BODY = 512 * 1024


def build_router(service: GatewayService, authority: str) -> APIRouter:
    router = APIRouter(prefix="/gateway", tags=["merchant-gateway"])

    @router.get("/about")
    def about() -> Dict[str, Any]:
        return {"gateway_id": service.gateway_id, "authority": authority, "kid": service.handle.kid,
                "tap_profile": "visa/trusted-agent-protocol@16d59bd + content-digest coverage",
                "notice": "Merchants and gateway are simulated test participants."}

    @router.get("/merchants/{merchant_id}/catalog")
    def catalog(merchant_id: str) -> List[Dict[str, Any]]:
        try:
            return service.merchants.catalog(merchant_id)
        except GatewayError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.body.get("detail"))

    @router.post("/merchants/{merchant_id}/checkouts")
    def create_checkout(merchant_id: str, req: CreateCheckoutRequest) -> Dict[str, Any]:
        try:
            return service.merchants.create_checkout(merchant_id, [i.model_dump() for i in req.line_items])
        except GatewayError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.body.get("detail"))

    @router.get("/checkouts/{checkout_id}")
    def get_checkout(checkout_id: str) -> Dict[str, Any]:
        try:
            return service.merchants.checkout_dict(checkout_id)
        except GatewayError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.body.get("detail"))

    @router.post("/checkouts/{checkout_id}/complete")
    async def complete(checkout_id: str, request: Request):
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return JSONResponse(status_code=400, content={"detail": "body must be JSON"})
        headers = {k: v for k, v in request.headers.items()}
        # The authority the agent signed must be the authority this gateway serves.
        tap_req = TapRequest(method=request.method, authority=authority, path=request.url.path, headers=headers, body=raw)
        try:
            result = service.complete(checkout_id, tap_req, body)
        except GatewayError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.body)
        status = 200
        decision = (result.get("diagnostic") or {}).get("decision")
        if decision in ("DENY", "REQUIRE_NEW_AUTHORIZATION"):
            status = 403
        elif decision == "RECONCILIATION_REQUIRED":
            status = 202
        return JSONResponse(status_code=status, content=result)

    return router


def http_coordinator(api_url: str, gateway_token: str):
    """Coordinator client for the standalone gateway process."""

    def _execute(payload: Dict[str, Any]) -> Dict[str, Any]:
        with httpx.Client(timeout=30) as client:
            r = client.post(f"{api_url}/v1/executions", json=payload, headers={"X-Gateway-Token": gateway_token})
            try:
                return r.json()
            except ValueError:
                raise GatewayError(502, {"detail": f"coordinator returned {r.status_code}"})

    return _execute


def create_app() -> FastAPI:  # pragma: no cover - standalone entrypoint
    from aaw_ap2 import AP2Profile
    from aaw_domain.profiles import register_profile
    from aaw_vi import VIProfile

    rt = Runtime()
    gateway_id = os.environ.get("AAW_GATEWAY_ID", "urn:aaw:merchant-gateway")
    payment_audience = os.environ.get("AAW_PAYMENT_AUDIENCE", "urn:aaw:verifier:payment")
    bootstrap(rt, issuer_id=os.environ.get("AAW_ISSUER_ID", "https://issuer.aaw.test"), gateway_id=gateway_id,
              processor_id=os.environ.get("AAW_PROCESSOR_ID", "urn:aaw:payment-processor"))
    register_profile(AP2Profile(payment_audience))
    register_profile(VIProfile(payment_audience))
    service = GatewayService(rt, gateway_id, payment_audience,
                             http_coordinator(os.environ.get("AAW_API_URL", "http://api:8000"),
                                              os.environ.get("AAW_ADMIN_TOKEN", "dev-admin-token")))
    app = FastAPI(title="AAW Merchant Gateway")
    app.include_router(build_router(service, os.environ.get("AAW_GATEWAY_AUTHORITY", "gateway.aaw.test")))
    return app

