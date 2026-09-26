"""Wallet API application factory.

``AAW_GATEWAY_MODE=embedded`` (default, tests, single-process dev) mounts the
merchant gateway, test issuer and test registry into this process; the
simulated agent still talks to the gateway over HTTP semantics (in-process ASGI
transport) so TAP headers and bodies are exercised exactly as over the wire.
``remote`` (docker-compose) talks to the sibling services over HTTP.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.testclient import TestClient

from aaw_domain.clock import Clock, FixedClock
from aaw_gateway.app import build_router as gateway_router
from aaw_gateway.service import GatewayService
from aaw_issuer.app import build_router as issuer_router
from aaw_issuer.service import IssuerService
from aaw_registry.app import build_router as registry_router

from . import routers
from .context import AppContext
from .services.execution import ExecutionService
from .settings import Settings


def create_app(settings: Optional[Settings] = None, clock: Optional[Clock] = None) -> FastAPI:
    settings = settings or Settings()
    if clock is None and os.environ.get("AAW_FIXED_CLOCK") == "1":
        clock = FixedClock()
    ctx = AppContext(settings, clock)
    app = FastAPI(title="Agent Authorization Wallet API", version="0.1.0")
    app.state.ctx = ctx
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])
    app.include_router(routers.proposals)
    app.include_router(routers.executions)
    app.include_router(routers.agent)
    app.include_router(routers.demo)

    if settings.gateway_mode == "embedded":
        issuer_service = IssuerService(ctx.rt, settings.issuer_id)
        ctx.issue_credential = lambda profile, user_id, jwk: issuer_service.issue(profile, user_id, jwk, actor="wallet-api")
        exec_service = ExecutionService(ctx)
        gateway_service = GatewayService(ctx.rt, settings.gateway_id, settings.payment_audience, exec_service.execute)
        app.include_router(gateway_router(gateway_service, settings.gateway_authority))
        app.include_router(issuer_router(issuer_service, settings.admin_token))
        app.include_router(registry_router(ctx.rt, settings.admin_token))
        ctx.gateway_base_url = f"http://{settings.gateway_authority}"

        def _client():
            return TestClient(app, base_url=ctx.gateway_base_url, raise_server_exceptions=False)

        ctx.gateway_client = _client  # type: ignore[assignment]

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "now": ctx.rt.now()}

    return app
