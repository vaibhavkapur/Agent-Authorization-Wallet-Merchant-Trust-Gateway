"""Simple bearer-token authentication for the demo participants.

Users authenticate with ``Authorization: Bearer <user token>``; agents with
``X-Agent-Token``; the gateway/worker with ``X-Gateway-Token`` (admin token).
Authorization decisions (e.g. a user may only approve their own proposal) are
made in the services against the authenticated principal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select

from aaw_domain.models import Agent, User

from .context import AppContext


@dataclass
class Principal:
    kind: str  # user | agent | gateway
    id: str
    display_name: str = ""


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def current_user(ctx: AppContext = Depends(get_ctx), authorization: str = Header(default="")) -> Principal:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="user bearer token required")
    token = authorization[7:]
    with ctx.rt.session() as s:
        user = s.execute(select(User).where(User.api_token == token)).scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=401, detail="invalid user token")
        return Principal("user", user.id, user.display_name)


def current_agent(ctx: AppContext = Depends(get_ctx), x_agent_token: str = Header(default="")) -> Principal:
    with ctx.rt.session() as s:
        agent = s.execute(select(Agent).where(Agent.api_token == x_agent_token)).scalar_one_or_none()
        if agent is None:
            raise HTTPException(status_code=401, detail="invalid agent token")
        return Principal("agent", agent.id, agent.display_name)


def current_gateway(ctx: AppContext = Depends(get_ctx), x_gateway_token: str = Header(default="")) -> Principal:
    if x_gateway_token != ctx.settings.admin_token:
        raise HTTPException(status_code=401, detail="gateway token required")
    return Principal("gateway", ctx.settings.gateway_id)


def user_or_agent(
    ctx: AppContext = Depends(get_ctx),
    authorization: str = Header(default=""),
    x_agent_token: str = Header(default=""),
) -> Principal:
    if authorization.startswith("Bearer "):
        return current_user(ctx, authorization)
    if x_agent_token:
        return current_agent(ctx, x_agent_token)
    raise HTTPException(status_code=401, detail="authentication required")


def optional_admin(ctx: AppContext = Depends(get_ctx), x_admin_token: Optional[str] = Header(default=None)) -> bool:
    return x_admin_token == ctx.settings.admin_token
