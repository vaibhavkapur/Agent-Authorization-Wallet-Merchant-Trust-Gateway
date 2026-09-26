"""HTTP routers for the wallet API (application endpoints, not protocol endpoints)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from aaw_domain.constraints import ProposalRequest
from aaw_domain.models import (
    Agent,
    AuthorizationGrant,
    ExecutionClaim,
    Merchant,
    RequestReplayRecord,
    User,
    VerificationAttempt,
)
from aaw_domain.profiles import supported_profiles
from aaw_exec import run_once

from .auth import Principal, current_agent, current_gateway, current_user, get_ctx, optional_admin, user_or_agent
from .context import AppContext
from .services.agent_sim import AgentSimulator
from .services.consent import ConsentService, ServiceError
from .services.execution import ExecutionService


def _wrap(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


# --------------------------------------------------------------------------- #
# Proposals / consent / grants
# --------------------------------------------------------------------------- #

proposals = APIRouter(prefix="/v1", tags=["authorization"])


class ApproveRequest(BaseModel):
    challenge_id: str
    nonce: str
    snapshot_digest: str


class ProposalChange(BaseModel):
    max_total_minor: Optional[str] = Field(default=None, pattern=r"^[0-9]{1,12}$")
    expires_at: Optional[str] = None


@proposals.post("/authorization-proposals")
def create_proposal(req: ProposalRequest, agent: Principal = Depends(current_agent), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).create_proposal, req, agent.id)


@proposals.get("/authorization-proposals")
def list_proposals(p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return ConsentService(ctx).list_proposals(p.kind, p.id)


@proposals.get("/authorization-proposals/{proposal_id}")
def get_proposal(proposal_id: str, p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).get_proposal, proposal_id, p.kind, p.id)


@proposals.patch("/authorization-proposals/{proposal_id}")
def change_proposal(proposal_id: str, change: ProposalChange, agent: Principal = Depends(current_agent),
                    ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).update_proposal, proposal_id, change.model_dump(exclude_none=True), agent.id)


@proposals.post("/authorization-proposals/{proposal_id}/consent-challenge")
def consent_challenge(proposal_id: str, user: Principal = Depends(current_user), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).create_challenge, proposal_id, user.id)


@proposals.post("/authorization-proposals/{proposal_id}/approve")
def approve(proposal_id: str, req: ApproveRequest, user: Principal = Depends(current_user),
            ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).approve, proposal_id, user.id, req.challenge_id, req.nonce, req.snapshot_digest)


@proposals.post("/authorization-proposals/{proposal_id}/reject")
def reject(proposal_id: str, user: Principal = Depends(current_user), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).reject, proposal_id, user.id)


@proposals.get("/authorizations")
def list_grants(p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return ConsentService(ctx).list_grants(p.kind, p.id)


@proposals.get("/authorizations/{grant_id}")
def get_grant(grant_id: str, p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).get_grant, grant_id, p.kind, p.id)


@proposals.post("/authorizations/{grant_id}/cancel")
def cancel_grant(grant_id: str, user: Principal = Depends(current_user), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ConsentService(ctx).cancel, grant_id, user.id)


# --------------------------------------------------------------------------- #
# Verification / execution / evidence
# --------------------------------------------------------------------------- #

executions = APIRouter(prefix="/v1", tags=["execution"])


@executions.post("/verifications")
def verify(payload: Dict[str, Any], p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return ExecutionService(ctx).verify_only(payload, actor=f"{p.kind}:{p.id}")


@executions.post("/executions")
def execute(payload: Dict[str, Any], gw: Principal = Depends(current_gateway), ctx: AppContext = Depends(get_ctx)):
    return ExecutionService(ctx).execute(payload)


@executions.get("/executions")
def list_executions(p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return ExecutionService(ctx).list(p.kind, p.id)


@executions.get("/executions/{claim_id}")
def get_execution(claim_id: str, p: Principal = Depends(user_or_agent), ctx: AppContext = Depends(get_ctx)):
    return _wrap(ExecutionService(ctx).get, claim_id, p.kind, p.id)


@executions.get("/executions/{claim_id}/evidence")
def evidence(claim_id: str, role: str = Query(default="user"), p: Principal = Depends(user_or_agent),
             ctx: AppContext = Depends(get_ctx)):
    return _wrap(ExecutionService(ctx).evidence, claim_id, role, p.kind, p.id)


# --------------------------------------------------------------------------- #
# Simulated agent
# --------------------------------------------------------------------------- #

agent = APIRouter(prefix="/v1/agent", tags=["simulated-agent"])


class PurchaseItem(BaseModel):
    id: str
    quantity: int = Field(default=1, ge=1, le=100)


class PurchaseRequest(BaseModel):
    grant_id: str
    merchant_id: Optional[str] = None
    items: Optional[List[PurchaseItem]] = None
    checkout_reference: Optional[str] = None
    tamper: Dict[str, Any] = Field(default_factory=dict)
    tap: Dict[str, Any] = Field(default_factory=dict)
    fault: Optional[str] = None
    nonce: Optional[str] = None


class ReplayRequest(BaseModel):
    request: Dict[str, Any]


@agent.post("/purchase")
def agent_purchase(req: PurchaseRequest, a: Principal = Depends(current_agent), ctx: AppContext = Depends(get_ctx)):
    return _wrap(
        AgentSimulator(ctx).purchase,
        a.id,
        req.grant_id,
        merchant_id=req.merchant_id,
        items=[i.model_dump() for i in req.items] if req.items else None,
        checkout_reference=req.checkout_reference,
        tamper=req.tamper,
        tap_options=req.tap,
        fault=req.fault,
        nonce=req.nonce,
    )


@agent.post("/replay")
def agent_replay(req: ReplayRequest, a: Principal = Depends(current_agent), ctx: AppContext = Depends(get_ctx)):
    return AgentSimulator(ctx).send(req.request)


# --------------------------------------------------------------------------- #
# Demo / observability
# --------------------------------------------------------------------------- #

demo = APIRouter(prefix="/v1", tags=["demo"])


@demo.get("/about")
def about(ctx: AppContext = Depends(get_ctx)):
    return {
        "name": "Agent Authorization Wallet + Merchant Trust Gateway",
        "profiles": supported_profiles(),
        "tap_profile": "visa/trusted-agent-protocol@16d59bd (RFC 9421) + content-digest coverage",
        "gateway_mode": ctx.settings.gateway_mode,
        "notice": "All issuers, registries, merchants and the payment processor are local test participants. "
                  "Local verification is not network accreditation.",
    }


class MerchantCheckoutRequest(BaseModel):
    line_items: List[PurchaseItem] = Field(min_length=1, max_length=20)


@demo.get("/merchants/{merchant_id}/catalog")
def merchant_catalog(merchant_id: str, ctx: AppContext = Depends(get_ctx)):
    """Convenience proxy to the merchant gateway (which may run as a separate service)."""
    with ctx.gateway_client() as client:
        r = client.get(f"/gateway/merchants/{merchant_id}/catalog")
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@demo.post("/merchants/{merchant_id}/checkouts")
def merchant_checkout(merchant_id: str, req: MerchantCheckoutRequest, ctx: AppContext = Depends(get_ctx)):
    """Convenience proxy: the merchant issues a final checkout (used by the direct-mode UI)."""
    with ctx.gateway_client() as client:
        r = client.post(f"/gateway/merchants/{merchant_id}/checkouts",
                        json={"line_items": [i.model_dump() for i in req.line_items]})
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@demo.get("/participants")
def participants(ctx: AppContext = Depends(get_ctx)):
    with ctx.rt.session() as s:
        users = [{"id": u.id, "display_name": u.display_name,
                  **({"token": u.api_token} if ctx.settings.expose_demo_tokens else {})}
                 for u in s.execute(select(User)).scalars()]
        agents = [{"id": a.id, "display_name": a.display_name, "provider": a.provider,
                   "mandate_key_thumbprint": a.mandate_key_thumbprint, "tap_key_id": a.tap_key_id,
                   **({"token": a.api_token} if ctx.settings.expose_demo_tokens else {})}
                  for a in s.execute(select(Agent)).scalars()]
        merchants = [{"id": m.id, "name": m.name, "website": m.website, "checkout_kid": m.checkout_kid}
                     for m in s.execute(select(Merchant)).scalars()]
    return {"users": users, "agents": agents, "merchants": merchants,
            "notice": "Synthetic identities. Tokens are exposed only because AAW_EXPOSE_DEMO_TOKENS=1."}


class FaultRequest(BaseModel):
    payment: Optional[str] = None  # decline | lose_response | crash_before_submit | None


@demo.post("/demo/faults")
def set_faults(req: FaultRequest, ctx: AppContext = Depends(get_ctx)):
    if req.payment not in (None, "decline", "lose_response", "crash_before_submit"):
        raise HTTPException(status_code=400, detail="unknown fault")
    ctx.rt.faults["payment"] = req.payment
    return {"faults": ctx.rt.faults}


@demo.get("/demo/faults")
def get_faults(ctx: AppContext = Depends(get_ctx)):
    return {"faults": ctx.rt.faults}


@demo.post("/demo/worker/run-once")
def worker_run_once(ctx: AppContext = Depends(get_ctx)):
    return run_once(ctx.rt.db, ctx.coordinator)


class ClockRequest(BaseModel):
    advance_seconds: int = Field(ge=0, le=10 * 365 * 24 * 3600)


@demo.post("/demo/clock/advance")
def advance_clock(req: ClockRequest, ctx: AppContext = Depends(get_ctx)):
    from aaw_domain.clock import FixedClock

    if not isinstance(ctx.rt.clock, FixedClock):
        raise HTTPException(status_code=400, detail="clock is not injectable in this process (set AAW_FIXED_CLOCK=1)")
    ctx.rt.clock.advance(req.advance_seconds)
    return {"now": ctx.rt.now()}


@demo.post("/demo/keys/{name}/rotate")
def rotate_key(name: str, is_admin: bool = Depends(optional_admin), ctx: AppContext = Depends(get_ctx)):
    """Rotate a participant key: the new key becomes active, the previous one is retired
    (still verifies retained evidence, cannot authorize new use)."""
    if not is_admin:
        raise HTTPException(status_code=401, detail="admin token required")
    from aaw_domain.trust import (
        PARTICIPANT_AGENT_MANDATE,
        PARTICIPANT_AGENT_TAP,
        PARTICIPANT_ISSUER,
        PARTICIPANT_MERCHANT,
    )

    mapping = {
        "agent_shopping_ed25519": (PARTICIPANT_AGENT_TAP, "shopping_agent_1", "ed25519"),
        "agent_shopping_es256": (PARTICIPANT_AGENT_MANDATE, "shopping_agent_1", "ES256"),
        "merchant_a": (PARTICIPANT_MERCHANT, "merchant_a", "ES256"),
        "merchant_b": (PARTICIPANT_MERCHANT, "merchant_b", "ES256"),
        "test_issuer": (PARTICIPANT_ISSUER, ctx.settings.issuer_id, "ES256"),
    }
    if name not in mapping:
        raise HTTPException(status_code=400, detail=f"rotation not supported for {name}")
    ptype, pid, alg = mapping[name]
    old = ctx.rt.keys.get(name)
    new = ctx.rt.keys.rotate(name)
    with ctx.rt.session() as s:
        trust = ctx.rt.trust(s)
        trust.register(ptype, pid, new.kid, new.public_jwk(), alg, "rotation")
        trust.retire_others(ptype, pid, new.kid)
        if name == "agent_shopping_ed25519":
            a = s.get(Agent, "shopping_agent_1")
            a.tap_key_id = new.kid
        if name == "agent_shopping_es256":
            from aaw_signer import jwk_thumbprint

            a = s.get(Agent, "shopping_agent_1")
            a.mandate_public_jwk = new.public_jwk()
            a.mandate_key_thumbprint = jwk_thumbprint(new.public_jwk())
        if name in ("merchant_a", "merchant_b"):
            m = s.get(Merchant, name)
            m.checkout_kid = new.kid
    return {"rotated": name, "previous_kid": old.kid, "new_kid": new.kid,
            "note": "previous key retired: verifies retained evidence, cannot authorize new use"}


@demo.get("/metrics")
def metrics(ctx: AppContext = Depends(get_ctx)):
    now = ctx.rt.now()
    with ctx.rt.session() as s:
        attempts = list(s.execute(select(VerificationAttempt)).scalars())
        by_role: Dict[str, Dict[str, Any]] = {}
        reasons: Dict[str, int] = {}
        for v in attempts:
            r = by_role.setdefault(v.verifier_role, {"count": 0, "latency_ms_total": 0, "decisions": {}})
            r["count"] += 1
            r["latency_ms_total"] += v.latency_ms
            r["decisions"][v.decision] = r["decisions"].get(v.decision, 0) + 1
            for code in v.reason_codes:
                reasons[code] = reasons.get(code, 0) + 1
        for r in by_role.values():
            r["latency_ms_avg"] = round(r["latency_ms_total"] / r["count"], 2) if r["count"] else 0
        replay_attempts = reasons.get("REQUEST_REPLAY", 0)
        nonces_recorded = s.execute(select(func.count()).select_from(RequestReplayRecord)).scalar_one()
        grants = list(s.execute(select(AuthorizationGrant)).scalars())
        claims = list(s.execute(select(ExecutionClaim)).scalars())
        return {
            "verification": by_role,
            "rejection_reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
            "replay": {"attempts_rejected": replay_attempts, "nonces_recorded": nonces_recorded},
            "authorizations": {
                "by_status": _count(g.status for g in grants),
                "expiring_within_1h": sum(1 for g in grants if g.status == "active" and now <= g.expires_at <= now + 3600),
                "expired": sum(1 for g in grants if g.status == "expired" or (g.status == "active" and g.expires_at < now)),
            },
            "executions": {
                "by_state": _count(c.state for c in claims),
                "unresolved": sum(1 for c in claims if c.state in ("claimed", "executing", "execution_unknown")),
            },
        }


def _count(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


__all__ = ["proposals", "executions", "agent", "demo"]
