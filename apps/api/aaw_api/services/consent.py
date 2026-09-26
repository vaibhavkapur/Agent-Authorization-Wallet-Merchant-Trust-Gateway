"""Proposals, consent challenges and approval (plan §8–§10).

Approval is the only path to the user signing component. It requires a fresh,
unconsumed challenge whose ``snapshot_digest`` equals the digest of the current
proposal snapshot; if the proposal changed after review the challenge is
invalidated and the caller receives the updated proposal.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from aaw_domain.artifacts import ArtifactVault, audit
from aaw_domain.checkout import CheckoutError, parse_checkout_jwt
from aaw_domain.constraints import GrantConstraints, MerchantRef, ProposalRequest, render_consent_snapshot
from aaw_domain.clock import to_utc_iso
from aaw_domain.models import (
    Agent,
    AuthorizationGrant,
    AuthorizationProposal,
    ConsentChallenge,
    Merchant,
    new_id,
)
from aaw_domain.profiles import CheckoutSummary, IssuanceContext, get_profile
from aaw_signer import ApprovedConsent, ConsentBindingError
from aaw_signer.user_component import canonical_digest

from ..context import AppContext


class ServiceError(Exception):
    def __init__(self, status_code: int, detail: Any):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def proposal_dict(p: AuthorizationProposal) -> Dict[str, Any]:
    return {
        "id": p.id,
        "user_id": p.user_id,
        "agent_id": p.agent_id,
        "profile": p.profile,
        "profile_version": p.profile_version,
        "mode": p.mode,
        "status": p.status,
        "version": p.version,
        "constraints": p.constraints_json,
        "checkout_reference": p.checkout_reference,
        "consent_snapshot": p.consent_snapshot_json,
        "consent_snapshot_digest": p.consent_snapshot_digest,
        "grant_id": p.grant_id,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    }


def grant_dict(g: AuthorizationGrant, summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {
        "id": g.id,
        "proposal_id": g.proposal_id,
        "user_id": g.user_id,
        "agent_id": g.agent_id,
        "agent_key_thumbprint": g.agent_key_thumbprint,
        "profile": g.profile,
        "profile_version": g.profile_version,
        "mode": g.mode,
        "constraints": g.constraints_json,
        "consent_snapshot_digest": g.consent_snapshot_digest,
        "bound_checkout_digest": g.bound_checkout_digest,
        "status": g.status,
        "expires_at": g.expires_at,
        "not_before": g.not_before,
        "cancelled_at": g.cancelled_at,
        "version": g.version,
        "created_at": g.created_at,
        "updated_at": g.updated_at,
    }
    if summary is not None:
        d["artifact_summary"] = summary
    return d


class ConsentService:
    def __init__(self, ctx: AppContext):
        self.ctx = ctx

    # -- proposals ------------------------------------------------------------

    def create_proposal(self, req: ProposalRequest, actor_agent_id: str) -> Dict[str, Any]:
        if req.agent_id != actor_agent_id:
            raise ServiceError(403, "an agent may only propose delegations to itself")
        profile = get_profile(req.profile)
        now = self.ctx.rt.now()
        with self.ctx.rt.session() as s:
            agent = s.get(Agent, req.agent_id)
            if agent is None:
                raise ServiceError(404, "unknown agent")
            checkout: Optional[CheckoutSummary] = None
            if req.mode == "direct":
                checkout = self._fetch_checkout(s, req.checkout_reference or "", req.merchant_id or "")
                merchants = [MerchantRef(**checkout.merchant)]
                constraints = GrantConstraints(
                    currency=checkout.currency,
                    max_total_minor=str(checkout.total_minor),
                    min_total_minor=str(checkout.total_minor),
                    merchants=merchants,
                    not_before=to_utc_iso(self.ctx.clock.now()),
                    expires_at=req.expires_at or _iso(min(checkout.expires_at, now + 3600)),
                    payment_instrument=req.payment_instrument or None,
                ) if req.payment_instrument else GrantConstraints(
                    currency=checkout.currency,
                    max_total_minor=str(checkout.total_minor),
                    min_total_minor=str(checkout.total_minor),
                    merchants=merchants,
                    not_before=to_utc_iso(self.ctx.clock.now()),
                    expires_at=req.expires_at or _iso(min(checkout.expires_at, now + 3600)),
                )
            else:
                merchants = []
                for mid in req.merchant_ids:
                    m = s.get(Merchant, mid)
                    if m is None:
                        raise ServiceError(400, f"unknown merchant {mid}")
                    merchants.append(MerchantRef(id=m.id, name=m.name, website=m.website))
                kwargs: Dict[str, Any] = dict(
                    currency=req.currency,
                    max_total_minor=req.max_total_minor,
                    min_total_minor=req.min_total_minor,
                    merchants=merchants,
                    not_before=req.not_before or to_utc_iso(self.ctx.clock.now()),
                    expires_at=req.expires_at,
                    line_items=req.line_items,
                )
                if req.payment_instrument:
                    kwargs["payment_instrument"] = req.payment_instrument
                try:
                    constraints = GrantConstraints(**kwargs)
                except ValueError as exc:
                    raise ServiceError(400, str(exc))
            snapshot = render_consent_snapshot(
                profile=profile.name,
                profile_version=profile.version,
                mode=req.mode,
                agent={"id": agent.id, "display_name": agent.display_name, "provider": agent.provider,
                       "mandate_key_thumbprint": agent.mandate_key_thumbprint},
                constraints=constraints,
                display_time_zone=req.display_time_zone,
                exact_checkout=checkout.as_review() if checkout else None,
            )
            prop = AuthorizationProposal(
                id=new_id("prop"),
                user_id=req.user_id,
                agent_id=req.agent_id,
                profile=profile.name,
                profile_version=profile.version,
                mode=req.mode,
                constraints_json=constraints.model_dump(),
                checkout_reference=req.checkout_reference,
                checkout_jwt=checkout.checkout_jwt if checkout else None,
                consent_snapshot_json=snapshot,
                consent_snapshot_digest=canonical_digest(snapshot),
                status="awaiting_consent",
                version=1,
                created_at=now,
                updated_at=now,
            )
            s.add(prop)
            audit(s, actor=f"agent:{agent.id}", action="PROPOSAL_CREATED", target_type="proposal", target_id=prop.id,
                  clock=self.ctx.clock, profile=profile.name, mode=req.mode)
            s.flush()
            return proposal_dict(prop)

    def _fetch_checkout(self, s, checkout_reference: str, merchant_id: str) -> CheckoutSummary:
        with self.ctx.gateway_client() as client:
            r = client.get(f"/gateway/checkouts/{checkout_reference}")
        if r.status_code != 200:
            raise ServiceError(400, f"merchant checkout {checkout_reference} not found")
        data = r.json()
        if data["merchant"]["id"] != merchant_id:
            raise ServiceError(400, "checkout belongs to a different merchant")
        try:
            return parse_checkout_jwt(data["checkout_jwt"], self.ctx.rt.trust(s), self.ctx.rt.now())
        except CheckoutError as exc:
            raise ServiceError(400, f"checkout rejected: {exc.reason.value}: {exc}")

    def update_proposal(self, proposal_id: str, changes: Dict[str, Any], actor_agent_id: str) -> Dict[str, Any]:
        """Any change re-renders the snapshot and invalidates outstanding challenges."""
        with self.ctx.rt.session() as s:
            p = s.get(AuthorizationProposal, proposal_id)
            if p is None or p.agent_id != actor_agent_id:
                raise ServiceError(404, "proposal not found")
            if p.status != "awaiting_consent":
                raise ServiceError(409, f"proposal is {p.status}")
            constraints = GrantConstraints.model_validate({**p.constraints_json, **changes})
            agent = s.get(Agent, p.agent_id)
            snapshot = render_consent_snapshot(
                profile=p.profile, profile_version=p.profile_version, mode=p.mode,
                agent={"id": agent.id, "display_name": agent.display_name, "provider": agent.provider,
                       "mandate_key_thumbprint": agent.mandate_key_thumbprint},
                constraints=constraints, display_time_zone=p.consent_snapshot_json["validity"]["display_time_zone"],
                exact_checkout=p.consent_snapshot_json.get("exact_checkout"),
            )
            p.constraints_json = constraints.model_dump()
            p.consent_snapshot_json = snapshot
            p.consent_snapshot_digest = canonical_digest(snapshot)
            p.version += 1
            p.updated_at = self.ctx.rt.now()
            for ch in s.execute(select(ConsentChallenge).where(ConsentChallenge.proposal_id == p.id,
                                                               ConsentChallenge.consumed_at.is_(None),
                                                               ConsentChallenge.invalidated_at.is_(None))).scalars():
                ch.invalidated_at = p.updated_at
            audit(s, actor=f"agent:{actor_agent_id}", action="PROPOSAL_CHANGED", target_type="proposal", target_id=p.id,
                  clock=self.ctx.clock, version=p.version)
            return proposal_dict(p)

    def get_proposal(self, proposal_id: str, principal_kind: str, principal_id: str) -> Dict[str, Any]:
        with self.ctx.rt.session() as s:
            p = s.get(AuthorizationProposal, proposal_id)
            if p is None:
                raise ServiceError(404, "proposal not found")
            if principal_kind == "user" and p.user_id != principal_id:
                raise ServiceError(403, "proposal belongs to another user")
            if principal_kind == "agent" and p.agent_id != principal_id:
                raise ServiceError(403, "proposal belongs to another agent")
            return proposal_dict(p)

    def list_proposals(self, principal_kind: str, principal_id: str) -> List[Dict[str, Any]]:
        with self.ctx.rt.session() as s:
            col = AuthorizationProposal.user_id if principal_kind == "user" else AuthorizationProposal.agent_id
            rows = s.execute(select(AuthorizationProposal).where(col == principal_id)
                             .order_by(AuthorizationProposal.created_at.desc())).scalars()
            return [proposal_dict(p) for p in rows]

    # -- consent challenge ----------------------------------------------------

    def create_challenge(self, proposal_id: str, user_id: str) -> Dict[str, Any]:
        now = self.ctx.rt.now()
        with self.ctx.rt.session() as s:
            p = s.get(AuthorizationProposal, proposal_id)
            if p is None:
                raise ServiceError(404, "proposal not found")
            if p.user_id != user_id:
                raise ServiceError(403, "you cannot review another user's proposal")
            if p.status != "awaiting_consent":
                raise ServiceError(409, f"proposal is {p.status}")
            if p.mode == "direct" and p.checkout_jwt:
                # Re-verify the merchant checkout at review time so the screen shows current amounts.
                try:
                    parse_checkout_jwt(p.checkout_jwt, self.ctx.rt.trust(s), now)
                except CheckoutError as exc:
                    raise ServiceError(409, f"checkout no longer valid: {exc.reason.value}")
            for ch in s.execute(select(ConsentChallenge).where(ConsentChallenge.proposal_id == p.id,
                                                               ConsentChallenge.consumed_at.is_(None),
                                                               ConsentChallenge.invalidated_at.is_(None))).scalars():
                ch.invalidated_at = now
            ch = ConsentChallenge(
                id=new_id("chal"), proposal_id=p.id, user_id=user_id, snapshot_digest=p.consent_snapshot_digest,
                nonce=secrets.token_urlsafe(24), expires_at=now + self.ctx.settings.consent_challenge_ttl,
                created_at=now,
            )
            s.add(ch)
            audit(s, actor=f"user:{user_id}", action="CONSENT_CHALLENGE_ISSUED", target_type="proposal", target_id=p.id,
                  clock=self.ctx.clock, challenge_id=ch.id)
            s.flush()
            return {
                "challenge_id": ch.id,
                "nonce": ch.nonce,
                "snapshot_digest": ch.snapshot_digest,
                "expires_at": ch.expires_at,
                "review": p.consent_snapshot_json,
                "signer": {"kind": "simulated user device", "kid": self.ctx.user_component.kid,
                           "notice": "Development signer isolated behind the consent flow; not a real user device."},
            }

    # -- approval -------------------------------------------------------------

    def approve(self, proposal_id: str, user_id: str, challenge_id: str, nonce: str, snapshot_digest: str) -> Dict[str, Any]:
        now = self.ctx.rt.now()
        with self.ctx.rt.session() as s:
            p = s.get(AuthorizationProposal, proposal_id)
            if p is None:
                raise ServiceError(404, "proposal not found")
            if p.user_id != user_id:
                raise ServiceError(403, "you cannot approve another user's proposal")
            if p.status != "awaiting_consent":
                raise ServiceError(409, f"proposal is {p.status}")
            ch = s.get(ConsentChallenge, challenge_id)
            if ch is None or ch.proposal_id != p.id or ch.user_id != user_id or ch.nonce != nonce:
                raise ServiceError(400, "challenge does not belong to this proposal/user")
            if ch.consumed_at is not None:
                raise ServiceError(409, "challenge already consumed")
            if ch.invalidated_at is not None:
                raise ServiceError(409, {"error": "challenge invalidated because the proposal changed",
                                         "proposal": proposal_dict(p)})
            if ch.expires_at < now:
                raise ServiceError(410, "challenge expired; request a new one")
            if snapshot_digest != p.consent_snapshot_digest or ch.snapshot_digest != p.consent_snapshot_digest:
                ch.invalidated_at = now
                audit(s, actor=f"user:{user_id}", action="CONSENT_CHALLENGE_INVALIDATED", target_type="proposal",
                      target_id=p.id, clock=self.ctx.clock, challenge_id=ch.id, reason="snapshot changed after review")
                s.commit()  # persist the invalidation even though the request fails
                raise ServiceError(409, {"error": "reviewed snapshot differs from the current proposal",
                                         "proposal": proposal_dict(p)})
            ch.consumed_at = now
            consent = ApprovedConsent(user_id=user_id, proposal_id=p.id, challenge_id=ch.id,
                                      snapshot_digest=p.consent_snapshot_digest, approved_at=now)
            agent = s.get(Agent, p.agent_id)
            constraints = GrantConstraints.model_validate(p.constraints_json)
            profile = get_profile(p.profile)
            trust = self.ctx.rt.trust(s)
            checkout = parse_checkout_jwt(p.checkout_jwt, trust, now) if p.checkout_jwt else None
            cred = self.ctx.issue_credential(p.profile, user_id, self.ctx.user_component.public_jwk())
            ctx = IssuanceContext(
                user_id=user_id,
                agent_id=agent.id,
                agent_public_jwk=agent.mandate_public_jwk,
                mode=p.mode,
                constraints=constraints,
                issuer_credential=cred["credential"],
                issuer_id=cred["issuer"],
                wallet_issuer=self.ctx.settings.wallet_issuer,
                agent_audience=self.ctx.agent_audience(agent.id),
                consent_snapshot_digest=p.consent_snapshot_digest,
                now=now,
                checkout=checkout,
            )
            try:
                artifacts = self.ctx.user_component.sign_reviewed(consent, p.consent_snapshot_json,
                                                                  lambda handle: profile.issue(ctx, handle))
            except ConsentBindingError as exc:
                raise ServiceError(409, str(exc))
            grant = AuthorizationGrant(
                id=new_id("grant"),
                proposal_id=p.id,
                user_id=user_id,
                agent_id=agent.id,
                agent_key_thumbprint=artifacts.agent_key_thumbprint,
                profile=p.profile,
                profile_version=p.profile_version,
                mode=p.mode,
                constraints_json=p.constraints_json,
                consent_snapshot_digest=p.consent_snapshot_digest,
                bound_checkout_digest=checkout.checkout_hash if checkout else None,
                status="active",
                expires_at=constraints.expires_ts,
                not_before=min(constraints.not_before_ts, now),
                version=1,
                created_at=now,
                updated_at=now,
            )
            s.add(grant)
            vault = ArtifactVault(s, self.ctx.clock)
            vault.store(artifact_type="consent_snapshot", profile=p.profile, issuer_id=self.ctx.settings.wallet_issuer,
                        obj=p.consent_snapshot_json, allowed_reader_roles=["user", "auditor"], grant_id=grant.id)
            vault.store(artifact_type="grant_artifacts", profile=p.profile, issuer_id=self.ctx.settings.wallet_issuer,
                        obj=artifacts.objects, allowed_reader_roles=["agent", "auditor"], grant_id=grant.id)
            vault.store(artifact_type="grant_summary", profile=p.profile, issuer_id=self.ctx.settings.wallet_issuer,
                        obj=artifacts.public_summary, allowed_reader_roles=["user", "agent", "auditor"], grant_id=grant.id)
            p.status = "approved"
            p.grant_id = grant.id
            p.updated_at = now
            audit(s, actor=f"user:{user_id}", action="GRANT_APPROVED", target_type="grant", target_id=grant.id,
                  clock=self.ctx.clock, proposal_id=p.id, challenge_id=ch.id, snapshot_digest=p.consent_snapshot_digest,
                  profile=p.profile, mode=p.mode)
            s.flush()
            return grant_dict(grant, artifacts.public_summary)

    def reject(self, proposal_id: str, user_id: str) -> Dict[str, Any]:
        with self.ctx.rt.session() as s:
            p = s.get(AuthorizationProposal, proposal_id)
            if p is None or p.user_id != user_id:
                raise ServiceError(404, "proposal not found")
            p.status = "rejected"
            p.updated_at = self.ctx.rt.now()
            audit(s, actor=f"user:{user_id}", action="PROPOSAL_REJECTED", target_type="proposal", target_id=p.id,
                  clock=self.ctx.clock)
            return proposal_dict(p)

    # -- grants ---------------------------------------------------------------

    def get_grant(self, grant_id: str, principal_kind: str, principal_id: str) -> Dict[str, Any]:
        with self.ctx.rt.session() as s:
            g = s.get(AuthorizationGrant, grant_id)
            if g is None:
                raise ServiceError(404, "grant not found")
            if principal_kind == "user" and g.user_id != principal_id:
                raise ServiceError(403, "grant belongs to another user")
            if principal_kind == "agent" and g.agent_id != principal_id:
                raise ServiceError(403, "grant belongs to another agent")
            summary = None
            for art in ArtifactVault(s, self.ctx.clock).for_grant(g.id):
                if art.artifact_type == "grant_summary":
                    summary = ArtifactVault(s, self.ctx.clock).load(art, principal_kind)
            return grant_dict(g, summary)

    def list_grants(self, principal_kind: str, principal_id: str) -> List[Dict[str, Any]]:
        with self.ctx.rt.session() as s:
            col = AuthorizationGrant.user_id if principal_kind == "user" else AuthorizationGrant.agent_id
            rows = s.execute(select(AuthorizationGrant).where(col == principal_id)
                             .order_by(AuthorizationGrant.created_at.desc())).scalars()
            return [grant_dict(g) for g in rows]

    def cancel(self, grant_id: str, user_id: str) -> Dict[str, Any]:
        with self.ctx.rt.session() as s:
            g = s.get(AuthorizationGrant, grant_id)
            if g is None or g.user_id != user_id:
                raise ServiceError(404, "grant not found")
            result = self.ctx.coordinator.cancel(s, g, actor=f"user:{user_id}", trace_id=new_id("trace"))
            s.flush()
            fresh = s.get(AuthorizationGrant, grant_id)
            return {**result, "grant": grant_dict(fresh)}

    def load_grant_artifacts(self, s, grant_id: str, reader_role: str) -> Dict[str, Any]:
        vault = ArtifactVault(s, self.ctx.clock)
        return vault.load_type(grant_id, "grant_artifacts", reader_role)


def _iso(ts: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
