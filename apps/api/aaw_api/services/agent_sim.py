"""Simulated shopping agent.

The real shopping agent would be an LLM-driven process; here it is deterministic
code that (1) obtains a final checkout from the merchant, (2) builds the
profile's closed mandates with the *agent* mandate key, (3) TAP-signs the
request with the *agent* TAP key and (4) submits it to the merchant gateway.
It holds no user key. Failure injection knobs exist so every demo scenario is
reproducible.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from aaw_domain.artifacts import ArtifactVault, audit
from aaw_domain.checkout import CheckoutError, parse_checkout_jwt
from aaw_domain.models import Agent, AuthorizationGrant
from aaw_domain.profiles import GrantArtifacts, get_profile
from aaw_tap import TAG_PAYER_AUTH, sign_tap_request

from ..context import AppContext
from .consent import ServiceError


class AgentSimulator:
    def __init__(self, ctx: AppContext):
        self.ctx = ctx

    def _checkout(self, merchant_id: str, items: Optional[List[Dict[str, Any]]], checkout_reference: Optional[str]):
        with self.ctx.gateway_client() as client:
            if checkout_reference:
                r = client.get(f"/gateway/checkouts/{checkout_reference}")
            else:
                r = client.post(f"/gateway/merchants/{merchant_id}/checkouts", json={"line_items": items or []})
        if r.status_code != 200:
            raise ServiceError(r.status_code, f"merchant checkout failed: {r.text}")
        return r.json()

    def purchase(
        self,
        agent_id: str,
        grant_id: str,
        *,
        merchant_id: Optional[str] = None,
        items: Optional[List[Dict[str, Any]]] = None,
        checkout_reference: Optional[str] = None,
        tamper: Optional[Dict[str, Any]] = None,
        tap_options: Optional[Dict[str, Any]] = None,
        fault: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        tamper = dict(tamper or {})
        tap_options = dict(tap_options or {})
        now = self.ctx.rt.now()
        with self.ctx.rt.session() as s:
            agent = s.get(Agent, agent_id)
            grant = s.get(AuthorizationGrant, grant_id)
            if grant is None or grant.agent_id != agent_id:
                raise ServiceError(404, "grant not found for this agent")
            artifacts_obj = ArtifactVault(s, self.ctx.clock).load_type(grant.id, "grant_artifacts", "agent")
            summary = ArtifactVault(s, self.ctx.clock).load_type(grant.id, "grant_summary", "agent")
            profile = get_profile(grant.profile)
            artifacts = GrantArtifacts(grant.profile, grant.profile_version, grant.mode, artifacts_obj, summary,
                                       grant.agent_key_thumbprint)
            merchant_id = merchant_id or (grant.constraints_json["merchants"][0]["id"])
            co_data = self._checkout(merchant_id, items, checkout_reference or (
                grant.proposal_id and _direct_checkout_reference(s, grant)))
            try:
                checkout = parse_checkout_jwt(co_data["checkout_jwt"], self.ctx.rt.trust(s), now)
            except CheckoutError as exc:
                raise ServiceError(400, f"agent rejected merchant checkout: {exc.reason.value}")
            # resolve tamper options that reference other checkouts
            for key in ("swap_checkout_jwt_after_signing", "checkout_jwt_override"):
                if key in tamper and isinstance(tamper[key], str) and not tamper[key].startswith("eyJ"):
                    other = self._checkout(merchant_id, None, tamper[key])
                    tamper[key] = other["checkout_jwt"]
            if tamper.pop("wrong_agent_key", False):
                tamper["agent_handle_override"] = self.ctx.rt.keys.get("rogue_agent_es256")
            nonce = nonce or str(uuid.uuid4())
            presentations = profile.build_presentations(
                artifacts, checkout, self.ctx.rt.keys.get("agent_shopping_es256"),
                checkout.merchant.get("website", ""), self.ctx.settings.payment_audience, nonce, now, tamper=tamper,
            )
            trace_id = f"trace_{uuid.uuid4().hex[:16]}"
            body = {
                "trace_id": trace_id,
                "grant_id": grant.id,
                "profile": grant.profile,
                "merchant_presentation": presentations["merchant"].payload,
                "payment_presentation": presentations["payment"].payload,
                "fault": fault,
            }
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            tap_handle = self.ctx.rt.keys.get("rogue_agent_ed25519") if tap_options.get("wrong_key") \
                else self.ctx.rt.keys.get("agent_shopping_ed25519")
            path = f"/gateway/checkouts/{co_data['checkout_id']}/complete"
            headers = sign_tap_request(
                tap_handle,
                authority=tap_options.get("authority") or self.ctx.settings.gateway_authority,
                path=path,
                body=raw,
                key_id=tap_options.get("key_id") or agent.tap_key_id,
                tag=tap_options.get("tag") or TAG_PAYER_AUTH,
                nonce=tap_options.get("nonce") or nonce,
                created=now - int(tap_options.get("age_seconds", 0)),
                lifetime=int(tap_options.get("lifetime", 480)),
                agent_identity=agent.id,
                override_covered=["@authority", "@path"] if tap_options.get("no_content_digest") else None,
            )
            if tap_options.get("tamper_body"):
                body["fault"] = "tampered"
                raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            audit(s, actor=f"agent:{agent_id}", action="AGENT_SUBMITTED_PURCHASE", target_type="grant", target_id=grant.id,
                  trace_id=trace_id, clock=self.ctx.clock, checkout_id=co_data["checkout_id"], total_minor=checkout.total_minor,
                  tamper=sorted(k for k in tamper.keys() if k != "agent_handle_override"), tap_options=sorted(tap_options))
        request_record = {"path": path, "headers": headers, "body": raw.decode("utf-8"), "nonce": nonce,
                          "checkout_id": co_data["checkout_id"], "trace_id": trace_id}
        return self.send(request_record, checkout=co_data)

    def send(self, request_record: Dict[str, Any], checkout: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Deliver (or re-deliver, for replay demos) a previously signed request."""
        with self.ctx.gateway_client() as client:
            r = client.post(request_record["path"], content=request_record["body"].encode("utf-8"),
                            headers={**request_record["headers"], "Content-Type": "application/json"})
        try:
            data = r.json()
        except ValueError:
            data = {"detail": r.text}
        return {"status_code": r.status_code, "response": data, "request": request_record, "checkout": checkout}


def _direct_checkout_reference(s, grant: AuthorizationGrant) -> Optional[str]:
    from aaw_domain.models import AuthorizationProposal

    if grant.mode != "direct":
        return None
    p = s.get(AuthorizationProposal, grant.proposal_id)
    return p.checkout_reference if p else None
