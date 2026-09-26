"""Shared fixtures: in-memory app with injected clock, profile harness, helpers."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from starlette.testclient import TestClient

from aaw_api.app import create_app
from aaw_api.settings import Settings
from aaw_domain import (
    PARTICIPANT_ISSUER,
    PARTICIPANT_MERCHANT,
    Database,
    GrantConstraints,
    IssuanceContext,
    ItemRef,
    LineItemRequirement,
    MerchantRef,
    TrustStore,
    VerifyExpectations,
)
from aaw_domain.checkout import build_checkout_jwt, parse_checkout_jwt
from aaw_domain.clock import FixedClock
from aaw_signer import KeyHandle

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

USER_HEADERS = {"Authorization": "Bearer user-token-demo"}
AGENT_HEADERS = {"X-Agent-Token": "agent-token-demo"}
FAR_FUTURE = "2036-09-26T18:00:00+05:30"
ADMIN_TOKEN = "dev-admin-token"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime.now(timezone.utc))


@pytest.fixture
def app(clock):
    return create_app(Settings(database_url="sqlite://", keys_dir="memory"), clock=clock)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def ctx(app):
    return app.state.ctx


class Api:
    """Thin helper around the HTTP API for scenario tests."""

    def __init__(self, client: TestClient):
        self.c = client

    def propose(self, profile: str, mode: str = "autonomous", **kw) -> Dict[str, Any]:
        body: Dict[str, Any] = {"user_id": "demo_user", "agent_id": "shopping_agent_1", "profile": profile, "mode": mode,
                                "currency": "USD", "max_total_minor": "15000", "merchant_ids": ["merchant_a", "merchant_b"],
                                "expires_at": FAR_FUTURE}
        body.update(kw)
        body = {k: v for k, v in body.items() if v is not None}
        r = self.c.post("/v1/authorization-proposals", json=body, headers=AGENT_HEADERS)
        assert r.status_code == 200, r.text
        return r.json()

    def challenge(self, proposal_id: str, headers=USER_HEADERS):
        return self.c.post(f"/v1/authorization-proposals/{proposal_id}/consent-challenge", headers=headers)

    def approve(self, proposal_id: str, ch: Dict[str, Any], headers=USER_HEADERS, digest: Optional[str] = None):
        return self.c.post(f"/v1/authorization-proposals/{proposal_id}/approve",
                           json={"challenge_id": ch["challenge_id"], "nonce": ch["nonce"],
                                 "snapshot_digest": digest or ch["snapshot_digest"]}, headers=headers)

    def grant(self, profile: str, mode: str = "autonomous", **kw) -> str:
        p = self.propose(profile, mode, **kw)
        ch = self.challenge(p["id"])
        assert ch.status_code == 200, ch.text
        ap = self.approve(p["id"], ch.json())
        assert ap.status_code == 200, ap.text
        return ap.json()["id"]

    def checkout(self, merchant_id: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        r = self.c.post(f"/v1/merchants/{merchant_id}/checkouts", json={"line_items": items})
        assert r.status_code == 200, r.text
        return r.json()

    def buy(self, grant_id: str, merchant_id: str = "merchant_a", sku: str = "SKU-HEADPHONES", **kw) -> Dict[str, Any]:
        body = {"grant_id": grant_id, "merchant_id": merchant_id, "items": [{"id": sku, "quantity": 1}]}
        body.update(kw)
        r = self.c.post("/v1/agent/purchase", json=body, headers=AGENT_HEADERS)
        assert r.status_code == 200, r.text
        return r.json()

    @staticmethod
    def decision(res: Dict[str, Any]) -> str:
        return ((res["response"].get("diagnostic") or {}).get("decision")) or ""

    @staticmethod
    def reasons(res: Dict[str, Any]) -> List[str]:
        return ((res["response"].get("diagnostic") or {}).get("reason_codes")) or []

    @staticmethod
    def claim_state(res: Dict[str, Any]) -> Optional[str]:
        return (res["response"].get("claim") or {}).get("state")


@pytest.fixture
def api(client) -> Api:
    return Api(client)


# --------------------------------------------------------------------------- #
# Low-level profile harness (no HTTP)
# --------------------------------------------------------------------------- #


class Harness:
    def __init__(self, now: Optional[int] = None):
        self.db = Database("sqlite://")
        self.db.create_all()
        self.session = self.db.new_session()
        self.trust = TrustStore(self.session)
        self.now = now or int(time.time())
        self.issuer = KeyHandle.new_es256("issuer-key-1")
        self.user = KeyHandle.new_es256("user-key-1")
        self.agent = KeyHandle.new_es256("agent-key-1")
        self.rogue = KeyHandle.new_es256("rogue-key-1")
        self.merchant_a = KeyHandle.new_es256("merchant-a-key-1")
        self.merchant_b = KeyHandle.new_es256("merchant-b-key-1")
        self.issuer_id = "https://issuer.test"
        self.trust.register(PARTICIPANT_ISSUER, self.issuer_id, self.issuer.kid, self.issuer.public_jwk(), "ES256", "test")
        self.trust.register(PARTICIPANT_MERCHANT, "merchant_a", self.merchant_a.kid, self.merchant_a.public_jwk(), "ES256", "test")
        self.trust.register(PARTICIPANT_MERCHANT, "merchant_b", self.merchant_b.kid, self.merchant_b.public_jwk(), "ES256", "test")
        self.merchants = {
            "merchant_a": {"id": "merchant_a", "name": "Merchant A", "website": "https://a.test"},
            "merchant_b": {"id": "merchant_b", "name": "Merchant B", "website": "https://b.test"},
        }
        self.payment_aud = "urn:aaw:verifier:payment"
        self.agent_aud = "urn:aaw:agent:agent_1"

    def checkout(self, merchant_id: str = "merchant_a", price: int = 12000, sku: str = "SKU1", qty: int = 1):
        handle = self.merchant_a if merchant_id == "merchant_a" else self.merchant_b
        jwt = build_checkout_jwt(handle, self.merchants[merchant_id],
                                 [{"id": sku, "title": "Thing", "quantity": qty, "unit_price_minor": price}], "USD", self.now)
        return parse_checkout_jwt(jwt, self.trust, self.now)

    def constraints(self, max_minor: int = 15000, merchants=("merchant_a", "merchant_b"), line_items=None,
                    expires_at: str = FAR_FUTURE) -> GrantConstraints:
        return GrantConstraints(
            currency="USD", max_total_minor=str(max_minor),
            merchants=[MerchantRef(**self.merchants[m]) for m in merchants],
            not_before="2026-01-01T00:00:00+00:00", expires_at=expires_at,
            line_items=[LineItemRequirement(id="li1", acceptable_items=[ItemRef(id=i, title="t") for i in li], quantity=1)
                        for li in line_items] if line_items else None,
        )

    def ctx(self, profile, mode: str, constraints: GrantConstraints, checkout=None, credential: Optional[str] = None):
        if credential is None:
            if profile.name == "ap2":
                from aaw_ap2 import build_user_credential

                credential = build_user_credential(self.issuer, self.issuer_id, "user_1", self.user.public_jwk(),
                                                   self.now, self.now + 86400, {"email": "a@b.test"}).serialize()
            else:
                from aaw_vi import build_user_credential

                credential = build_user_credential(self.issuer, self.issuer_id, "user_1", self.user.public_jwk(),
                                                   self.now, self.now + 86400, email="a@b.test")
        return IssuanceContext(user_id="user_1", agent_id="agent_1", agent_public_jwk=self.agent.public_jwk(), mode=mode,
                               constraints=constraints, issuer_credential=credential, issuer_id=self.issuer_id,
                               wallet_issuer="https://wallet.test", agent_audience=self.agent_aud,
                               consent_snapshot_digest="ab" * 32, now=self.now, checkout=checkout)

    def expect(self, role: str, checkout, nonce: str = "nonce-1", now: Optional[int] = None) -> VerifyExpectations:
        now = now if now is not None else self.now
        if role == "merchant":
            return VerifyExpectations("merchant", checkout.merchant["website"], now, nonce=nonce,
                                      expected_checkout_jwt=checkout.checkout_jwt)
        return VerifyExpectations("payment", self.payment_aud, now, nonce=nonce, expected_checkout_hash=checkout.checkout_hash)

    def run(self, profile, mode: str, checkout, constraints=None, tamper=None, nonce: str = "nonce-1",
            verify_now: Optional[int] = None, present_checkout=None):
        constraints = constraints or self.constraints()
        art = profile.issue(self.ctx(profile, mode, constraints, checkout), self.user)
        present_checkout = present_checkout or checkout
        pres = profile.build_presentations(art, present_checkout, self.agent, present_checkout.merchant["website"],
                                           self.payment_aud, nonce, self.now, tamper=tamper)
        mpv = profile.verify(pres["merchant"], self.trust, self.expect("merchant", checkout, nonce, verify_now),
                             expected_intermediate_aud=self.agent_aud)
        ppv = profile.verify(pres["payment"], self.trust, self.expect("payment", checkout, nonce, verify_now),
                             expected_intermediate_aud=self.agent_aud)
        return art, pres, mpv, ppv


@pytest.fixture
def harness() -> Harness:
    return Harness()


def codes(pv) -> List[str]:
    return [r.value for r in pv.reasons]
