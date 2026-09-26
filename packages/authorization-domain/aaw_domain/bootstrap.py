"""Demo participants (all simulated test participants).

Idempotent: every app calls :func:`bootstrap` on startup against the shared
database. Public keys go to the trust store; private keys stay in the dev key
store of the process that owns the role.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from aaw_signer import jwk_thumbprint

from .models import Agent, Merchant, User
from .runtime import Runtime
from .trust import (
    PARTICIPANT_AGENT_MANDATE,
    PARTICIPANT_AGENT_TAP,
    PARTICIPANT_ISSUER,
    PARTICIPANT_MERCHANT,
    PARTICIPANT_VERIFIER,
)

DEMO_USER = {"id": "demo_user", "display_name": "Demo User (simulated)", "api_token": "user-token-demo"}
DEMO_AGENT = {
    "id": "shopping_agent_1",
    "display_name": "Shopping Agent 1 (simulated)",
    "provider": "urn:aaw:test-agent-provider",
    "api_token": "agent-token-demo",
}
MERCHANTS: List[Dict[str, Any]] = [
    {"id": "merchant_a", "name": "Merchant A (test)", "website": "https://merchant-a.aaw.test", "key": "merchant_a"},
    {"id": "merchant_b", "name": "Merchant B (test)", "website": "https://merchant-b.aaw.test", "key": "merchant_b"},
]
CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "merchant_a": [
        {"id": "SKU-HEADPHONES", "title": "Wired headphones", "unit_price_minor": 12000, "currency": "USD"},
        {"id": "SKU-CABLE", "title": "USB-C cable", "unit_price_minor": 1500, "currency": "USD"},
        {"id": "SKU-SPEAKER", "title": "Desk speaker", "unit_price_minor": 15500, "currency": "USD"},
        {"id": "SKU-STAND", "title": "Laptop stand", "unit_price_minor": 15000, "currency": "USD"},
    ],
    "merchant_b": [
        {"id": "SKU-KEYBOARD", "title": "Compact keyboard", "unit_price_minor": 9900, "currency": "USD"},
        {"id": "SKU-MOUSE", "title": "Wireless mouse", "unit_price_minor": 4500, "currency": "USD"},
    ],
}


def merchant_authority(gateway_authority: str) -> str:
    return gateway_authority


def bootstrap(rt: Runtime, *, issuer_id: str, gateway_id: str, processor_id: str) -> None:
    """Idempotent and safe under concurrent startup: a lost insert race is retried, at
    which point the rows created by the other process are found and reused."""
    import time

    from sqlalchemy.exc import IntegrityError

    rt.db.create_all()
    for attempt in range(5):
        try:
            _bootstrap_once(rt, issuer_id=issuer_id, gateway_id=gateway_id, processor_id=processor_id)
            return
        except IntegrityError:
            if attempt == 4:
                raise
            time.sleep(0.2 * (attempt + 1))


def _bootstrap_once(rt: Runtime, *, issuer_id: str, gateway_id: str, processor_id: str) -> None:
    now = rt.now()
    with rt.session() as s:
        trust = rt.trust(s)
        if s.get(User, DEMO_USER["id"]) is None:
            s.add(User(id=DEMO_USER["id"], display_name=DEMO_USER["display_name"], api_token=DEMO_USER["api_token"],
                       created_at=now))
        agent_mandate = rt.keys.get("agent_shopping_es256")
        agent_tap = rt.keys.get("agent_shopping_ed25519")
        if s.get(Agent, DEMO_AGENT["id"]) is None:
            s.add(Agent(id=DEMO_AGENT["id"], display_name=DEMO_AGENT["display_name"], provider=DEMO_AGENT["provider"],
                        mandate_public_jwk=agent_mandate.public_jwk(),
                        mandate_key_thumbprint=jwk_thumbprint(agent_mandate.public_jwk()),
                        tap_key_id=agent_tap.kid, api_token=DEMO_AGENT["api_token"], created_at=now))
        trust.register(PARTICIPANT_AGENT_MANDATE, DEMO_AGENT["id"], agent_mandate.kid, agent_mandate.public_jwk(),
                       "ES256", "local-config")
        trust.register(PARTICIPANT_AGENT_TAP, DEMO_AGENT["id"], agent_tap.kid, agent_tap.public_jwk(), "ed25519",
                       "test-registry")
        for m in MERCHANTS:
            handle = rt.keys.get(m["key"])
            if s.get(Merchant, m["id"]) is None:
                s.add(Merchant(id=m["id"], name=m["name"], website=m["website"], authority="gateway", checkout_kid=handle.kid,
                               created_at=now))
            trust.register(PARTICIPANT_MERCHANT, m["id"], handle.kid, handle.public_jwk(), "ES256", "local-config")
        issuer = rt.keys.get("test_issuer")
        trust.register(PARTICIPANT_ISSUER, issuer_id, issuer.kid, issuer.public_jwk(), "ES256", "test-issuer")
        gw = rt.keys.get("merchant_gateway")
        trust.register(PARTICIPANT_VERIFIER, gateway_id, gw.kid, gw.public_jwk(), "ES256", "local-config")
        pp = rt.keys.get("payment_processor")
        trust.register(PARTICIPANT_VERIFIER, processor_id, pp.kid, pp.public_jwk(), "ES256", "local-config")


def merchant_record(merchant_id: str) -> Dict[str, Any]:
    for m in MERCHANTS:
        if m["id"] == merchant_id:
            return {"id": m["id"], "name": m["name"], "website": m["website"]}
    raise KeyError(merchant_id)


def stable_token(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:32]
