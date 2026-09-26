"""Generate ``reference_autonomous.json`` using ONLY the vendored Verifiable Intent
reference implementation (agent-intent/verifiable-intent @ 356c296) and its
example key material (``examples/helpers.py`` deterministic private scalars).

The wallet's VI adapter is not involved, so the fixture is an independent
artifact: our verifier must accept it, and the reference verifier must accept
what our adapter produces (see tests/crypto/test_vi_profile.py).

Run from the repository root:
    PYTHONPATH=packages/vi-profile/vendor python fixtures/vi/generate_reference_fixture.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from verifiable_intent.crypto.disclosure import _b64url_encode, build_selective_presentation, hash_bytes
from verifiable_intent.crypto.signing import _jwt_encode, public_key_to_jwk
from verifiable_intent.issuance.agent import create_layer3_checkout, create_layer3_payment
from verifiable_intent.issuance.issuer import create_layer1
from verifiable_intent.issuance.user import create_layer2_autonomous
from verifiable_intent.models.agent_mandate import (
    CheckoutL3Mandate,
    FinalCheckoutMandate,
    FinalPaymentMandate,
    PaymentL3Mandate,
)
from verifiable_intent.models.constraints import (
    AllowedMerchantConstraint,
    AllowedPayeeConstraint,
    CheckoutLineItemsConstraint,
    PaymentAmountConstraint,
)
from verifiable_intent.models.issuer_credential import IssuerCredential
from verifiable_intent.models.user_mandate import CheckoutMandate, MandateMode, PaymentMandate, UserMandate

# Deterministic example keys from the reference repository's examples/helpers.py
_ISSUER_D = 0x1A2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01
_USER_D = 0x2B3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF0102
_AGENT_D = 0x3C4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF010203
_MERCHANT_D = 0x4D5E6F708192A3B4C5D6E7F80112233445566778899AABBCCDDEEFF01020304

NOW = 1_790_400_000  # 2026-09-26T09:20:00Z
MERCHANTS = [
    {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
    {"id": "merchant-uuid-2", "name": "Babolat", "website": "https://babolat.com"},
]
ITEMS = [{"id": "BAB86345", "title": "Babolat Pure Aero Tennis Racket"}, {"id": "HEA23102", "title": "Head Graphene 360 Speed"}]
INSTRUMENT = {"type": "mastercard.srcDigitalCard", "id": "f199c3dd-7106-478b-9b5f-7af9ca725170", "description": "Mastercard **** 1234"}


def key(d):
    return ec.derive_private_key(d, ec.SECP256R1())


def main() -> None:
    issuer, user, agent, merchant = key(_ISSUER_D), key(_USER_D), key(_AGENT_D), key(_MERCHANT_D)
    l1 = create_layer1(IssuerCredential(iss="https://www.mastercard.com", sub="user-alice-001", iat=NOW, exp=NOW + 86400,
                                        aud="https://wallet.example.com", cnf_jwk=public_key_to_jwk(user),
                                        email="alice@example.com", pan_last_four="1234", scheme="Mastercard"), issuer)
    mandate = UserMandate(
        nonce="fixture-nonce-l2", aud="https://agent.verifiable-intent.example", iat=NOW, iss="https://wallet.example.com",
        exp=NOW + 86400, mode=MandateMode.AUTONOMOUS, sd_hash=hash_bytes(l1.serialize().encode("ascii")),
        prompt_summary="Buy a Babolat tennis racket under $400",
        checkout_mandate=CheckoutMandate(vct="mandate.checkout.open.1", cnf_jwk=public_key_to_jwk(agent), cnf_kid="agent-key-1",
                                         constraints=[AllowedMerchantConstraint(allowed=MERCHANTS),
                                                      CheckoutLineItemsConstraint(items=[{"id": "line-item-1", "acceptable_items": ITEMS, "quantity": 1}])]),
        payment_mandate=PaymentMandate(vct="mandate.payment.open.1", cnf_jwk=public_key_to_jwk(agent), cnf_kid="agent-key-1",
                                       payment_instrument=INSTRUMENT,
                                       constraints=[PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                                                    AllowedPayeeConstraint(allowed=MERCHANTS)]),
        merchants=MERCHANTS, acceptable_items=ITEMS,
    )
    l2 = create_layer2_autonomous(mandate, user)
    checkout_payload = {"iss": "https://tennis-warehouse.com", "sub": "cart_checkout", "iat": NOW, "exp": NOW + 3600,
                        "cart": {"items": [{"sku": "BAB86345", "name": "Babolat Pure Aero Tennis Racket", "quantity": 1, "unitPrice": 279.99}],
                                 "subTotal": {"amount": 279.99, "currencyCode": "USD"}}}
    checkout_jwt = _jwt_encode({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, checkout_payload, merchant)
    c_hash = _b64url_encode(hashlib.sha256(checkout_jwt.encode("utf-8")).digest())

    def disc(pred):
        for d, v in zip(l2.disclosures, l2.disclosure_values):
            if pred(v[-1]):
                return d
        raise KeyError

    payment_disc = disc(lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = disc(lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = disc(lambda v: isinstance(v, dict) and v.get("name") == "Tennis Warehouse")
    item_disc = disc(lambda v: isinstance(v, dict) and v.get("id") == "BAB86345")
    l2_base = l2.serialize().split("~")[0]
    nonce = "fixture-nonce-l3"
    l3a = create_layer3_payment(PaymentL3Mandate(nonce=nonce, aud="https://www.mastercard.com", iat=NOW, iss="https://agent.example.com", exp=NOW + 300,
                                                 final_payment=FinalPaymentMandate(transaction_id=c_hash, payee=MERCHANTS[0],
                                                                                   payment_amount={"currency": "USD", "amount": 27999},
                                                                                   payment_instrument=INSTRUMENT),
                                                 final_merchant=MERCHANTS[0]), agent, l2_base, payment_disc, merchant_disc)
    l3b = create_layer3_checkout(CheckoutL3Mandate(nonce=nonce, aud="https://tennis-warehouse.com", iat=NOW, iss="https://agent.example.com", exp=NOW + 300,
                                                   final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=c_hash)),
                                 agent, l2_base, checkout_disc, item_disc)
    fixture = {
        "source": "agent-intent/verifiable-intent@356c29635f1c44df7de02edb58699ca9f29bece6 reference implementation, examples/helpers.py keys",
        "now": NOW,
        "issuer_public_jwk": public_key_to_jwk(issuer),
        "merchant_public_jwk": public_key_to_jwk(merchant),
        "l1": l1.serialize(),
        "l2": l2.serialize(),
        "l2_for_merchant": build_selective_presentation(l2_base, [checkout_disc, item_disc]),
        "l2_for_network": build_selective_presentation(l2_base, [payment_disc, merchant_disc]),
        "l3_checkout": l3b.serialize(),
        "l3_payment": l3a.serialize(),
        "checkout_jwt": checkout_jwt,
        "checkout_hash": c_hash,
        "expected": {"l3_aud_checkout": "https://tennis-warehouse.com", "l3_aud_payment": "https://www.mastercard.com",
                     "l3_nonce": nonce, "amount": 27999, "payee_id": "merchant-uuid-1"},
    }
    out = Path(__file__).with_name("reference_autonomous.json")
    out.write_text(json.dumps(fixture, indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
