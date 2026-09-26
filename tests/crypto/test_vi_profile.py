"""Verifiable Intent profile: separate fixtures and verification rules.

Independence: ``fixtures/vi/reference_autonomous.json`` was produced by the
vendored reference implementation alone (no adapter code); our adapter must
accept it. Conversely the reference verifier (``verify_chain``) is what checks
the artifacts our adapter produces."""

from __future__ import annotations

import json

import pytest

from aaw_domain import PARTICIPANT_ISSUER, Database, TrustStore, VerifyExpectations
from aaw_domain.profiles import Presentation
from aaw_signer import jwk_thumbprint
from aaw_vi import VIProfile
from tests.conftest import FIXTURES, Harness, codes
from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
from verifiable_intent.verification.chain import verify_chain as reference_verify_chain

profile = VIProfile()


@pytest.mark.parametrize("mode", ["autonomous", "direct"])
def test_valid_presentations_pass_both_roles(harness: Harness, mode):
    co = harness.checkout()
    art, pres, mpv, ppv = harness.run(profile, mode, co)
    assert mpv.crypto_valid and mpv.protocol_valid and not mpv.reasons, mpv.details
    assert ppv.crypto_valid and ppv.protocol_valid and not ppv.reasons, ppv.details
    assert mpv.checkout_hash == co.checkout_hash == ppv.transaction_id
    assert ppv.amount_minor == 12000
    if mode == "autonomous":
        assert mpv.agent_key_thumbprint == jwk_thumbprint(harness.agent.public_jwk())
        assert ppv.reference_digest == mpv.open_mandate_digest
        assert {c.type for c in ppv.constraint_results} == {"mandate.payment.amount_range", "mandate.payment.allowed_payees",
                                                            "mandate.payment.reference"}
        assert {c.type for c in mpv.constraint_results} == {"mandate.checkout.allowed_merchants", "mandate.checkout.line_items"}
        assert "l3" in pres["merchant"].payload and "l3" in pres["payment"].payload
    else:
        assert "l3" not in pres["merchant"].payload


def test_reference_fixture_verifies_through_our_adapter():
    fx = json.loads((FIXTURES / "vi" / "reference_autonomous.json").read_text())
    db = Database("sqlite://")
    db.create_all()
    trust = TrustStore(db.new_session())
    trust.register(PARTICIPANT_ISSUER, "https://www.mastercard.com", "mastercard-issuer-key-1", fx["issuer_public_jwk"], "ES256", "fixture", valid_from=0)
    p = VIProfile(l1_vct="https://credentials.mastercard.com/card")
    pres = Presentation("vi", p.version, "payment", {"l1": fx["l1"], "l2": fx["l2_for_network"], "l3": fx["l3_payment"]},
                        fx["expected"]["l3_aud_payment"], fx["expected"]["l3_nonce"])
    pv = p.verify(pres, trust, VerifyExpectations("payment", fx["expected"]["l3_aud_payment"], fx["now"] + 5,
                                                  nonce=fx["expected"]["l3_nonce"], expected_checkout_hash=fx["checkout_hash"]))
    assert pv.crypto_valid and pv.protocol_valid, (codes(pv), pv.details)
    assert pv.amount_minor == fx["expected"]["amount"] and pv.payee["id"] == fx["expected"]["payee_id"]
    assert all(c.satisfied for c in pv.constraint_results), pv.constraint_results
    # wrong nonce / expired
    assert "NONCE_MISMATCH" in codes(p.verify(pres, trust, VerifyExpectations("payment", fx["expected"]["l3_aud_payment"], fx["now"] + 5, nonce="other")))
    assert "EXPIRED_AUTHORIZATION" in codes(p.verify(pres, trust, VerifyExpectations("payment", fx["expected"]["l3_aud_payment"], fx["now"] + 100000, nonce=fx["expected"]["l3_nonce"])))
    # merchant side of the fixture: the reference cart schema is not our checkout schema, so the
    # chain verifies but the application-level checkout parse is what rejects it.
    mpres = Presentation("vi", p.version, "merchant", {"l1": fx["l1"], "l2": fx["l2_for_merchant"], "l3": fx["l3_checkout"]},
                         fx["expected"]["l3_aud_checkout"], fx["expected"]["l3_nonce"])
    mpv = p.verify(mpres, trust, VerifyExpectations("merchant", fx["expected"]["l3_aud_checkout"], fx["now"] + 5, nonce=fx["expected"]["l3_nonce"]))
    assert mpv.crypto_valid and codes(mpv) == ["MALFORMED_ARTIFACT"]
    assert "checkout missing merchant.id" in mpv.details["errors"][0]


def test_our_artifacts_verify_with_the_reference_verifier_directly(harness: Harness):
    co = harness.checkout()
    art, pres, _, _ = harness.run(profile, "autonomous", co)
    from aaw_signer.keys import jwk_to_public_key

    l1 = decode_sd_jwt(pres["payment"].payload["l1"])
    l2 = decode_sd_jwt(pres["payment"].payload["l2"])
    l3 = decode_sd_jwt(pres["payment"].payload["l3"])
    res = reference_verify_chain(l1, l2, l3_payment=l3, issuer_public_key=jwk_to_public_key(harness.issuer.public_jwk()),
                                 l1_serialized=pres["payment"].payload["l1"], l2_serialized=pres["payment"].payload["l2"],
                                 l2_payment_serialized=pres["payment"].payload["l2"], expected_l1_vct="urn:aaw:test:vi-user-credential:1",
                                 expected_l3_payment_aud=harness.payment_aud, expected_l3_payment_nonce="nonce-1")
    assert res.valid, res.errors


def test_wrong_agent_key_and_digest_mismatch_fail(harness: Harness):
    co = harness.checkout()
    _, _, mpv, ppv = harness.run(profile, "autonomous", co, tamper={"agent_handle_override": harness.rogue})
    assert codes(mpv) == ["AGENT_KEY_MISMATCH"] and codes(ppv) == ["AGENT_KEY_MISMATCH"]
    _, _, _, ppv2 = harness.run(profile, "autonomous", co, tamper={"alter_payment_amount_after_signing": 100})
    assert "DISCLOSURE_DIGEST_MISMATCH" in codes(ppv2)
    _, _, mpv3, _ = harness.run(profile, "autonomous", co, tamper={"drop_checkout_jwt": True})
    assert set(codes(mpv3)) & {"DISCLOSURE_DIGEST_MISMATCH", "MISSING_REQUIRED_DISCLOSURE"}
    _, _, mpv4, _ = harness.run(profile, "autonomous", co, tamper={"extra_disclosure": True})
    assert set(codes(mpv4)) & {"UNEXPECTED_DISCLOSURE", "DISCLOSURE_DIGEST_MISMATCH"}


def test_unknown_issuer_fails(harness: Harness):
    from aaw_signer import KeyHandle
    from aaw_vi import build_user_credential

    stranger = KeyHandle.new_es256("stranger")
    cred = build_user_credential(stranger, "https://stranger.test", "user_1", harness.user.public_jwk(), harness.now, harness.now + 3600)
    co = harness.checkout()
    art = profile.issue(harness.ctx(profile, "autonomous", harness.constraints(), credential=cred), harness.user)
    pres = profile.build_presentations(art, co, harness.agent, co.merchant["website"], harness.payment_aud, "n", harness.now)
    pv = profile.verify(pres["payment"], harness.trust, harness.expect("payment", co, "n"))
    assert codes(pv) == ["UNKNOWN_ISSUER"]


def test_checkout_payment_mismatch_and_over_cap(harness: Harness):
    approved = harness.checkout(price=12000)
    other = harness.checkout(price=15500)
    _, pres, _, _ = harness.run(profile, "direct", approved)
    assert codes(profile.verify(pres["merchant"], harness.trust, harness.expect("merchant", other))) == ["CHECKOUT_BINDING_MISMATCH"]
    # autonomous over cap: protocol-level amount_range fails
    _, _, _, ppv = harness.run(profile, "autonomous", other)
    assert ppv.crypto_valid and not ppv.constraints_satisfied
    assert any(c.type == "mandate.payment.amount_range" and not c.satisfied for c in ppv.constraint_results)


def test_line_item_constraints_are_machine_checked(harness: Harness):
    constraints = harness.constraints(line_items=[["SKU1", "SKU2"]])
    ok = harness.checkout(sku="SKU1")
    bad = harness.checkout(sku="SKU9")
    _, _, mpv, _ = harness.run(profile, "autonomous", ok, constraints=constraints)
    assert all(c.satisfied for c in mpv.constraint_results), mpv.constraint_results
    _, _, mpv2, _ = harness.run(profile, "autonomous", bad, constraints=constraints)
    assert any(c.type == "mandate.checkout.line_items" and not c.satisfied for c in mpv2.constraint_results)


def test_role_views_are_scoped(harness: Harness):
    co = harness.checkout("merchant_a")
    _, pres, _, _ = harness.run(profile, "autonomous", co)
    m = json.dumps(profile.evidence_view(pres["merchant"]))
    p = json.dumps(profile.evidence_view(pres["payment"]))
    assert "mandate.payment.open.1" not in m and "Merchant B" not in m
    assert "mandate.checkout.open.1" not in p and "SKU1" not in p
    assert "a@b.test" not in m and "a@b.test" not in p
