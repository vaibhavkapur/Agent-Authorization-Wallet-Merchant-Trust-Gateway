"""AP2 profile: cryptographic and protocol tests (plan §19)."""

from __future__ import annotations

import json

import pytest

from aaw_ap2 import AP2Profile, build_user_credential
from aaw_ap2.sdjwt import Link, parse_chain, serialize_chain
from aaw_domain import PARTICIPANT_ISSUER
from aaw_domain.profiles import Presentation
from aaw_signer import KeyHandle, b64url_encode, jwk_thumbprint, sign_compact
from tests.conftest import Harness, codes
from verifiable_intent.crypto.signing import _jwt_decode_parts, es256_verify, jwk_to_public_key  # independent verifier

profile = AP2Profile()


@pytest.mark.parametrize("mode", ["autonomous", "direct"])
def test_valid_presentations_pass_both_roles(harness: Harness, mode):
    co = harness.checkout()
    art, pres, mpv, ppv = harness.run(profile, mode, co)
    assert mpv.crypto_valid and mpv.protocol_valid and not mpv.reasons, mpv.details
    assert ppv.crypto_valid and ppv.protocol_valid and not ppv.reasons, ppv.details
    assert mpv.checkout_hash == co.checkout_hash == ppv.transaction_id
    assert ppv.amount_minor == 12000 and ppv.currency == "USD"
    assert mpv.mode == mode == ppv.mode
    if mode == "autonomous":
        assert mpv.agent_key_thumbprint == jwk_thumbprint(harness.agent.public_jwk())
        assert ppv.reference_digest == mpv.open_mandate_digest
        assert {c.type for c in mpv.constraint_results} == {"checkout.allowed_merchants"}
        assert {c.type for c in ppv.constraint_results} >= {"payment.amount_range", "payment.allowed_payees", "payment.reference"}
    assert len(parse_chain(pres["merchant"].payload["chain"])) == (3 if mode == "autonomous" else 2)


def test_signatures_verify_with_independent_ecdsa_implementation(harness: Harness):
    """Second verifier: the VI reference implementation's raw ES256 verifier checks
    every JWS in our AP2 chain against the key our verifier resolved."""
    co = harness.checkout()
    art, pres, mpv, _ = harness.run(profile, "autonomous", co)
    links = parse_chain(pres["merchant"].payload["chain"])
    keys = [harness.issuer.public_jwk(), harness.user.public_jwk(), harness.agent.public_jwk()]
    for link, jwk in zip(links, keys):
        header, payload, sig = _jwt_decode_parts(link.jwt)
        signing_input = link.jwt.rsplit(".", 1)[0].encode("ascii")
        assert es256_verify(signing_input, sig, jwk_to_public_key(jwk)), header


def test_altered_signed_content_fails(harness: Harness):
    co = harness.checkout()
    _, pres, _, _ = harness.run(profile, "autonomous", co)
    links = parse_chain(pres["payment"].payload["chain"])
    h, p, s = links[2].jwt.split(".")
    payload = json.loads(__import__("aaw_signer").b64url_decode(p))
    payload["iat"] += 1
    links[2].jwt = ".".join([h, b64url_encode(json.dumps(payload).encode()), s])
    bad = Presentation("ap2", profile.version, "payment", {"chain": serialize_chain(links)}, harness.payment_aud, "nonce-1")
    pv = profile.verify(bad, harness.trust, harness.expect("payment", co))
    assert not pv.crypto_valid and "AGENT_KEY_MISMATCH" in codes(pv)


def test_unsupported_algorithm_and_unknown_issuer_fail(harness: Harness):
    co = harness.checkout()
    # unknown issuer: credential signed by a key not on the allowlist
    stranger = KeyHandle.new_es256("stranger-1")
    cred = build_user_credential(stranger, "https://stranger.test", "user_1", harness.user.public_jwk(), harness.now,
                                 harness.now + 3600).serialize()
    art = profile.issue(harness.ctx(profile, "autonomous", harness.constraints(), credential=cred), harness.user)
    pres = profile.build_presentations(art, co, harness.agent, co.merchant["website"], harness.payment_aud, "n", harness.now)
    pv = profile.verify(pres["merchant"], harness.trust, harness.expect("merchant", co, "n"))
    assert codes(pv) == ["UNKNOWN_ISSUER"]
    # same issuer id, wrong key type/alg registered (EdDSA credential)
    ed = KeyHandle.new_ed25519("issuer-ed")
    harness.trust.register(PARTICIPANT_ISSUER, "https://ed.test", ed.kid, ed.public_jwk(), "EdDSA", "test")
    cred_link = build_user_credential(harness.issuer, "https://ed.test", "user_1", harness.user.public_jwk(), harness.now,
                                      harness.now + 3600)
    # re-sign the credential payload with the Ed25519 key (alg EdDSA)
    payload = cred_link.payload
    jwt = sign_compact(ed, {"typ": "dc+sd-jwt", "kid": ed.kid}, payload)
    art = profile.issue(harness.ctx(profile, "autonomous", harness.constraints(), credential=Link(jwt).serialize()), harness.user)
    pres = profile.build_presentations(art, co, harness.agent, co.merchant["website"], harness.payment_aud, "n", harness.now)
    pv = profile.verify(pres["merchant"], harness.trust, harness.expect("merchant", co, "n"))
    assert codes(pv) == ["UNSUPPORTED_ALGORITHM"]


def test_wrong_agent_key_fails(harness: Harness):
    co = harness.checkout()
    _, _, mpv, ppv = harness.run(profile, "autonomous", co, tamper={"agent_handle_override": harness.rogue})
    assert codes(mpv) == ["AGENT_KEY_MISMATCH"] and codes(ppv) == ["AGENT_KEY_MISMATCH"]


def test_selective_disclosure_digest_mismatch_fails(harness: Harness):
    co = harness.checkout()
    _, _, mpv, ppv = harness.run(profile, "autonomous", co, tamper={"alter_payment_amount_after_signing": 100})
    assert not ppv.protocol_valid and "DISCLOSURE_DIGEST_MISMATCH" in codes(ppv)
    assert mpv.protocol_valid
    _, _, mpv2, _ = harness.run(profile, "autonomous", co, tamper={"swap_checkout_jwt_after_signing": harness.checkout(price=1).checkout_jwt})
    assert "DISCLOSURE_DIGEST_MISMATCH" in codes(mpv2)


def test_missing_required_disclosure_is_rejected(harness: Harness):
    co = harness.checkout()
    _, _, mpv, _ = harness.run(profile, "autonomous", co, tamper={"drop_checkout_jwt": True})
    assert "MISSING_REQUIRED_DISCLOSURE" in codes(mpv)
    _, _, mpv2, _ = harness.run(profile, "autonomous", co, tamper={"extra_disclosure": True})
    assert set(codes(mpv2)) & {"UNEXPECTED_DISCLOSURE", "DISCLOSURE_DIGEST_MISMATCH"}


def test_checkout_and_payment_mismatch_fails(harness: Harness):
    approved = harness.checkout(price=12000)
    other = harness.checkout(price=15500)
    # direct: user approved `approved`, agent presents it to complete `other`
    _, pres, _, _ = harness.run(profile, "direct", approved)
    pv = profile.verify(pres["merchant"], harness.trust, harness.expect("merchant", other))
    assert codes(pv) == ["CHECKOUT_BINDING_MISMATCH"]
    ppv = profile.verify(pres["payment"], harness.trust, harness.expect("payment", other))
    assert codes(ppv) == ["PAYMENT_BINDING_MISMATCH"]


def test_profile_specific_algorithm_and_typ_requirements(harness: Harness):
    co = harness.checkout()
    _, pres, _, _ = harness.run(profile, "autonomous", co)
    links = parse_chain(pres["merchant"].payload["chain"])
    # intermediate link must be kb+sd-jwt+kb: swap typ of the user link
    hdr = links[1].header
    hdr["typ"] = "kb+sd-jwt"
    from aaw_signer import b64url_decode

    payload = json.loads(b64url_decode(links[1].jwt.split(".")[1]))
    links[1].jwt = sign_compact(harness.user, hdr, payload)  # re-signed, so the failure is the typ rule, not the signature
    bad = Presentation("ap2", profile.version, "merchant", {"chain": serialize_chain(links)}, co.merchant["website"], "nonce-1")
    pv = profile.verify(bad, harness.trust, harness.expect("merchant", co))
    assert "MALFORMED_ARTIFACT" in codes(pv) or "CHAIN_BINDING_MISMATCH" in codes(pv)


def test_open_claims_must_be_unchanged_in_closed_mandate(harness: Harness):
    """AP2 rule: claims present in the open mandate must be unchanged in the closed one
    (payment_instrument here)."""
    co = harness.checkout()
    _, _, _, ppv = harness.run(profile, "autonomous", co,
                               tamper={"payment_instrument_override": {"id": "other", "type": "card", "description": "x"}})
    assert "PAYMENT_INSTRUMENT_NOT_ALLOWED" in codes(ppv)


def test_merchant_view_reveals_only_this_merchant(harness: Harness):
    co = harness.checkout("merchant_a")
    _, pres, mpv, ppv = harness.run(profile, "autonomous", co)
    merchant_view = profile.evidence_view(pres["merchant"])
    payment_view = profile.evidence_view(pres["payment"])
    m_values = json.dumps(merchant_view)
    p_values = json.dumps(payment_view)
    assert "Merchant B" not in m_values and "merchant_b" not in m_values
    assert "mandate.payment" not in m_values
    assert "mandate.checkout" not in p_values and "SKU1" not in p_values
    assert "15000" not in p_values.replace('"max": 15000', "")  # cap only inside the constraint the payee role needs
    assert "a@b.test" not in m_values and "a@b.test" not in p_values  # identity claims never disclosed


def test_expiry_boundary_with_injected_clock():
    constraints_exp = 1_900_000_000
    h = Harness(now=constraints_exp - 3600)
    constraints = h.constraints(expires_at="2030-03-17T17:46:40+00:00")
    assert constraints.expires_ts == constraints_exp
    art = profile.issue(h.ctx(profile, "autonomous", constraints), h.user)
    for present_at, ok in ((constraints_exp - 1, True), (constraints_exp + 121, False)):
        h.now = present_at
        co = h.checkout()
        pres = profile.build_presentations(art, co, h.agent, co.merchant["website"], h.payment_aud, "n", present_at)
        pv = profile.verify(pres["merchant"], h.trust, h.expect("merchant", co, "n", now=present_at),
                            expected_intermediate_aud=h.agent_aud)
        assert pv.protocol_valid is ok, (present_at, codes(pv))
        if not ok:
            assert "EXPIRED_AUTHORIZATION" in codes(pv)
