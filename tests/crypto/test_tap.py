"""TAP (RFC 9421) request signing and gateway verification."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric import rsa

from aaw_domain import PARTICIPANT_AGENT_TAP, Database, TrustStore
from aaw_signer import KeyHandle, b64url_encode
from aaw_tap import TapRequest, parse_signature_input, sign_tap_request, verify_tap_request
from tests.conftest import FIXTURES

AUTH = "gateway.aaw.test"
PATH = "/gateway/checkouts/co_1/complete"


def _setup():
    db = Database("sqlite://")
    db.create_all()
    s = db.new_session()
    trust = TrustStore(s)
    k = KeyHandle.new_ed25519("agent-tap-1")
    trust.register(PARTICIPANT_AGENT_TAP, "shopping_agent_1", k.kid, k.public_jwk(), "ed25519", "test-registry", valid_from=0)
    return s, trust, k


def _req(headers, body=b'{"a":1}', authority=AUTH, path=PATH):
    return TapRequest("POST", authority, path, headers, body)


def test_sign_and_verify_then_replay_is_rejected():
    s, trust, k = _setup()
    now = 1_790_000_000
    body = json.dumps({"a": 1}).encode()
    h = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now, agent_identity="shopping_agent_1")
    assert h["Signature-Input"].startswith('sig2=("@authority" "@path" "content-digest");created=')
    v = verify_tap_request(_req(h, body), trust, s, now)
    assert v.ok and v.agent_id == "shopping_agent_1" and v.tag == "agent-payer-auth"
    replay = verify_tap_request(_req(h, body), trust, s, now + 5)
    assert not replay.ok and replay.reason.value == "REQUEST_REPLAY"


def test_coverage_time_context_and_key_rules():
    s, trust, k = _setup()
    now = 1_790_000_000
    body = b'{"a":1}'
    # tampered body → digest mismatch
    h = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now)
    assert verify_tap_request(_req(h, b'{"a":2}'), trust, s, now).reason.value == "CONTENT_DIGEST_MISMATCH"
    # different authority/path → signature invalid
    assert verify_tap_request(_req(h, body, authority="evil.test"), trust, s, now).reason.value == "REQUEST_SIGNATURE_INVALID"
    assert verify_tap_request(_req(h, body, path="/other"), trust, s, now).reason.value == "REQUEST_SIGNATURE_INVALID"
    # body without content-digest coverage
    h2 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now, override_covered=["@authority", "@path"])
    assert verify_tap_request(_req(h2, body), trust, s, now).reason.value == "REQUEST_COVERAGE_INSUFFICIENT"
    # expired / future / too long
    h3 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now - 1000, lifetime=480)
    assert verify_tap_request(_req(h3, body), trust, s, now).reason.value == "REQUEST_EXPIRED"
    h4 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now + 600)
    assert verify_tap_request(_req(h4, body), trust, s, now).reason.value == "REQUEST_NOT_YET_VALID"
    h5 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now, lifetime=3600)
    assert verify_tap_request(_req(h5, body), trust, s, now).reason.value == "REQUEST_LIFETIME_TOO_LONG"
    # operation context
    h6 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now, tag="agent-browser-auth")
    assert verify_tap_request(_req(h6, body), trust, s, now).reason.value == "OPERATION_CONTEXT_MISMATCH"
    # unknown / inactive key; rogue key claiming a registered keyId
    h7 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id="nope", created=now)
    assert verify_tap_request(_req(h7, body), trust, s, now).reason.value == "UNKNOWN_AGENT_KEY"
    rogue = KeyHandle.new_ed25519("rogue")
    h8 = sign_tap_request(rogue, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now)
    assert verify_tap_request(_req(h8, body), trust, s, now).reason.value == "REQUEST_SIGNATURE_INVALID"
    trust.set_status(PARTICIPANT_AGENT_TAP, "shopping_agent_1", k.kid, "revoked")
    h9 = sign_tap_request(k, authority=AUTH, path=PATH, body=body, key_id=k.kid, created=now)
    assert verify_tap_request(_req(h9, body), trust, s, now).reason.value == "AGENT_KEY_INACTIVE"
    # missing headers
    assert verify_tap_request(_req({}, body), trust, s, now).reason.value == "REQUEST_SIGNATURE_MISSING"


def test_rsa_pss_sha256_is_accepted_for_visa_sample_parity():
    s, trust, _ = _setup()
    now = 1_790_000_000
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key().public_numbers()
    jwk = {"kty": "RSA", "n": b64url_encode(pub.n.to_bytes(256, "big")), "e": b64url_encode(pub.e.to_bytes(3, "big"))}
    trust.register(PARTICIPANT_AGENT_TAP, "rsa_agent", "rsa-key-1", jwk, "rsa-pss-sha256", "test-registry", valid_from=0)
    handle = KeyHandle(kid="rsa-key-1", _private=priv)
    h = sign_tap_request(handle, authority=AUTH, path=PATH, body=None, key_id="rsa-key-1", created=now)
    v = verify_tap_request(TapRequest("GET", AUTH, PATH, h, None), trust, s, now, require_content_digest=False)
    assert v.ok and v.alg == "rsa-pss-sha256"


def test_visa_sample_signature_input_parses():
    text = (FIXTURES / "tap" / "visa_sample_signature_input.txt").read_text().strip()
    parsed = parse_signature_input(text)
    assert parsed["label"] == "sig2"
    assert parsed["covered"] == ["@authority", "@path"]
    assert parsed["params"]["keyid"] == "key-id" and parsed["params"]["alg"] == "rsa-pss-sha256"
    assert parsed["params"]["created"] == 1735689600 and parsed["params"]["tag"] == "agent-payer-auth"
