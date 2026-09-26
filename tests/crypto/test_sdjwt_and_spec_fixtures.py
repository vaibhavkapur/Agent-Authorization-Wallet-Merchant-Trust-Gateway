"""SD-JWT / Delegate SD-JWT primitives and the AP2 specification's published example
artifacts (fixtures/ap2/*). The fixtures were produced by an independent
implementation (Google's, as published on ap2-protocol.org); our parser and
verifier must accept them exactly, and reject them once altered."""

from __future__ import annotations

import hashlib
import json

import pytest

from aaw_ap2.sdjwt import (
    Link,
    SdJwtError,
    decode_disclosure,
    digest_disclosure,
    make_disclosure,
    parse_chain,
    resolve_claims,
    serialize_chain,
)
from aaw_ap2.verify import verify_chain
from aaw_domain import Database, TrustStore, VerifyExpectations
from aaw_domain.checkout import checkout_hash
from aaw_signer import b64url_decode, b64url_encode
from verifiable_intent.crypto.disclosure import hash_disclosure as vi_hash_disclosure  # independent implementation

from tests.conftest import FIXTURES


def _trust():
    db = Database("sqlite://")
    db.create_all()
    return TrustStore(db.new_session())


def test_disclosure_digest_matches_independent_implementation():
    d = make_disclosure({"id": "m1", "name": "M"}, salt="c2FsdA")
    assert digest_disclosure(d) == vi_hash_disclosure(d)
    named = make_disclosure("value", name="claim")
    arr = decode_disclosure(named)
    assert arr[1] == "claim" and arr[2] == "value"


def test_resolve_claims_handles_sd_and_array_elements_and_rejects_duplicates():
    d1 = make_disclosure("v1", name="a")
    d2 = make_disclosure({"x": 1})
    payload = {"_sd": [digest_disclosure(d1)], "arr": [{"...": digest_disclosure(d2)}, "plain"], "_sd_alg": "sha-256"}
    res = resolve_claims(payload, [d1, d2])
    assert res.claims == {"a": "v1", "arr": [{"x": 1}, "plain"]}
    assert not res.unused()
    with pytest.raises(SdJwtError):
        resolve_claims(payload, [d1, d1])
    # undisclosed digests are simply omitted
    res2 = resolve_claims(payload, [d1])
    assert res2.claims == {"a": "v1", "arr": ["plain"]}


def test_chain_serialization_round_trip():
    l1 = Link("a.b.c", ["d1", "d2"])
    l2 = Link("x.y.z", [])
    l3 = Link("p.q.r", ["d3"])
    compact = serialize_chain([l1, l2, l3])
    assert compact == "a.b.c~d1~d2~~x.y.z~~p.q.r~d3~"
    links = parse_chain(compact)
    assert [(l.jwt, l.disclosures) for l in links] == [("a.b.c", ["d1", "d2"]), ("x.y.z", []), ("p.q.r", ["d3"])]
    with pytest.raises(SdJwtError):
        parse_chain("a.b.c~d1")  # no trailing ~ → dSD-JWT+KB not supported by this profile


def test_ap2_spec_example_chain_is_internally_consistent():
    compact = (FIXTURES / "ap2" / "spec_checkout_mandate_chain.dsdjwt").read_text().strip()
    links = parse_chain(compact)
    assert len(links) == 2
    open_link, closed_link = links
    assert open_link.header["typ"] == "example+sd-jwt"
    assert closed_link.header["typ"] == "kb+sd-jwt"
    # sd_hash in the closed KB-SD-JWT covers the open presentation exactly
    assert closed_link.payload["sd_hash"] == open_link.sd_hash()
    # every delegate_payload digest in the closed link resolves to a presented disclosure
    resolved = resolve_claims(closed_link.payload, closed_link.disclosures)
    content = resolved.claims["delegate_payload"][0]
    assert content["vct"] == "mandate.checkout.1"
    assert content["checkout_hash"] == checkout_hash(content["checkout_jwt"])
    assert not resolved.unused()


def test_ap2_spec_example_verifies_through_our_verifier_and_fails_when_altered():
    compact = (FIXTURES / "ap2" / "spec_checkout_mandate_chain.dsdjwt").read_text().strip()
    trust = _trust()
    closed_iat = parse_chain(compact)[1].payload["iat"]
    expect = VerifyExpectations("merchant", "merchant", closed_iat + 10, nonce="b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4")
    # The issuer key ("agent-provider-key-1") is not published, so only the issuer signature is skipped.
    res = verify_chain(compact, trust, expect, skip_issuer_signature=True)
    assert res.ok, res.errors
    assert res.crypto_valid
    assert res.links[-1].content["vct"] == "mandate.checkout.1"

    # altered checkout_jwt disclosure → digest no longer matches
    links = parse_chain(compact)
    tampered = []
    for d in links[1].disclosures:
        arr = decode_disclosure(d)
        if len(arr) == 3 and arr[1] == "checkout_jwt":
            arr[2] = arr[2][:-4] + "AAAA"
            d = b64url_encode(json.dumps(arr).encode())
        tampered.append(d)
    links[1].disclosures = tampered
    bad = verify_chain(serialize_chain(links), trust, expect, skip_issuer_signature=True)
    assert not bad.ok
    assert bad.errors[0][0].value in ("DISCLOSURE_DIGEST_MISMATCH", "MISSING_REQUIRED_DISCLOSURE")

    # wrong nonce / audience
    assert not verify_chain(compact, trust, VerifyExpectations("merchant", "merchant", closed_iat + 10, nonce="x"),
                            skip_issuer_signature=True).ok
    assert not verify_chain(compact, trust, VerifyExpectations("merchant", "other", closed_iat + 10),
                            skip_issuer_signature=True).ok

    # a bit flipped in the closed signature
    links = parse_chain(compact)
    h, p, sig = links[1].jwt.split(".")
    raw = bytearray(b64url_decode(sig))
    raw[0] ^= 0x01
    links[1].jwt = ".".join([h, p, b64url_encode(bytes(raw))])
    assert not verify_chain(serialize_chain(links), trust, expect, skip_issuer_signature=True).ok


def test_ap2_spec_payment_example_reference_equals_open_checkout_sd_hash():
    """Documents the published example: the payment.reference conditional_transaction_id
    equals the sd_hash the agent computed over the open checkout mandate presentation."""
    open_checkout = (FIXTURES / "ap2" / "spec_open_checkout_mandate.sdjwt").read_text().strip()
    payment_chain = (FIXTURES / "ap2" / "spec_payment_mandate_chain.dsdjwt").read_text().strip()
    open_link = parse_chain(open_checkout)[0]
    links = parse_chain(payment_chain)
    open_payment = resolve_claims(links[0].payload, links[0].disclosures).claims["delegate_payload"][0]
    ref = next(c for c in open_payment["constraints"] if c["type"] == "payment.reference")
    assert ref["conditional_transaction_id"] == open_link.sd_hash()
    assert hashlib.sha256(open_link.serialize().encode()).digest()  # sanity: sd_hash is sha-256 of the presentation
