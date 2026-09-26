"""End-to-end flows through the HTTP API for both profiles (demo scenarios A–E and the
application tests of plan §19)."""

from __future__ import annotations

import json

import pytest

from tests.conftest import AGENT_HEADERS, USER_HEADERS, Api

PROFILES = ["ap2", "vi"]


@pytest.mark.parametrize("profile", PROFILES)
def test_demo_a_valid_autonomous_purchase(api: Api, client, profile):
    gid = api.grant(profile)
    res = api.buy(gid, "merchant_a", "SKU-HEADPHONES")  # $120 of a $150 cap
    assert res["status_code"] == 200
    assert api.decision(res) == "ALLOW" and api.claim_state(res) == "consumed"
    assert set(res["response"]["receipts"]) == {"checkout", "payment"}
    d = res["response"]["diagnostic"]
    assert d["request_authentication"] == "valid" and d["delegation_verification"] == "valid"
    assert d["constraint_verification"] == "valid" and d["binding_verification"] == "valid"
    g = client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()
    assert g["status"] == "consumed"


@pytest.mark.parametrize("profile", PROFILES)
def test_demo_b_authentic_request_invalid_purchase(api: Api, profile):
    gid = api.grant(profile, merchant_ids=["merchant_a"])
    res = api.buy(gid, "merchant_a", "SKU-SPEAKER")  # $155 > $150
    assert res["status_code"] == 403
    d = res["response"]["diagnostic"]
    assert d["request_authentication"] == "valid"  # TAP verified
    assert d["decision"] == "REQUIRE_NEW_AUTHORIZATION"
    assert "DELIVERED_TOTAL_EXCEEDS_LIMIT" in d["reason_codes"]
    assert d["evaluated_total_minor"] == "15500" and d["authorized_max_minor"] == "15000"
    # the grant is still usable for an eligible purchase
    res2 = api.buy(gid, "merchant_a", "SKU-STAND")  # exactly $150
    assert api.decision(res2) == "ALLOW" and api.claim_state(res2) == "consumed"


@pytest.mark.parametrize("profile", PROFILES)
def test_exact_cap_passes_and_cap_plus_one_fails(api: Api, client, profile):
    gid = api.grant(profile, max_total_minor="15000")
    res = api.buy(gid, "merchant_a", "SKU-STAND")  # 15000
    assert api.decision(res) == "ALLOW"
    gid2 = api.grant(profile, max_total_minor="14999")
    res2 = api.buy(gid2, "merchant_a", "SKU-STAND")
    assert api.decision(res2) == "REQUIRE_NEW_AUTHORIZATION" and "DELIVERED_TOTAL_EXCEEDS_LIMIT" in api.reasons(res2)


@pytest.mark.parametrize("profile", PROFILES)
def test_demo_c_checkout_tampering(api: Api, profile):
    # direct: the user approved checkout A; the agent tries to use it for checkout B
    a = api.checkout("merchant_a", [{"id": "SKU-HEADPHONES", "quantity": 1}])
    b = api.checkout("merchant_a", [{"id": "SKU-CABLE", "quantity": 1}])
    gid = api.grant(profile, "direct", checkout_reference=a["checkout_id"], merchant_id="merchant_a",
                    max_total_minor=None, merchant_ids=None, expires_at=None)
    res = api.buy(gid, "merchant_a", checkout_reference=b["checkout_id"])
    assert res["status_code"] == 403 and "CHECKOUT_BINDING_MISMATCH" in api.reasons(res)
    # autonomous: payee replaced after signing → digest mismatch; agent underpays → binding mismatch
    gid2 = api.grant(profile)
    res2 = api.buy(gid2, tamper={"alter_payee_after_signing" if profile == "ap2" else "alter_payment_amount_after_signing":
                                 {"id": "merchant_b", "name": "Merchant B (test)"} if profile == "ap2" else 1})
    assert res2["status_code"] == 403 and "DISCLOSURE_DIGEST_MISMATCH" in api.reasons(res2)
    res3 = api.buy(gid2, tamper={"payment_amount_minor": 100})
    assert res3["status_code"] == 403 and "PAYMENT_BINDING_MISMATCH" in api.reasons(res3)
    res4 = api.buy(gid2, tamper={"wrong_agent_key": True})
    assert "AGENT_KEY_MISMATCH" in api.reasons(res4)
    # the grant was never consumed by the failed attempts
    res5 = api.buy(gid2)
    assert api.decision(res5) == "ALLOW"


@pytest.mark.parametrize("profile", PROFILES)
def test_demo_d_replay_and_concurrency(api: Api, client, profile):
    gid = api.grant(profile)
    first = api.buy(gid)
    assert api.decision(first) == "ALLOW"
    # transport replay of the exact same signed request
    replay = client.post("/v1/agent/replay", json={"request": first["request"]}, headers=AGENT_HEADERS).json()
    assert replay["status_code"] == 401 and api.reasons(replay) == ["REQUEST_REPLAY"]
    # legitimate newly signed retry of the same business operation → original outcome
    retry = api.buy(gid, checkout_reference=first["request"]["checkout_id"])
    assert retry["status_code"] == 200 and retry["response"].get("idempotent_replay") is True
    assert retry["response"]["claim"]["id"] == first["response"]["claim"]["id"]
    # a different purchase with the consumed grant
    other = api.buy(gid, "merchant_b", "SKU-MOUSE")
    assert other["status_code"] == 403 and api.reasons(other) == ["AUTHORIZATION_CONSUMED"]
    assert api.decision(other) == "REQUIRE_NEW_AUTHORIZATION"
    execs = client.get("/v1/executions", headers=USER_HEADERS).json()
    assert len([e for e in execs if e["grant_id"] == gid]) == 1


@pytest.mark.parametrize("profile", PROFILES)
def test_demo_e_private_evidence_views(api: Api, client, profile):
    gid = api.grant(profile)
    res = api.buy(gid, "merchant_a", "SKU-HEADPHONES")
    cid = res["response"]["claim"]["id"]
    merchant = client.get(f"/v1/executions/{cid}/evidence", params={"role": "merchant"}, headers=USER_HEADERS).json()
    payment = client.get(f"/v1/executions/{cid}/evidence", params={"role": "payment"}, headers=USER_HEADERS).json()
    m = json.dumps(merchant)
    p = json.dumps(payment)
    assert "merchant_presentation" in merchant["artifacts"] and "payment_presentation" not in merchant["artifacts"]
    assert "payment_presentation" in payment["artifacts"] and "merchant_presentation" not in payment["artifacts"]
    assert set(merchant["receipts"]) == {"checkout"} and set(payment["receipts"]) == {"payment"}
    assert "Merchant B" not in m  # the other permitted merchant is never revealed to merchant A
    assert "mandate.payment" not in m
    assert "SKU-HEADPHONES" not in p and "mandate.checkout" not in p  # line items stay out of the payment view
    assert "demo_user@users.aaw.test" not in m and "demo_user@users.aaw.test" not in p  # identity claims never disclosed
    auditor = client.get(f"/v1/executions/{cid}/evidence", params={"role": "auditor"}, headers=USER_HEADERS).json()
    assert {"merchant_presentation", "payment_presentation", "consent_snapshot", "grant_artifacts"} <= set(auditor["artifacts"])
    assert any(e["action"] == "GRANT_APPROVED" for e in auditor["audit_events"])
    # receipts reference the presented closed mandate
    assert payment["receipts"]["payment"]["decoded"]["payload"]["status"] == "Success"
    assert payment["receipts"]["payment"]["reference"] == res["response"]["diagnostic"]["final_artifact_hashes"]["payment"]


@pytest.mark.parametrize("profile", PROFILES)
def test_expiry_boundary_uses_injected_clock(api: Api, client, clock, profile):
    from datetime import timedelta

    exp = clock.now() + timedelta(seconds=600)
    gid = api.grant(profile, expires_at=exp.isoformat())
    clock.advance(598)
    ok = api.buy(gid)
    assert api.decision(ok) == "ALLOW", api.reasons(ok)
    gid2 = api.grant(profile, expires_at=(clock.now() + timedelta(seconds=10)).isoformat())
    clock.advance(10)
    late = api.buy(gid2)
    assert "EXPIRED_AUTHORIZATION" in api.reasons(late) and api.decision(late) == "REQUIRE_NEW_AUTHORIZATION"
    # worker marks it expired
    rep = client.post("/v1/demo/worker/run-once").json()
    assert gid2 in rep["expired"]


def test_user_cannot_approve_another_users_proposal(api: Api, client, ctx):
    from aaw_domain.models import User

    with ctx.rt.session() as s:
        s.add(User(id="other_user", display_name="Other", api_token="user-token-other", created_at=0))
    p = api.propose("ap2")
    other = {"Authorization": "Bearer user-token-other"}
    assert api.challenge(p["id"], headers=other).status_code == 403
    ch = api.challenge(p["id"]).json()
    assert api.approve(p["id"], ch, headers=other).status_code == 403
    # and the challenge cannot be used with a wrong digest; the challenge is then invalidated
    bad = api.approve(p["id"], ch, digest="0" * 64)
    assert bad.status_code == 409
    again = api.approve(p["id"], ch)
    assert again.status_code == 409


def test_proposal_change_invalidates_challenge_and_shows_updated_terms(api: Api, client):
    p = api.propose("ap2")
    ch = api.challenge(p["id"]).json()
    changed = client.patch(f"/v1/authorization-proposals/{p['id']}", json={"max_total_minor": "20000"}, headers=AGENT_HEADERS)
    assert changed.status_code == 200 and changed.json()["consent_snapshot_digest"] != ch["snapshot_digest"]
    r = api.approve(p["id"], ch)
    assert r.status_code == 409
    assert r.json()["detail"]["proposal"]["consent_snapshot"]["maximum_delivered_total"]["minor"] == "20000"
    # a fresh challenge over the new snapshot approves
    ch2 = api.challenge(p["id"]).json()
    assert ch2["review"]["maximum_delivered_total"]["display"] == "USD 200.00"
    assert api.approve(p["id"], ch2).status_code == 200


def test_consent_snapshot_contains_required_review_fields(api: Api):
    p = api.propose("vi")
    review = api.challenge(p["id"]).json()["review"]
    assert review["agent"]["id"] == "shopping_agent_1" and review["purchase_count"] == 1
    assert [m["id"] for m in review["permitted_merchants"]] == ["merchant_a", "merchant_b"]
    assert review["maximum_delivered_total"] == {"minor": "15000", "currency": "USD", "display": "USD 150.00"}
    assert review["validity"]["display_time_zone"] == "+05:30" and review["validity"]["expires_at_local"].endswith("+05:30")
    assert review["approval_type"] == "constraints"
    assert review["data_sharing"]["merchant_receives"] and review["data_sharing"]["payment_receives"]


@pytest.mark.parametrize("profile", PROFILES)
def test_cancellation_before_execution_is_deterministic(api: Api, client, profile):
    gid = api.grant(profile)
    r = client.post(f"/v1/authorizations/{gid}/cancel", headers=USER_HEADERS).json()
    assert r["outcome"] == "cancelled_before_execution"
    res = api.buy(gid)
    assert api.reasons(res) == ["AUTHORIZATION_CANCELLED"] and api.decision(res) == "DENY"
    # cancelling a consumed grant is not possible
    gid2 = api.grant(profile)
    api.buy(gid2)
    r2 = client.post(f"/v1/authorizations/{gid2}/cancel", headers=USER_HEADERS).json()
    assert r2["outcome"] == "not_cancellable"


@pytest.mark.parametrize("profile", PROFILES)
def test_tap_failures_are_rejected_before_any_mandate_processing(api: Api, profile):
    gid = api.grant(profile)
    for opts, reason in (({"wrong_key": True}, "REQUEST_SIGNATURE_INVALID"), ({"tag": "agent-browser-auth"}, "OPERATION_CONTEXT_MISMATCH"),
                         ({"tamper_body": True}, "CONTENT_DIGEST_MISMATCH"), ({"age_seconds": 1000}, "REQUEST_EXPIRED"),
                         ({"no_content_digest": True}, "REQUEST_COVERAGE_INSUFFICIENT"), ({"key_id": "unknown-key"}, "UNKNOWN_AGENT_KEY")):
        res = api.buy(gid, tap=opts)
        assert res["status_code"] == 401, (opts, res["response"])
        assert api.reasons(res) == [reason]
        assert "merchant_verification" not in res["response"]["diagnostic"]["details"]
    # recognised agent with invalid purchase authority: TAP ok, mandate rejected before execution
    res = api.buy(gid, tamper={"wrong_agent_key": True})
    assert res["response"]["diagnostic"]["request_authentication"] == "valid"
    assert res["response"]["claim"] is None if "claim" in res["response"] else True
    assert api.claim_state(api.buy(gid)) == "consumed"


@pytest.mark.parametrize("profile", PROFILES)
def test_sku_constraints_are_enforced(api: Api, profile):
    gid = api.grant(profile, merchant_ids=["merchant_a"],
                    line_items=[{"id": "li1", "acceptable_items": [{"id": "SKU-HEADPHONES", "title": "Wired headphones"}], "quantity": 1}])
    bad = api.buy(gid, "merchant_a", "SKU-CABLE")
    assert bad["status_code"] == 403 and "SKU_NOT_ALLOWED" in api.reasons(bad)
    good = api.buy(gid, "merchant_a", "SKU-HEADPHONES")
    assert api.decision(good) == "ALLOW"


def test_dry_run_verification_endpoint(api: Api, client):
    gid = api.grant("ap2")
    res = api.buy(gid, tamper={"payment_amount_minor": 100})  # denied, grant still active
    body = json.loads(res["request"]["body"])
    body["checkout_jwt"] = res["checkout"]["checkout_jwt"]
    v = client.post("/v1/verifications", json=body, headers=USER_HEADERS).json()
    assert v["dry_run"] and "PAYMENT_BINDING_MISMATCH" in v["diagnostic"]["reason_codes"]


def test_registry_and_issuer_endpoints_require_admin(client):
    assert client.get("/registry/agents").status_code == 200
    key_id = client.get("/registry/agents").json()[0]["tap_keys"][0]["key_id"]
    assert client.get(f"/registry/keys/{key_id}").json()["is_active"] == "true"
    assert client.post(f"/registry/keys/{key_id}/status", json={"status": "revoked"}).status_code == 401
    assert client.post("/issuer/credentials", json={"profile": "ap2", "user_id": "x", "user_public_jwk": {}}).status_code == 401
    assert client.get("/issuer/jwks").json()["keys"][0]["kty"] == "EC"
