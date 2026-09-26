"""Recovery tests (plan §19): lost payment response, worker crash after claim
persistence, signed retry returns the original outcome, historical keys."""

from __future__ import annotations

import pytest

from aaw_domain import PARTICIPANT_MERCHANT, TrustError
from aaw_domain.checkout import parse_checkout_jwt
from aaw_exec import STALE_CLAIM_SECONDS
from tests.conftest import ADMIN_TOKEN, USER_HEADERS, Api

PROFILES = ["ap2", "vi"]


@pytest.mark.parametrize("profile", PROFILES)
def test_payment_response_lost_after_success_is_reconciled(api: Api, client, profile):
    gid = api.grant(profile)
    res = api.buy(gid, fault="lose_response")
    assert res["status_code"] == 202 and api.decision(res) == "RECONCILIATION_REQUIRED"
    assert api.claim_state(res) == "execution_unknown" and "EXECUTION_UNCERTAIN" in api.reasons(res)
    cid = res["response"]["claim"]["id"]
    assert client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()["status"] == "execution_unknown"
    # a second attempt with the same grant cannot start another purchase
    again = api.buy(gid, "merchant_b", "SKU-MOUSE")
    assert api.decision(again) == "RECONCILIATION_REQUIRED" and "EXECUTION_UNCERTAIN" in api.reasons(again)
    # cancellation can only be pending now
    assert client.post(f"/v1/authorizations/{gid}/cancel", headers=USER_HEADERS).json()["outcome"] == "cancellation_pending"
    # the worker asks the processor ledger and settles
    rep = client.post("/v1/demo/worker/run-once").json()
    assert cid in rep["reconciled"]
    ex = client.get(f"/v1/executions/{cid}", headers=USER_HEADERS).json()
    assert ex["claim"]["state"] == "consumed" and set(ex["receipts"]) == {"checkout", "payment"}
    assert ex["claim"]["payment_attempt"]["state"] == "succeeded"
    assert client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()["status"] == "consumed"


@pytest.mark.parametrize("profile", PROFILES)
def test_worker_crash_after_claim_persistence(api: Api, client, clock, profile):
    gid = api.grant(profile)
    res = api.buy(gid, fault="crash_before_submit")
    assert res["status_code"] == 202 and api.claim_state(res) == "claimed"
    cid = res["response"]["claim"]["id"]
    # too early: the owning request might still be running
    assert cid not in client.post("/v1/demo/worker/run-once").json()["reconciled"]
    clock.advance(STALE_CLAIM_SECONDS + 1)
    rep = client.post("/v1/demo/worker/run-once").json()
    assert cid in rep["reconciled"]
    ex = client.get(f"/v1/executions/{cid}", headers=USER_HEADERS).json()
    assert ex["claim"]["state"] == "resolved_not_executed"
    assert ex["receipts"]["checkout"] and ex["receipts"]["payment"]
    grant = client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()
    if profile == "ap2":
        # AP2: rejection receipt issued → the agent may present the open mandate again
        assert grant["status"] == "active"
        retry = api.buy(gid)
        assert api.decision(retry) == "ALLOW" and api.claim_state(retry) == "consumed"
    else:
        # VI: one L3 pair per mandate pair → new authorization required
        assert grant["status"] == "requires_new_authorization"
        retry = api.buy(gid)
        assert api.decision(retry) == "REQUIRE_NEW_AUTHORIZATION" and "AUTHORIZATION_REQUIRES_RENEWAL" in api.reasons(retry)


@pytest.mark.parametrize("profile", PROFILES)
def test_signed_retry_returns_original_outcome(api: Api, client, profile):
    gid = api.grant(profile)
    first = api.buy(gid)
    retry = api.buy(gid, checkout_reference=first["request"]["checkout_id"])
    assert retry["request"]["nonce"] != first["request"]["nonce"]  # freshly signed
    assert retry["response"]["idempotent_replay"] is True
    assert retry["response"]["claim"]["id"] == first["response"]["claim"]["id"]
    assert retry["response"]["receipts"] == first["response"]["receipts"]
    # declined payment: definitive non-execution, outcome is stable on retry too
    gid2 = api.grant(profile)
    declined = api.buy(gid2, fault="decline")
    assert api.claim_state(declined) == "resolved_not_executed"
    assert declined["response"]["diagnostic"]["execution_outcome"] == "not_executed"
    same = api.buy(gid2, checkout_reference=declined["request"]["checkout_id"])
    assert same["response"]["idempotent_replay"] is True and same["response"]["claim"]["state"] == "resolved_not_executed"


def test_old_keys_still_verify_retained_evidence_under_documented_policy(api: Api, client, ctx):
    gid = api.grant("ap2")
    res = api.buy(gid)
    cid = res["response"]["claim"]["id"]
    checkout_jwt = res["checkout"]["checkout_jwt"]
    # rotate the merchant key: the previous key is retired
    r = client.post("/v1/demo/keys/merchant_a/rotate", headers={"X-Admin-Token": ADMIN_TOKEN})
    assert r.status_code == 200
    old_kid, new_kid = r.json()["previous_kid"], r.json()["new_kid"]
    with ctx.rt.session() as s:
        trust = ctx.rt.trust(s)
        now = ctx.rt.now()
        # historical evidence: verifying with allow_retired succeeds
        assert parse_checkout_jwt(checkout_jwt, trust, now, allow_retired=True).checkout_hash == res["checkout"]["checkout_hash"]
        # new use: the retired key may not authorize anything
        with pytest.raises(Exception):
            parse_checkout_jwt(checkout_jwt, trust, now, allow_retired=False)
        with pytest.raises(TrustError):
            trust.resolve(PARTICIPANT_MERCHANT, "merchant_a", old_kid, "ES256", at=now)
        assert trust.resolve(PARTICIPANT_MERCHANT, "merchant_a", new_kid, "ES256", at=now).key_id == new_kid
    # new checkouts are signed with the new key and purchases keep working
    gid2 = api.grant("ap2")
    assert api.decision(api.buy(gid2)) == "ALLOW"
    # the retained execution record is still readable
    assert client.get(f"/v1/executions/{cid}", headers=USER_HEADERS).json()["claim"]["state"] == "consumed"


def test_revoked_tap_key_blocks_recognised_agent(api: Api, client):
    gid = api.grant("ap2")
    key_id = client.get("/registry/agents").json()[0]["tap_keys"][0]["key_id"]
    assert client.post(f"/registry/keys/{key_id}/status", json={"status": "revoked"},
                       headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}).status_code == 200
    res = api.buy(gid)
    assert res["status_code"] == 401 and api.reasons(res) == ["AGENT_KEY_INACTIVE"]
    client.post(f"/registry/keys/{key_id}/status", json={"status": "active"}, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    assert api.decision(api.buy(gid)) == "ALLOW"
