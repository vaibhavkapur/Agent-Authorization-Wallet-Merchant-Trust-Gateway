"""One grant cannot support two concurrent purchases; cancellation vs execution is
deterministic. Uses a file-backed SQLite database so the threads contend on real
writes (the in-memory StaticPool would share one connection)."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from aaw_api.app import create_app
from aaw_api.settings import Settings
from aaw_domain.clock import FixedClock
from tests.conftest import USER_HEADERS, Api


@pytest.fixture
def file_api(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path}/aaw.db", keys_dir="memory"),
                     clock=FixedClock(datetime.now(timezone.utc)))
    return Api(TestClient(app)), TestClient(app)


@pytest.mark.parametrize("profile", ["ap2", "vi"])
def test_one_grant_cannot_support_two_concurrent_purchases(file_api, profile):
    api, client = file_api
    gid = api.grant(profile)
    results = [None] * 6
    barrier = threading.Barrier(6)

    def worker(i, merchant, sku):
        barrier.wait()
        results[i] = api.buy(gid, merchant, sku)

    threads = [threading.Thread(target=worker, args=(i, "merchant_a" if i % 2 == 0 else "merchant_b",
                                                     "SKU-HEADPHONES" if i % 2 == 0 else "SKU-MOUSE")) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    decisions = [api.decision(r) for r in results]
    consumed = [r for r in results if api.claim_state(r) == "consumed"]
    assert len(consumed) == 1, decisions
    others = [r for r in results if r is not consumed[0]]
    for r in others:
        assert api.claim_state(r) in (None,) or r["response"].get("idempotent_replay")
        assert set(api.reasons(r)) <= {"AUTHORIZATION_ALREADY_CLAIMED", "AUTHORIZATION_CONSUMED"} or r["response"].get("idempotent_replay"), r["response"]
    execs = client.get("/v1/executions", headers=USER_HEADERS).json()
    assert len([e for e in execs if e["grant_id"] == gid]) == 1
    assert client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()["status"] == "consumed"


@pytest.mark.parametrize("profile", ["ap2", "vi"])
def test_cancellation_versus_execution_has_one_winner(file_api, profile):
    api, client = file_api
    outcomes = []
    for _ in range(4):
        gid = api.grant(profile)
        res = {}
        barrier = threading.Barrier(2)

        def cancel():
            barrier.wait()
            res["cancel"] = client.post(f"/v1/authorizations/{gid}/cancel", headers=USER_HEADERS).json()

        def buy():
            barrier.wait()
            res["buy"] = api.buy(gid)

        t1, t2 = threading.Thread(target=cancel), threading.Thread(target=buy)
        t1.start(); t2.start(); t1.join(); t2.join()
        final = client.get(f"/v1/authorizations/{gid}", headers=USER_HEADERS).json()["status"]
        bought = api.claim_state(res["buy"]) == "consumed"
        cancelled = res["cancel"]["outcome"] == "cancelled_before_execution"
        assert bought != cancelled, (res["cancel"], res["buy"]["response"].get("diagnostic"))
        if bought:
            assert final == "consumed" and res["cancel"]["outcome"] in ("not_cancellable", "cancellation_pending")
        else:
            assert final == "cancelled" and api.reasons(res["buy"]) == ["AUTHORIZATION_CANCELLED"]
        outcomes.append("bought" if bought else "cancelled")
    assert outcomes  # both orders are legitimate; only the exclusivity matters
