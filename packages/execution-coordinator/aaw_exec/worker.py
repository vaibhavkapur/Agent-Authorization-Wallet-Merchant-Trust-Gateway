"""Durable background worker: expiry, stale-claim recovery, reconciliation.

Run with ``python -m aaw_exec.worker`` (compose ``worker`` service) or call
:func:`run_once` from tests with an injected clock.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List

from sqlalchemy import select

from aaw_domain.artifacts import audit
from aaw_domain.clock import Clock, SystemClock
from aaw_domain.db import Database
from aaw_domain.models import AuthorizationGrant, ExecutionClaim

from .coordinator import STALE_CLAIM_SECONDS, Coordinator


def run_once(db: Database, coordinator: Coordinator, clock: Clock = None) -> Dict[str, List[str]]:
    clock = clock or coordinator.clock
    now = clock.now_ts()
    report: Dict[str, List[str]] = {"expired": [], "reconciled": [], "still_unknown": []}
    with db.session() as s:
        for g in s.execute(
            select(AuthorizationGrant).where(AuthorizationGrant.status == "active", AuthorizationGrant.expires_at <= now)
        ).scalars():
            g.status = "expired"
            g.version += 1
            g.updated_at = now
            audit(s, actor="worker", action="GRANT_EXPIRED", target_type="grant", target_id=g.id, clock=clock)
            report["expired"].append(g.id)
    with db.session() as s:
        # Claims whose processor response was lost can be reconciled immediately from the
        # processor ledger; claims still "claimed"/"executing" are only touched once stale
        # (the owning request may still be in flight).
        candidates = list(
            s.execute(
                select(ExecutionClaim).where(
                    (ExecutionClaim.state == "execution_unknown")
                    | (
                        ExecutionClaim.state.in_(["claimed", "executing"])
                        & (ExecutionClaim.claimed_at <= now - STALE_CLAIM_SECONDS)
                    )
                )
            ).scalars()
        )
        for c in candidates:
            coordinator.reconcile(s, c)
            (report["reconciled"] if c.state in ("consumed", "resolved_not_executed") else report["still_unknown"]).append(c.id)
    return report


def main() -> None:  # pragma: no cover - process entrypoint
    from aaw_signer import DevKeyStore

    from .coordinator import ReceiptSigner, ReceiptSigners

    db = Database()
    db.create_all()
    ks = DevKeyStore.from_env()
    coord = Coordinator(ReceiptSigners(
        checkout=ReceiptSigner(ks.get("merchant_gateway"), os.environ.get("AAW_GATEWAY_ID", "urn:aaw:merchant-gateway")),
        payment=ReceiptSigner(ks.get("payment_processor"), os.environ.get("AAW_PROCESSOR_ID", "urn:aaw:payment-processor")),
    ), SystemClock())
    interval = int(os.environ.get("AAW_WORKER_INTERVAL", "5"))
    while True:
        rep = run_once(db, coord)
        if any(rep.values()):
            print("worker:", rep, flush=True)
        time.sleep(interval)


if __name__ == "__main__":  # pragma: no cover
    main()
