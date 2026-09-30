# API Reference

[Documentation home](index.md)

## Base URL and authentication

The local base URL is `http://localhost:8000`. FastAPI serves the complete request schemas at `/docs` and `/openapi.json`. Application routes live in `apps/api/aaw_api/routers.py`.

- User: `Authorization: Bearer user-token-demo`.
- Agent: `X-Agent-Token: agent-token-demo`.
- Internal gateway execution: `X-Gateway-Token`, matched against `AAW_ADMIN_TOKEN`.
- Key rotation: `X-Admin-Token`, also matched against `AAW_ADMIN_TOKEN`.

These are seeded development credentials. Ownership checks still apply. `GET /v1/participants` exposes fixture tokens when `AAW_EXPOSE_DEMO_TOKENS=1`.

## Consent and grant flow

1. Agent calls `POST /v1/authorization-proposals`. For autonomous mode supply `user_id`, `agent_id`, `profile` (`ap2` or `vi`), `mode: autonomous`, `currency`, `max_total_minor` as a digit string, `merchant_ids`, and a future timezone-aware `expires_at`. Purchase count is one. Direct mode instead requires `checkout_reference` and `merchant_id`.
2. Read `GET /v1/authorization-proposals/{proposal_id}` and review `consent_snapshot`.
3. User calls `POST /v1/authorization-proposals/{proposal_id}/consent-challenge`. Retain `challenge_id`, `nonce`, and `snapshot_digest` from the response.
4. After reviewing the snapshot, user calls `POST /v1/authorization-proposals/{proposal_id}/approve` with those three fields. The response is the grant; use its `id` for the purchase.

Example challenge request (replace `PROPOSAL_ID`):

```bash
curl -X POST http://localhost:8000/v1/authorization-proposals/PROPOSAL_ID/consent-challenge \
  -H "Authorization: Bearer user-token-demo"
```

Approval body shape; all values must come from that challenge:

```json
{
  "challenge_id": "CHALLENGE_ID",
  "nonce": "CHALLENGE_NONCE",
  "snapshot_digest": "REVIEWED_SNAPSHOT_DIGEST"
}
```

A changed proposal invalidates the reviewed digest. Challenges expire after 300 seconds. The agent token cannot approve user consent.

## Purchase and evidence

```bash
curl -X POST http://localhost:8000/v1/agent/purchase \
  -H "X-Agent-Token: agent-token-demo" \
  -H "Content-Type: application/json" \
  -d '{"grant_id":"GRANT_ID","merchant_id":"merchant_a","items":[{"id":"SKU-HEADPHONES","quantity":1}]}'
```

Replace `GRANT_ID` with the approved grant. The simulated agent prepares the protocol presentations and signs the gateway request.

- `GET /v1/authorizations` and `GET /v1/authorizations/{grant_id}`: grants visible to the authenticated participant.
- `POST /v1/authorizations/{grant_id}/cancel`: user cancellation.
- `POST /v1/authorization-proposals/{proposal_id}/reject`: user rejection before grant creation.
- `PATCH /v1/authorization-proposals/{proposal_id}`: agent updates the cap or expiry before approval.
- `POST /v1/verifications`: diagnostic verification without execution.
- `POST /v1/executions`: internal gateway execution; not a substitute for consent.
- `GET /v1/executions/{claim_id}` and `/v1/executions/{claim_id}/evidence?role=user`: execution and filtered evidence. Other views include merchant, payment, and auditor.
- `GET /v1/metrics`: verification outcomes, replay records, grant expiry, and unresolved executions.

## Outcomes and retries

Diagnostics use `ALLOW`, `REQUIRE_NEW_AUTHORIZATION`, `DENY`, and `RECONCILIATION_REQUIRED`. A valid TAP signature does not establish purchase authority. Business decisions and HTTP success are separate; inspect the diagnostic and execution state.

The coordinator keys execution by grant and checkout, while TAP rejects replayed signed requests. Retrying after uncertainty means reconciling the original execution; generating a new purchase is not a recovery strategy. See [Demo Guide](demo/README.md) for the worker and fault controls.
