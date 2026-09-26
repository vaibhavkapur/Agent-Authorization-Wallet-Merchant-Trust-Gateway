# Agent Authorization Wallet + Merchant Trust Gateway

An authorization wallet that lets a user delegate one bounded purchase to an agent, plus a merchant gateway that independently verifies request identity, purchase authority, and transaction integrity.

> **[Read the full documentation](docs/demo/README.md)**

## Getting Started

```bash
# Install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start the API (gateway, issuer, and registry embedded; SQLite)
export PYTHONPATH=packages/signer-interface:packages/authorization-domain:packages/ap2-profile:packages/vi-profile:packages/vi-profile/vendor:packages/tap-verifier:packages/execution-coordinator:apps/api:apps/merchant-gateway:apps/test-issuer:apps/test-registry
uvicorn aaw_api.main:app --reload --port 8000

# Start the UI (separate terminal)
cd apps/web && npm install && npm run dev
```

Or `docker compose up --build` for PostgreSQL and separate services. Open http://localhost:3000.

## Quick Example

```bash
# Propose an autonomous purchase: one buy, $150 cap, merchants A or B
curl -X POST http://localhost:8000/v1/authorization-proposals \
  -H "X-Agent-Token: agent-token-demo" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo_user",
    "agent_id": "shopping_agent_1",
    "profile": "ap2",
    "mode": "autonomous",
    "currency": "USD",
    "max_total_minor": "15000",
    "merchant_ids": ["merchant_a", "merchant_b"],
    "expires_at": "2036-09-26T18:00:00+05:30"
  }'

# After the user approves the consent challenge, the agent buys $120 headphones
curl -X POST http://localhost:8000/v1/agent/purchase \
  -H "X-Agent-Token: agent-token-demo" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_id": "authz_...",
    "merchant_id": "merchant_a",
    "items": [{ "id": "SKU-HEADPHONES", "quantity": 1 }]
  }'
```
