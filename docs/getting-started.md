# Getting Started

[Documentation home](index.md)

## Prerequisites

Use Python 3.12 (the container runtime), `pip`, and Git. The optional Next.js 14 UI needs Node.js 20+ and npm. Docker Compose is an alternative to installing the services locally.

## Clone and install

```bash
git clone https://github.com/vaibhavkapur/Agent-Authorization-Wallet-Merchant-Trust-Gateway.git
cd Agent-Authorization-Wallet-Merchant-Trust-Gateway
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=packages/signer-interface:packages/authorization-domain:packages/ap2-profile:packages/vi-profile:packages/vi-profile/vendor:packages/tap-verifier:packages/execution-coordinator:apps/api:apps/merchant-gateway:apps/test-issuer:apps/test-registry
uvicorn aaw_api.main:app --reload --port 8000
```

This starts the wallet with embedded gateway, issuer, and registry. Tables and synthetic participants are initialized automatically in `aaw.db`; participant keys are created under `.keys/`. No external payment account is needed.

In a second terminal, from the repository root:

```bash
cd apps/web
npm ci
npm run dev
```

Open [the UI](http://localhost:3000), [interactive API reference](http://localhost:8000/docs), or check `curl http://localhost:8000/healthz`.

## First authorized purchase

Use the UI to propose one autonomous purchase with AP2, a USD 150 cap, merchant A or B, and an expiry within the next hour. Review the consent snapshot as the demo user and approve it. Then choose the USD 120 headphones in the simulated agent view. The expected result is `ALLOW`, a consumed grant, and separate checkout and payment receipts.

For an API walkthrough, see [API Reference](api-reference.md). A proposal alone does not authorize a purchase: the user must obtain and approve a challenge, and the purchase must use the returned grant ID. User and agent credentials are deliberately separate.

## Alternative: separate services

```bash
docker compose up --build
```

Compose runs PostgreSQL, the API, gateway, issuer, registry, reconciliation worker, and web UI. See [Deployment](deployment.md) for ports and persistence.

## Verify and explore

```bash
source .venv/bin/activate
python -m pytest -q
```

[Demo Guide](demo/README.md) covers over-budget purchases, tampering, replay, evidence views, and recovery. [Configuration](configuration.md) explains the optional fixed clock. All payment processing and participant identities are local fixtures.
