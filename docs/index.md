# Agent Authorization Wallet + Merchant Trust Gateway

A wallet and merchant gateway for one bounded, explicitly approved agent purchase. It separates request identity, purchase authority, transaction binding, and execution state.

[Get Started](getting-started.md) · [API Reference](api-reference.md) · [Repository README](../README.md)

## Key Features

- Direct and autonomous consent with deterministic review snapshots.
- Independent merchant and payment verification with AP2 or VI profiles and TAP request authentication.
- Atomic grant claims, replay protection, reconciliation, and role-specific evidence.

## Tech Stack and Scope

Python / FastAPI / SQLAlchemy; SQLite or PostgreSQL; Next.js 14 / React. Signing uses local test participants and payment processing is simulated.

## Documentation

- [Getting Started](getting-started.md)
- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [Configuration](configuration.md)
- [Database and Evidence](database.md)
- [Testing](testing.md)
- [Deployment](deployment.md)
- [Trust Model](trust-model/README.md)
- [Protocol Revisions](protocol-versions/README.md)
- [AP2 Profile](protocol-versions/ap2.md)
- [VI Profile](protocol-versions/vi.md)
- [TAP Profile](protocol-versions/tap.md)
- [Demo Guide](demo/README.md)

## Project Structure

- `apps/`: API, gateway, issuer, registry, and web UI.
- `packages/`: authorization domain, profiles, signing, verification, and execution.
- `fixtures/`, `migrations/`, `tests/`: provenance, schema material, and regression checks.

The implementation guides describe the current code. [Development plan](../plan.md) records design intent and future work; planned features are not automatically implemented.

## Related projects

These are independent companion repositories, not runtime dependencies or claims of an implemented integration:

- [Cross-Border Payments Engine](https://github.com/vaibhavkapur/Cross-Border-Payments-Engine): remittance quoting, settlement lifecycle, and ledger demonstration.
- [Stablecoin Payments API](https://github.com/vaibhavkapur/Stablecoin-Payments-API): customer, wallet, deposit, transfer, and checkout API.
- [Agentic Commerce + Stablecoin Checkout](https://github.com/vaibhavkapur/Agentic-Commerce-Stablecoin-Checkout): conversational commerce, policy checks, and payment routing.
- [Smart Wallet Policy Engine](https://github.com/vaibhavkapur/smart-wallet-policy-engine): transaction risk evaluation and wallet authorization.
- [Stablecoin Payment Orchestrator](https://github.com/vaibhavkapur/Stablecoin-Payment-Orchestrator): USDC routing, workers, and treasury accounting.
