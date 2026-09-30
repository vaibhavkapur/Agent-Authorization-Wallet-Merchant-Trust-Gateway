# Architecture

[Documentation home](index.md)

## Overview

The wallet captures a user's bounded consent; the merchant gateway verifies the resulting purchase independently. The coordinator then checks payment authority and atomically claims the grant before invoking a simulated processor.

```text
User review UI → Wallet API → Consent snapshot + signed authorization
                                   ↓
Simulated shopping agent → TAP-signed request → Merchant gateway
                                                  ↓
                           Payment verification + execution coordinator
                                                  ↓
                              Processor simulator → receipts + evidence
                                                  ↑
                                Reconciliation worker / shared database
```

## Components and technology

- `apps/api`: FastAPI application, consent service, simulated agent, payment verification, execution API.
- `apps/merchant-gateway`: request authentication and merchant-side authorization verification.
- `apps/test-issuer` and `apps/test-registry`: synthetic credential issuer and TAP trust registry.
- `apps/web`: Next.js 14 / React UI for delegation, diagnostics, and evidence.
- `packages/authorization-domain`: SQLAlchemy records, constraints, trust state, and verification pipeline.
- `packages/ap2-profile`, `packages/vi-profile`, `packages/tap-verifier`: separate protocol implementations and pinned inputs.
- `packages/signer-interface`: participant signing boundary; `packages/execution-coordinator`: atomic claims, processor simulation, receipts, and worker.

## Purchase lifecycle

1. An authenticated agent proposes constraints or a specific direct-mode checkout.
2. The user reviews a deterministic snapshot and approves its challenge nonce and digest.
3. The wallet creates the grant and role-specific authorization artifacts.
4. The gateway verifies TAP identity and merchant authority against its own signed checkout.
5. The payment verifier checks the payment presentation, checkout binding, constraints, and grant state.
6. The coordinator claims the grant atomically and records the processor outcome. An unknown outcome retains recovery state; it does not authorize a second purchase.

Request authentication, delegation, constraint checks, binding, and execution state are distinct diagnostics. AP2 and VI have different retry rules; see the [protocol notes](protocol-versions/README.md).

## Process and trust boundaries

The local default embeds services through ASGI transports. Compose splits them into HTTP processes but shares a development database and key volume. Logical signer boundaries in this demo are not hardware isolation or independent production custody.

See [Trust Model](trust-model/README.md) for keys, revocation, and evidence limits; [Database](database.md) for persisted state; and [Deployment](deployment.md) for the supported local topology.
