# Agent Authorization Wallet + Merchant Trust Gateway — Development Plan

## 1. Project summary

Build an **authorization wallet that lets a user delegate a bounded purchase to an agent**, plus a merchant gateway that independently checks the resulting request.

Example user instruction:

> “Allow my shopping agent to make one purchase up to $150 from either of these two merchants before tomorrow evening.”

The system should capture the permission, bind it to the intended agent, verify the final checkout, and produce inspectable evidence of every decision.

Core capabilities:

- explicit user consent on a trusted review screen
- AP2 direct and autonomous authorization flows
- a separate Verifiable Intent implementation profile
- TAP verification at the merchant boundary
- exact checkout-to-payment binding
- deterministic constraint validation
- replay resistance and durable execution records
- role-specific disclosure and audit evidence

Planning baseline: **25 September 2026**. This is an authorization-wallet project; holding funds or implementing a smart contract wallet is optional.

---

## 2. Product goal and positioning

The product answers three questions:

1. Which agent sent this request, and is the request authentic?
2. What authority did the user delegate to that agent?
3. Does this exact purchase fit that authority?

The earlier stablecoin checkout applied application policy. This project makes authorization evidence independently verifiable by other participants.

It connects payments authentication, step-up review, delegated permissions, and transaction integrity. It should also show the limits of the proof: a signature does not establish that a merchant's product description is truthful or that goods were delivered.

---

## 3. Protocol responsibilities

### AP2 — purchase and payment authorization

Use the current v0.2 checkout/payment mandate model. Implement human-present approval first, then constrained autonomous execution. Follow the specification's checkout binding and verifier responsibilities. [AP2 specification](https://ap2-protocol.org/ap2/specification/)

### Verifiable Intent — delegation and selective disclosure

Implement its credential-provider, user, and agent credential chain with role-specific disclosures. The public repository identifies this as **draft v0.1**; pin the exact revision. [Verifiable Intent](https://github.com/agent-intent/verifiable-intent)

### TAP — merchant request verification

Use TAP's signed-request mechanism and registry-backed verification at the merchant gateway. Follow the selected profile's request coverage, time checks, and operation context. [Visa reference implementation](https://github.com/visa/trusted-agent-protocol)

Implement AP2 and VI as separate profiles with their own parsers, fixtures, and verification rules. Shared cryptographic primitives do not by themselves prove interoperability. An AP2-to-VI mapping is a later, explicitly tested integration.

---

## 4. MVP scope

### Build first

- one user and one agent
- one merchant and one simulated payment processor
- a local test credential issuer and agent registry
- one-purchase delegation with an amount cap and expiry
- immediate approval of an exact checkout
- AP2 and VI flows selectable as separate demo modes
- TAP verification on merchant requests
- real cryptographic signing and verification
- simulated payment execution with durable idempotency

### Add later

- second merchant and merchant restrictions
- key rotation and application revocation controls
- a provider sandbox or testnet execution adapter
- integration with the procurement project

### Defer

- live card-network enrollment
- production credential issuance or custody
- legal liability assignment
- recursive agent-to-agent redelegation
- custom cryptographic algorithms

Label local issuers and registry identities as test participants. Local verification is not network accreditation.

---

## 5. Recommended technology stack

- **Backend:** Python and FastAPI
- **Persistence:** PostgreSQL
- **Frontend:** Next.js and TypeScript
- **Cryptography:** maintained JOSE/SD-JWT libraries and pinned reference implementations
- **Gateway:** FastAPI middleware or a separate reverse proxy
- **Workers:** a small durable background worker
- **Testing:** pytest, protocol fixtures, integration tests
- **Environment:** Docker Compose

Prefer Python for the first verifier implementation because the VI repository provides a Python reference implementation. Keep protocol-specific logic behind adapters so the frontend and policy service remain independent.

---

## 6. High-level architecture

```text
User → Trusted review UI → User signing component
                               ↑
                       Test credential issuer
                               ↓
Shopping agent → Final checkout → Authorization profile adapter
       │                              ├─ AP2
       │                              └─ Verifiable Intent
       ↓
TAP-signed request → Merchant gateway → Deterministic verifier
                                           ↓
                                   Execution coordinator
                                           ↓
                                   Payment simulator
                                           ↓
                                Receipt and evidence store

Test agent registry → trusted keys for request verification
```

User, agent, merchant, and issuer keys are distinct. The agent cannot access the user's signing key.

---

## 7. Trust and key model

### Test credential issuer

Issue credentials only through an authenticated fixture-enrollment flow. Verifiers trust an explicit issuer allowlist, not arbitrary keys supplied inside a request.

### User signing component

For the local demo, isolate a development signer behind the authenticated consent flow. Show that this is a simulated user device. The signer accepts only the reviewed immutable request and a fresh consent challenge.

### Agent signer

Sign agent-authorized artifacts using the agent key bound by the selected profile. Keep this key separate from payment-wallet credentials.

### Merchant signer

Produce the merchant checkout artifact required by the chosen flow. Apply the profile's exact algorithm and serialization requirements.

### Gateway trust store

Resolve keys through trusted registry configuration. Enforce issuer, key type, algorithm, validity, and applicable key-status rules. A public-key identifier is a lookup hint, not a trust decision.

---

## 8. Consent user experience

The review screen must show:

- delegated agent identity
- purchase count: one
- permitted merchants
- maximum delivered total and currency
- start and expiry times with time zone
- whether the user is approving exact items or constraints
- which data is shared with merchant and payment participants

Use deterministic UI rendering from validated data. The model may explain a proposal but cannot rewrite the actual signed terms during approval.

If anything changes between review and signing, invalidate the challenge and display the updated proposal. Persist the reviewed representation and its link to the resulting protocol artifacts.

---

## 9. Direct authorization flow

1. Merchant creates a final checkout.
2. Application verifies its source and resolves all amounts.
3. User reviews exact items, merchant, total, and payment context.
4. Trusted signing component signs the selected profile's authorization artifacts.
5. Agent forwards the appropriate disclosures to each verifier.
6. Gateway validates the TAP request when that path is enabled.
7. Merchant and payment verifiers perform their separate checks.
8. Execution coordinator persists a unique execution attempt.
9. Payment simulator executes once.
10. Application records outcome and protocol receipts where required.

The demo should allow inspection of each role's view without exposing unrelated credentials.

---

## 10. Autonomous authorization flow

1. User reviews bounded purchase constraints.
2. User authorizes the specific agent key through the selected profile.
3. Agent obtains a qualifying final checkout.
4. Agent constructs the transaction-specific authorization evidence.
5. Independent verifiers check signatures, delegation, constraints, and checkout binding.
6. Coordinator atomically claims the authorization for this purchase.
7. Execution proceeds and receipts are retained.

For AP2, follow the current autonomous mandate-use and rejection-receipt rules. Do not turn one open mandate into a generic reusable spending session. Agent-to-agent delegation is outside the current AP2 specification's defined scope. [AP2 autonomous mode](https://ap2-protocol.org/ap2/specification/)

A future recurring-purchase product must define separate authorizations and application accounting rather than assuming reuse is allowed.

---

## 11. Deterministic verification pipeline

Run validation before a payment capability becomes available:

1. Identify the supported profile and version.
2. Apply input size and structure limits.
3. Validate signed-request coverage and freshness.
4. Resolve trusted issuer and agent keys.
5. Verify signatures with an algorithm allowlist.
6. Verify disclosure digests and key bindings.
7. Check expiry and applicable audience/context restrictions.
8. Verify that checkout and payment artifacts bind to the same transaction.
9. Enforce supported amount, merchant, and payee constraints.
10. Apply product/SKU checks required by the application.
11. Check local cancellation/revocation and execution-use state.
12. Persist an execution reservation atomically.

Keep cryptographic validity, protocol validity, and application-policy eligibility as separate results. A valid signature can accompany an ineligible purchase.

---

## 12. Policy outcomes and reason codes

Use these application outcomes:

- `ALLOW`: all checks passed
- `REQUIRE_NEW_AUTHORIZATION`: proposed terms exceed the grant
- `DENY`: invalid evidence or explicitly disallowed action
- `RECONCILIATION_REQUIRED`: a previous execution has an uncertain result

Example diagnostic object, not a wire-format mandate:

```json
{
  "decision": "DENY",
  "request_authentication": "valid",
  "delegation_verification": "valid",
  "constraint_verification": "failed",
  "reason_codes": ["DELIVERED_TOTAL_EXCEEDS_LIMIT"],
  "evaluated_total_minor": "15500",
  "authorized_max_minor": "15000",
  "currency": "USD"
}
```

Other reasons include `UNKNOWN_ISSUER`, `EXPIRED_AUTHORIZATION`, `AGENT_KEY_MISMATCH`, `CHECKOUT_BINDING_MISMATCH`, and `AUTHORIZATION_ALREADY_CLAIMED`.

---

## 13. Data model

### `authorization_grants`

- `id`, `user_id`, `agent_id`, `profile`, `profile_version`
- `constraints_json`, `consent_snapshot_digest`
- `status`, `expires_at`, `cancelled_at`, `version`

### `protocol_artifacts`

- `id`, `grant_id`, `artifact_type`, `issuer_id`
- `encrypted_object_reference`, `digest`, `created_at`
- `allowed_reader_roles`, `retention_until`

### `trusted_keys`

- `issuer_or_agent_id`, `key_id`, `public_key`
- `source`, `valid_from`, `valid_until`, `local_status`

### `verification_attempts`

- `id`, `grant_id`, `checkout_reference`, `trace_id`
- `profile`, `ruleset_version`, `decision`, `reason_codes`
- `verified_at`, `redacted_evidence_reference`

### `execution_claims`

- `id`, `grant_id`, `checkout_digest`, `idempotency_key`
- `payment_attempt_id`, `state`, `claimed_at`, `resolved_at`

### Other records

- `request_replay_records`: signed-request identity and expiry
- `consent_challenges`: user, snapshot, nonce, expiry, consumed time
- `payment_attempts`: execution state and external references
- `receipts`: evidence references and verified outcome
- `audit_events`: actor, action, target, time, trace

Separate confidential artifacts from ordinary operational logs. Public keys may be stored normally; private keys belong in the signer boundary.

---

## 14. API design

The following endpoints are application APIs, not official AP2, VI, or TAP endpoints:

```http
POST /v1/authorization-proposals
POST /v1/authorization-proposals/{id}/consent-challenge
POST /v1/authorization-proposals/{id}/approve
GET  /v1/authorizations/{id}
POST /v1/authorizations/{id}/cancel
POST /v1/verifications
POST /v1/executions
GET  /v1/executions/{id}
GET  /v1/executions/{id}/evidence
```

Example proposal:

```json
{
  "agent_id": "shopping_agent_1",
  "profile": "ap2",
  "mode": "autonomous",
  "purchase_count": 1,
  "currency": "USD",
  "max_total_minor": "15000",
  "merchant_ids": ["merchant_a", "merchant_b"],
  "expires_at": "2026-09-26T18:00:00+05:30"
}
```

Generate official artifacts through a profile adapter. Do not sign this generic JSON and present it as an AP2 or VI credential.

---

## 15. Execution lifecycle and replay handling

```text
proposed → awaiting_consent → active → claimed → consumed
active → cancelled | expired
claimed → execution_unknown → consumed | resolved_not_executed
```

Use a unique constraint to ensure a grant has only one active purchase claim. Repeated delivery of the same business operation returns the existing result.

Distinguish:

- a transport replay that must be rejected
- a legitimate newly signed retry of the same business operation
- a new purchase attempting to reuse consumed authority

After definitive non-execution, decide whether new authorization is required according to the pinned protocol rules. A worker must not simply reset a mandate to reusable.

---

## 16. Revocation and race conditions

Provide an application cancellation endpoint for grants that have not been committed to execution. Serialize cancellation and execution claiming on the same grant record.

Once submission has begun, cancellation may stop future actions but cannot promise reversal of an accepted payment. Display `cancellation_pending` or the actual resolved outcome.

Local revocation state is an application control. A disconnected third-party verifier cannot learn it automatically from a previously signed artifact. Document whether a verifier checks an online status service or relies on expiry.

For key rotation, keep historical public keys needed to verify old evidence while separately preventing unauthorized new use.

---

## 17. Selective disclosure and privacy

Create two evidence views:

- merchant view: the checkout information and authorization evidence needed by that role
- payment view: the payment constraints and binding information needed by that role

Use the selected profile's disclosure mechanism. Removing a field from an unsigned UI object does not demonstrate selective disclosure.

Build tests proving that a verifier rejects a required missing disclosure and that unrelated claims are absent from the other role's view. VI distinguishes machine-checkable constraints from descriptive product context; implement exact SKU checks in application policy where required. [VI scope and constraints](https://github.com/agent-intent/verifiable-intent)

---

## 18. UI and observability

Build:

1. delegation creation and review
2. active authorization list
3. transaction verification detail
4. role-specific evidence viewer
5. failure-injection controls for local demos

The verification detail should show request authentication, delegation verification, purchase constraints, execution state, and receipt verification separately.

Measure verification latency, rejection reasons, replay attempts, authorization expiry, and unresolved executions. Use synthetic identities and redacted artifacts in exported screenshots.

---

## 19. Testing strategy

### Cryptographic and protocol tests

- valid reference artifacts pass
- altered signed content fails
- unsupported algorithm and unknown issuer fail
- wrong agent key fails
- selective-disclosure digest mismatch fails
- checkout and payment mismatch fails
- profile-specific algorithm requirements are enforced

### Application tests

- exact cap passes and cap plus one minor unit fails
- expiry boundary uses an injected clock
- one grant cannot support two concurrent purchases
- cancellation versus execution has a deterministic outcome
- user cannot approve another user's proposal

### Recovery tests

- payment response lost after success
- worker crash after claim persistence
- signed retry returns the original business outcome
- old keys still verify retained historical evidence under the documented policy

Use independent fixtures or a second verifier where possible. A signer and verifier sharing the same bug can falsely appear interoperable.

---

## 20. Phased delivery plan

### Phase 1 — consent and direct AP2 path

Build the trusted review flow, test signer, final checkout artifact, direct authorization, and payment simulator.

Success: tampering with an approved checkout prevents execution.

### Phase 2 — autonomous AP2 path

Add bounded agent authority, deterministic validation, expiry, and durable single-purchase claims.

Success: an eligible transaction executes without fresh consent; an over-budget one cannot.

### Phase 3 — Verifiable Intent profile

Implement the selected VI revision, delegation chain, and two disclosure views with separate fixtures.

Success: independent verification passes and private claims remain role-scoped.

### Phase 4 — TAP gateway and recovery

Add signed-request validation, test registry, replay cases, and uncertain-payment reconciliation.

Success: recognized agents with invalid purchase authority are rejected before execution.

---

## 21. Suggested roadmap and repository

Planning estimate: **four to five focused weeks**, with cryptographic interoperability taking priority over UI polish.

- Week 1: trust model, consent flow, immutable snapshots, direct path.
- Week 2: autonomous flow, atomic claims, negative cases.
- Week 3: VI profile, disclosures, independent fixture checks.
- Week 4: TAP gateway, replay protection, recovery.
- Week 5 if needed: second verifier, demo polish, integration notes.

```text
agent-authorization-wallet/
  apps/{web,api,merchant-gateway,test-registry,test-issuer}/
  packages/
    authorization-domain/
    ap2-profile/
    vi-profile/
    tap-verifier/
    signer-interface/
    execution-coordinator/
  fixtures/{ap2,vi,tap}/
  tests/{crypto,protocol,concurrency,recovery}/
  migrations/
  docs/{trust-model,protocol-versions,demo}/
  docker-compose.yml
```

---

## 22. Demo scenarios

### Demo A — valid autonomous purchase

User permits one purchase up to $150. A $120 checkout succeeds and the grant becomes consumed.

### Demo B — authentic request, invalid purchase

TAP verification succeeds, but the checkout is $155. The constraint verifier rejects it.

### Demo C — checkout tampering

Replace the recipient or checkout artifact after authorization. Binding verification fails.

### Demo D — replay and concurrency

Submit the same purchase twice, then attempt a different purchase with the same grant. Show one execution and distinct diagnostic results.

### Demo E — private evidence views

Open merchant and payment views side by side and explain why each receives different disclosures.

---

## 23. Definition of done and portfolio framing

Ship real signatures, schema-checked artifacts, two independently tested authorization profiles, a TAP gateway, and reproducible failure cases.

Include a trust diagram, verification responsibilities, immutable specification references, setup instructions, fixture provenance, and a clear distinction between simulated participants and implemented protocol behavior.

Portfolio wording after completion:

> Built an agent authorization wallet and merchant gateway with AP2 and Verifiable Intent profiles, TAP request verification, scoped user delegation, selective disclosure, and deterministic enforcement of purchase constraints.

Avoid claims of production network certification or guaranteed dispute outcomes.

---

## 24. Primary references and immediate next steps

- [AP2 v0.2 specification](https://ap2-protocol.org/ap2/specification/)
- [Verifiable Intent draft and reference implementation](https://github.com/agent-intent/verifiable-intent)
- [Visa TAP sample implementation](https://github.com/visa/trusted-agent-protocol)

Record exact revisions, algorithms, SDK versions, and supported profiles before implementation. Preserve normative signature inputs and key-binding rules rather than inventing a shared credential format.

Start with one final checkout, one explicit consent action, one real signed authorization, and one verifier that rejects a changed amount. Build the delegation and request-authentication layers on top.

**One-sentence summary:** A wallet and merchant gateway that prove which agent was authorized to make which purchase, then enforce that authority before execution.
