# Trust model

## Participants and keys

Every participant has a distinct key. Private keys exist only inside the signer boundary
(`packages/signer-interface`) of the process that plays that role; verifiers hold public keys in the
`trusted_keys` allowlist.

```
                 ┌──────────────────────────┐
                 │ Test credential issuer   │  ES256  test_issuer-key-N
                 │ (apps/test-issuer)       │  issues L1 / user credential with cnf = user device key
                 └────────────┬─────────────┘
                              │ credential
        consent challenge     ▼
User ──review──▶ Trusted review UI ──▶ User signing component   ES256  user_device-key-N
                 (apps/web)           (apps/api, behind the consent flow; signs only the reviewed
                                       snapshot: AP2 KB-SD-JWT(+KB) / VI L2)
                                              │ open (or closed) mandates, cnf = agent mandate key
                                              ▼
                                     Shopping agent (simulated, apps/api agent_sim)
                                       ES256  agent_shopping_es256-key-N   → closed mandates (AP2 link 2 / VI L3)
                                       Ed25519 agent_shopping_ed25519-key-N → TAP request signature
                                              │
              merchant checkout JWT           │ TAP-signed HTTP request carrying two role presentations
   Merchant A/B  ES256 merchant_a/b-key-N ───▶│
                                              ▼
                                     Merchant gateway (apps/merchant-gateway)
                                       1. TAP verification (registry trust store, nonce record)
                                       2. merchant-side mandate verification against *its* checkout
                                       3. checkout receipt (ES256 merchant_gateway-key-N)
                                              │
                                              ▼
                                     Coordinator + payment verifier (apps/api)
                                       independent re-verification of both views, application policy,
                                       atomic claim, payment simulator, payment receipt
                                       (ES256 payment_processor-key-N)

   Test agent registry (apps/test-registry) ──▶ trusted_keys(agent_tap) used by the gateway
```

The agent never receives a `UserSigningComponent`; it receives only the encrypted `grant_artifacts`
blob (open mandates + disclosure index) readable by the `agent` role.

## Trust decisions

| Question | Decided by | Evidence |
| --- | --- | --- |
| Which agent sent this request? | Gateway TAP verifier | registry key for `keyId`, signature over `@authority`/`@path`/`content-digest`, nonce record |
| What authority did the user delegate? | Profile verifier (AP2 chain / VI chain) | issuer allowlist → user `cnf` → agent `cnf`; open mandate constraints; consent nonce |
| Does this exact purchase fit? | Profile constraints + application pipeline | `checkout_hash == sha-256(checkout_jwt) == transaction_id`, amount/merchant/payee/SKU checks, grant state |
| Was it executed exactly once? | Coordinator | CAS on the grant row, idempotency key per (grant, checkout), processor ledger |

Cryptographic validity, protocol validity and application eligibility are reported separately in the
diagnostic (`delegation_verification`, `constraint_verification`, `binding_verification`,
`execution_state`). A valid signature can accompany an ineligible purchase (Demo B).

## Key status and rotation

`trusted_keys.local_status` is `active`, `retired` or `revoked`. New authorizations require `active`;
verifying retained evidence passes `allow_retired=True` (see
`tests/recovery/test_recovery.py::test_old_keys_still_verify_retained_evidence_under_documented_policy`).
`POST /v1/demo/keys/{name}/rotate` retires the previous key and activates a new one.

## Revocation

Grant cancellation is an **application control** on the wallet's grant row, serialised with claiming
through the same compare-and-swap. A disconnected third-party verifier holding a previously signed
mandate cannot learn about it; it relies on `exp` (short in autonomous mode) or must query the wallet
(`GET /v1/authorizations/{id}`). This project's verifiers are online with the wallet's database, so
they check grant state at step 11 of the pipeline.

## What the proofs do not establish

* that the merchant's product description is truthful, or that goods were delivered
* that a real card network accepted anything — the processor is simulated and its receipts are test
  artifacts
* that a local issuer or registry is accredited by any network
