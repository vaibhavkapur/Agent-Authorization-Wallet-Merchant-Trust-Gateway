# AP2 profile (v0.2) — implementation notes

[Documentation home](../index.md)

Package: `packages/ap2-profile/aaw_ap2`. Version string reported by the API:
`ap2-v0.2@e1ea56d+draft-gco-oauth-delegate-sd-jwt-00`.

## Delegation model

AP2 offers two delegation models. This project implements the **User Credential** model:

```
[0] issuer SD-JWT            typ dc+sd-jwt, vct urn:aaw:test:user-credential:1, cnf = user device key
 ~~
[1] user KB-SD-JWT(+KB)      typ kb+sd-jwt+kb (autonomous) | kb+sd-jwt (direct), signed by the user key
                             delegate_payload = [ {"...": D_checkout}, {"...": D_payment} ]
                             sd_hash over the presented [0]; nonce = consent challenge digest prefix
 ~~
[2] agent KB-SD-JWT          typ kb+sd-jwt, signed by the key in the open mandate's cnf (autonomous only)
                             delegate_payload = [ {"...": D_closed} ], sd_hash over the presented [1],
                             aud = verifier, nonce = TAP request nonce
```

Compact serialization follows draft-gco-oauth-delegate-sd-jwt-00 §5.1.1 (`~~` separates links,
trailing `~`). Verification follows §6 plus the AP2 *Verification and Processing Rules*:

1. link 0 issuer resolved from the trust store by `(iss, kid)`; `kid` is only a lookup hint
2. each following link verified with the previous content's `cnf.jwk`; `typ` enforced
   (`kb+sd-jwt+kb` for intermediate, `kb+sd-jwt` for final); `sd_hash` or `issuer_jwt_hash` must match
3. exactly one `delegate_payload` element disclosed per link; unreferenced disclosures rejected
   (`UNEXPECTED_DISCLOSURE`), altered disclosures rejected (`DISCLOSURE_DIGEST_MISMATCH`)
4. `vct` matched exactly (`mandate.checkout.open.1`, `mandate.checkout.1`, `mandate.payment.open.1`,
   `mandate.payment.1`)
5. open-mandate claims must be unchanged in the closed mandate (e.g. `payment_instrument`)
6. constraints evaluated per type; unknown constraint types fail (`UNKNOWN_CONSTRAINT`, receipt error
   `unresolved_constraint`)

Constraint types used: `checkout.allowed_merchants`, `checkout.line_items`, `payment.amount_range`,
`payment.allowed_payees`, `payment.reference`, `payment.execution_date`. Defined by AP2 but rejected
by this single-purchase profile: `payment.agent_recurrence`, `payment.budget`, `payment.allowed_pisps`.

## Interpretation decisions (where the specification is silent or ambiguous)

* **`payment.reference.conditional_transaction_id`.** The published example equals the `sd_hash` of the
  open checkout mandate presentation *with all its disclosures*. That value cannot be recomputed by a
  verifier once the agent selectively discloses (one merchant out of two), and it is circular when the
  open checkout and open payment mandates share one user signature. This project sets it to the
  **disclosure digest of the open checkout mandate element** (the value that appears as `{"...": D}` in
  `delegate_payload`) — literally "a matching hash in its delegate chain", stable under selective
  disclosure, and identical to the Verifiable Intent reference implementation's choice. Test
  `test_ap2_spec_payment_example_reference_equals_open_checkout_sd_hash` documents the published
  example's behaviour.
* **Both open mandates in one user signature.** One consent action yields one `kb+sd-jwt+kb` whose
  `delegate_payload` has two disclosure elements; the agent discloses exactly one per verifier
  (draft §5.1.4). Merchant and payment participants therefore share the same user JWT but see
  different mandate contents.
* **Direct mode nonce.** The user-signed closed mandates carry the consent nonce (bound to the reviewed
  snapshot digest) and an `aud` array `[merchant website, payment verifier]`. Replay protection comes
  from the TAP request nonce and the one-claim-per-checkout coordinator, not from the mandate nonce.
  The coordinator checks the presented nonce against the grant's recorded consent nonce.
* **Autonomous mode freshness.** Agent-signed final links must carry the TAP request nonce, the
  verifier's audience, and an `iat` within 600 s.
* **L1 identity disclosures are never presented.** The user signs `sd_hash` over the bare credential
  JWT, so the agent cannot add identity disclosures later.

## Receipts

`aaw_ap2.receipts` issues Checkout/Payment Receipts as JWTs (`typ ap2-receipt+jwt`) with `status`,
`iss`, `iat`, `reference` (sd_hash-style digest of the final SD-JWT), `order_id`/`payment_id`,
`psp_confirmation_id`, and `error`/`error_description` mapped from reason codes to
`invalid_credential`, `unresolved_constraint`, `invalid_mandate`, `mandates_not_supported`.

## Re-presentation after failure

AP2: "Shopping Agents MUST NOT present any subsequent open Mandates without receiving a rejection
receipt from the previous one." After the coordinator issues an Error receipt for a definitively
non-executed attempt, the grant returns to `active` and the agent may present the open mandate for
another checkout (audit action `REPRESENTATION_PERMITTED_AFTER_REJECTION_RECEIPT`).

## Fixtures

`fixtures/ap2/*.sdjwt|.dsdjwt` are the encoded examples published on ap2-protocol.org
(Checkout Mandate and Payment Mandate pages, fetched 2026-09-26). They were produced by an
independent implementation; `tests/crypto/test_sdjwt_and_spec_fixtures.py` shows they parse, that the
closed mandate signature verifies against the open mandate's `cnf`, that `sd_hash` and `checkout_hash`
recompute exactly, and that alterations are rejected. The issuer key `agent-provider-key-1` is not
published, so only the issuer signature step is skipped for the fixture (a test-only flag).
