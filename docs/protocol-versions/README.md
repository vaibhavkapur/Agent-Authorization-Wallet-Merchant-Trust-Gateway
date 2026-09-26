# Pinned protocol revisions

[Documentation home](../index.md)

All normative inputs were captured on **2026-09-26**. Nothing here is a network
certification; every issuer, registry, merchant and processor is a local test
participant.

| Profile | Source | Revision | Local package |
| --- | --- | --- | --- |
| AP2 | [ap2-protocol.org specification v0.2](https://ap2-protocol.org/ap2/specification/), `google-agentic-commerce/AP2` | commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29) | `packages/ap2-profile` (`aaw_ap2`) |
| Delegate SD-JWT (used by AP2) | [draft-gco-oauth-delegate-sd-jwt-00](https://datatracker.ietf.org/doc/html/draft-gco-oauth-delegate-sd-jwt-00) | -00, published 2026-04-21 | `aaw_ap2.sdjwt`, `aaw_ap2.verify` |
| SD-JWT | RFC 9901 (Nov 2025) | — | `aaw_ap2.sdjwt` (disclosure processing), vendored VI crypto |
| Verifiable Intent | [agent-intent/verifiable-intent](https://github.com/agent-intent/verifiable-intent) draft v0.1 | commit `356c29635f1c44df7de02edb58699ca9f29bece6` (2026-04-20), reference implementation vendored unmodified under `packages/vi-profile/vendor/verifiable_intent` (Apache-2.0) | `packages/vi-profile` (`aaw_vi`) |
| TAP | [visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol) sample | commit `16d59bdf3f8a542bc538d0962edbb80ea30a02af` (2025-10-28); RFC 9421 / RFC 9530 | `packages/tap-verifier` (`aaw_tap`) |

Algorithms (allowlisted, never taken from the artifact alone):

* `ES256` for every JOSE artifact (credentials, mandates, checkout JWT, receipts). AP2 requires a
  non-deterministic scheme for the checkout JWT; ES256 satisfies it.
* `ed25519` (default) and `rsa-pss-sha256` for TAP request signatures, as in the Visa sample.
* `sha-256` for every SD-JWT digest, `sd_hash`, `checkout_hash`, `transaction_id`, Content-Digest.

Library versions: see `requirements.txt`. jwcrypto 1.6.1 performs JWS signing/verification;
disclosure processing for AP2 is implemented in `aaw_ap2.sdjwt` and cross-checked in tests against
the vendored VI reference's independent `hash_disclosure`/`es256_verify`.

Profile-specific notes: [ap2.md](ap2.md), [vi.md](vi.md), [tap.md](tap.md).
