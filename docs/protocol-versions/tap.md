# TAP profile — implementation notes

[Documentation home](../index.md)

Package: `packages/tap-verifier/aaw_tap`. Pinned to the Visa sample implementation
(`visa/trusted-agent-protocol` @ `16d59bd`), which uses RFC 9421 HTTP Message Signatures.

## Wire format (matches the sample)

```
Signature-Input: sig2=("@authority" "@path" "content-digest");created=1790421969;expires=1790422449;keyId="agent_shopping_ed25519-key-1";alg="ed25519";nonce="8d2a25e6-…";tag="agent-payer-auth"
Signature:       sig2=:<base64 signature>:
Content-Digest:  sha-256=:<base64 sha-256 of the body>:
Signature-Agent: "shopping_agent_1"
```

Signature base (RFC 9421 §2.5, as the sample builds it):

```
"@authority": gateway.aaw.test
"@path": /gateway/checkouts/co_…/complete
"content-digest": sha-256=:…:
"@signature-params": ("@authority" "@path" "content-digest");created=…;expires=…;keyId="…";alg="ed25519";nonce="…";tag="agent-payer-auth"
```

The verifier uses the received `Signature-Input` parameter string verbatim, so the sample's
`; `-spaced variant also verifies (`fixtures/tap/visa_sample_signature_input.txt`).

## Checks, in order

1. headers present; one label; base64 signature
2. covered components include `@authority` and `@path`; **requests with a body must also cover
   `content-digest`** (local extension — the sample covers only `@authority`/`@path` because its
   demo requests are GETs)
3. `created ≤ now + 60`, `expires ≥ now`, `expires − created ≤ 480 s` (8 minutes, as in the sample)
4. operation context: `tag` must be `agent-payer-auth` on the checkout-completion endpoint
   (`agent-browser-auth` is rejected with `OPERATION_CONTEXT_MISMATCH`)
5. `keyId` resolved through the registry-backed trust store; the registered algorithm must equal `alg`;
   inactive/revoked keys fail (`AGENT_KEY_INACTIVE`); the `Signature-Agent` header, if present, must
   name the agent the registry maps the key to
6. `Content-Digest` recomputed over the raw body
7. signature verified (`ed25519` or `rsa-pss-sha256`)
8. `(keyId, nonce)` inserted into `request_replay_records` (unique) — a second delivery is
   `REQUEST_REPLAY`

The gateway then verifies the merchant-side mandate chain with the TAP nonce as the expected mandate
nonce and `urn:aaw:agent:<agent_id>` (from the registry) as the expected delegate audience, so the
request signer and the mandate delegate must be the same agent. The coordinator additionally checks
that the TAP agent equals the grant's delegate agent.

## Registry

`apps/test-registry` exposes `GET /registry/keys/{key_id}` in the shape of the sample registry
(`key_id`, `is_active`, `public_key`, `algorithm`, `agent_id`) and authenticated enrollment/status
endpoints. Keys live in the shared `trusted_keys` table, which is what the gateway resolves against.
This is a **test registry**: local verification is not network accreditation.
