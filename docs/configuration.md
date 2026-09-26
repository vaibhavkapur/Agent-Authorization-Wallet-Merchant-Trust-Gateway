# Configuration

[Documentation home](index.md)

## Loading settings

Export environment variables before starting Python services; `Settings` reads `os.environ` and does not load a `.env` file. The authoritative definitions are `apps/api/aaw_api/settings.py` and `docker-compose.yml`.

## Data and runtime

- `DATABASE_URL`: defaults to `sqlite:///./aaw.db`; Compose uses PostgreSQL with the `psycopg2` driver.
- `AAW_KEYS_DIR`: `.keys`; must remain consistent with persisted trusted keys and grants.
- `AAW_ARTIFACT_KEY`: encryption-key material for the artifact vault. Compose supplies development-only material; retain the same value when reopening existing encrypted artifacts.
- `AAW_FIXED_CLOCK=1`: freezes the process clock at startup and enables the advance-clock demo. Otherwise the system clock is used.
- `AAW_WORKER_INTERVAL`: seconds between standalone worker iterations; Compose sets `5`.

## Service routing

- `AAW_GATEWAY_MODE`: `embedded` by default; `remote` uses `AAW_GATEWAY_URL` (default `http://gateway:8010`).
- `AAW_API_URL`: `http://api:8000`, used by the gateway in the separate-service topology.
- `AAW_ISSUER_URL`: `http://issuer:8020`, used for remote issuance.
- `AAW_GATEWAY_AUTHORITY`: `gateway.aaw.test`, the signed request authority. Keep routing and signature validation aligned.
- `AAW_CORS_ORIGINS`: comma-separated UI origins; default `http://localhost:3000`.
- `NEXT_PUBLIC_API_URL`: browser-visible API URL for the web app; local default is `http://localhost:8000`.

## Identity and development access

- `AAW_WALLET_ISSUER`: `https://wallet.aaw.test`.
- `AAW_ISSUER_ID`: `https://issuer.aaw.test`.
- `AAW_GATEWAY_ID`: `urn:aaw:merchant-gateway`.
- `AAW_PROCESSOR_ID`: `urn:aaw:payment-processor`.
- `AAW_PAYMENT_AUDIENCE`: `urn:aaw:verifier:payment`.
- `AAW_ADMIN_TOKEN`: `dev-admin-token` by default.
- `AAW_EXPOSE_DEMO_TOKENS`: `1` by default; set `0` to hide fixture tokens in participant listings. This does not remove all demo endpoints or replace the authentication model.

Consent challenges have a 300-second lifetime defined in `Settings`. See [Trust Model](trust-model/README.md) before changing participant identities, audiences, or retained keys.
