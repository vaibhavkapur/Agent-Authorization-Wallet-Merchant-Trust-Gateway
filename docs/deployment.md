# Deployment

[Documentation home](index.md)

## Supported local topology

```bash
docker compose up --build
docker compose ps
curl http://localhost:8000/healthz
```

Compose starts API `8000`, gateway `8010`, issuer `8020`, registry `8030`, web `3000`, PostgreSQL `5432`, and a background reconciliation worker. The Python image uses Python 3.12. Services share the database and the named `keys` volume.

The supplied Compose file does not explicitly mount a named PostgreSQL data volume. Do not treat container recreation as a backup or persistence policy. Preserve the database, signing keys, and artifact encryption material together if retaining evidence across environment rebuilds.

## Local operation

`docker compose logs api gateway worker` helps trace the request-to-execution path. `/v1/metrics` reports unresolved claims and rejection reasons. A single-process development run has no standalone worker loop; the demo guide shows `/v1/demo/worker/run-once` for manual recovery.

Use `docker compose stop` to pause the environment without deleting it. Do not delete database or key storage while trying to reconcile an uncertain execution.

## Deployment scope

This is a local authorization and trust demonstration. The issuer, registry, merchants, processor, development tokens, and shared signer volume are fixture infrastructure. Hiding demo tokens alone does not make it a production identity, custody, or payment service. The [Trust Model](trust-model/README.md) describes the actual boundaries and [Configuration](configuration.md) documents their settings.
