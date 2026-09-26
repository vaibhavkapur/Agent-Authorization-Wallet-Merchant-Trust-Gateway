# Database and Evidence

[Documentation home](index.md)

## Storage model

SQLAlchemy models in `packages/authorization-domain/aaw_domain/models.py` store participants, proposals, consent challenges, grants, execution claims, trusted keys, request replay records, verification attempts, and evidence. The database initializes tables on startup; `migrations/` provides schema material for inspection.

SQLite is the local default and enables foreign keys, WAL where supported, and a busy timeout. Compose uses PostgreSQL. Both are accessed through the session boundary in `aaw_domain.db`.

## Atomic authority consumption

A grant is claimed with a compare-and-swap before external execution. The claim tracks whether submission is pending, consumed, or uncertain. Replay protection for a TAP request is separate from execution idempotency for a grant/checkout pair.

The worker resolves stale claims and uncertain processor outcomes. Retain the database when testing recovery; deleting a claim to make a retry proceed removes the evidence needed to distinguish an unexecuted request from a completed payment.

## Protected artifacts

Authorization artifacts are stored through the encrypted vault, and evidence endpoints return role-specific views. Participant signing keys live separately in `AAW_KEYS_DIR`; verifiers use public trusted-key records. Keep database, key material, and artifact-key configuration together when restoring a local environment.

See [Trust Model](trust-model/README.md) for retired-key verification and the limits of revocation at disconnected verifiers. Receipts describe simulated processing, not settlement on an external network.
