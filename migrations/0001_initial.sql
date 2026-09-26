-- 0001_initial.sql — generated from aaw_domain.models (PostgreSQL dialect).
-- Apply with: psql "$DATABASE_URL" -f migrations/0001_initial.sql
-- Services also run Base.metadata.create_all() on startup (idempotent), so this file documents the schema

BEGIN;

CREATE TABLE IF NOT EXISTS agents (
	id VARCHAR(64) NOT NULL, 
	display_name VARCHAR(128) NOT NULL, 
	provider VARCHAR(128) NOT NULL, 
	mandate_public_jwk JSON NOT NULL, 
	mandate_key_thumbprint VARCHAR(64) NOT NULL, 
	tap_key_id VARCHAR(128) NOT NULL, 
	api_token VARCHAR(128) NOT NULL, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (api_token)
);

CREATE TABLE IF NOT EXISTS artifact_blobs (
	reference VARCHAR(64) NOT NULL, 
	ciphertext BYTEA NOT NULL, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (reference)
);

CREATE TABLE IF NOT EXISTS audit_events (
	id VARCHAR(64) NOT NULL, 
	actor VARCHAR(128) NOT NULL, 
	action VARCHAR(64) NOT NULL, 
	target_type VARCHAR(32) NOT NULL, 
	target_id VARCHAR(64) NOT NULL, 
	trace_id VARCHAR(64), 
	at INTEGER NOT NULL, 
	details_json JSON NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_audit_events_action ON audit_events (action);
CREATE INDEX IF NOT EXISTS ix_audit_events_trace_id ON audit_events (trace_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_target_id ON audit_events (target_id);

CREATE TABLE IF NOT EXISTS authorization_grants (
	id VARCHAR(64) NOT NULL, 
	proposal_id VARCHAR(64) NOT NULL, 
	user_id VARCHAR(64) NOT NULL, 
	agent_id VARCHAR(64) NOT NULL, 
	agent_key_thumbprint VARCHAR(64) NOT NULL, 
	profile VARCHAR(16) NOT NULL, 
	profile_version VARCHAR(64) NOT NULL, 
	mode VARCHAR(16) NOT NULL, 
	constraints_json JSON NOT NULL, 
	consent_snapshot_digest VARCHAR(64) NOT NULL, 
	bound_checkout_digest VARCHAR(128), 
	status VARCHAR(32) NOT NULL, 
	expires_at INTEGER NOT NULL, 
	not_before INTEGER NOT NULL, 
	cancelled_at INTEGER, 
	version INTEGER NOT NULL, 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_authorization_grants_user_id ON authorization_grants (user_id);
CREATE INDEX IF NOT EXISTS ix_authorization_grants_status ON authorization_grants (status);
CREATE INDEX IF NOT EXISTS ix_authorization_grants_proposal_id ON authorization_grants (proposal_id);
CREATE INDEX IF NOT EXISTS ix_authorization_grants_agent_id ON authorization_grants (agent_id);

CREATE TABLE IF NOT EXISTS authorization_proposals (
	id VARCHAR(64) NOT NULL, 
	user_id VARCHAR(64) NOT NULL, 
	agent_id VARCHAR(64) NOT NULL, 
	profile VARCHAR(16) NOT NULL, 
	profile_version VARCHAR(64) NOT NULL, 
	mode VARCHAR(16) NOT NULL, 
	constraints_json JSON NOT NULL, 
	checkout_reference VARCHAR(128), 
	checkout_jwt TEXT, 
	consent_snapshot_json JSON NOT NULL, 
	consent_snapshot_digest VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	version INTEGER NOT NULL, 
	grant_id VARCHAR(64), 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_authorization_proposals_agent_id ON authorization_proposals (agent_id);
CREATE INDEX IF NOT EXISTS ix_authorization_proposals_user_id ON authorization_proposals (user_id);

CREATE TABLE IF NOT EXISTS consent_challenges (
	id VARCHAR(64) NOT NULL, 
	proposal_id VARCHAR(64) NOT NULL, 
	user_id VARCHAR(64) NOT NULL, 
	snapshot_digest VARCHAR(64) NOT NULL, 
	nonce VARCHAR(64) NOT NULL, 
	expires_at INTEGER NOT NULL, 
	consumed_at INTEGER, 
	invalidated_at INTEGER, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (nonce)
);

CREATE INDEX IF NOT EXISTS ix_consent_challenges_proposal_id ON consent_challenges (proposal_id);

CREATE TABLE IF NOT EXISTS execution_claims (
	id VARCHAR(64) NOT NULL, 
	grant_id VARCHAR(64) NOT NULL, 
	checkout_digest VARCHAR(128) NOT NULL, 
	checkout_reference VARCHAR(128), 
	idempotency_key VARCHAR(128) NOT NULL, 
	payment_attempt_id VARCHAR(64), 
	state VARCHAR(32) NOT NULL, 
	trace_id VARCHAR(64) NOT NULL, 
	profile VARCHAR(16) NOT NULL, 
	amount_minor INTEGER NOT NULL, 
	currency VARCHAR(3) NOT NULL, 
	payee_id VARCHAR(64) NOT NULL, 
	decision VARCHAR(32) NOT NULL, 
	diagnostic_json JSON NOT NULL, 
	claimed_at INTEGER NOT NULL, 
	resolved_at INTEGER, 
	order_id VARCHAR(64), 
	PRIMARY KEY (id), 
	CONSTRAINT uq_claim_idempotency UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_execution_claims_grant_id ON execution_claims (grant_id);
CREATE INDEX IF NOT EXISTS ix_claim_grant_state ON execution_claims (grant_id, state);
CREATE INDEX IF NOT EXISTS ix_execution_claims_state ON execution_claims (state);

CREATE TABLE IF NOT EXISTS merchant_checkouts (
	id VARCHAR(64) NOT NULL, 
	merchant_id VARCHAR(64) NOT NULL, 
	checkout_jwt TEXT NOT NULL, 
	checkout_hash VARCHAR(64) NOT NULL, 
	total_minor INTEGER NOT NULL, 
	currency VARCHAR(3) NOT NULL, 
	line_items_json JSON NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	order_id VARCHAR(64), 
	created_at INTEGER NOT NULL, 
	expires_at INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_merchant_checkouts_merchant_id ON merchant_checkouts (merchant_id);
CREATE INDEX IF NOT EXISTS ix_merchant_checkouts_checkout_hash ON merchant_checkouts (checkout_hash);

CREATE TABLE IF NOT EXISTS merchants (
	id VARCHAR(64) NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	website VARCHAR(256) NOT NULL, 
	authority VARCHAR(256) NOT NULL, 
	checkout_kid VARCHAR(128) NOT NULL, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS payment_attempts (
	id VARCHAR(64) NOT NULL, 
	claim_id VARCHAR(64) NOT NULL, 
	idempotency_key VARCHAR(128) NOT NULL, 
	amount_minor INTEGER NOT NULL, 
	currency VARCHAR(3) NOT NULL, 
	payee_id VARCHAR(64) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	psp_confirmation_id VARCHAR(64), 
	fault VARCHAR(64), 
	created_at INTEGER NOT NULL, 
	updated_at INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_payment_attempts_claim_id ON payment_attempts (claim_id);

CREATE TABLE IF NOT EXISTS processor_ledger (
	idempotency_key VARCHAR(128) NOT NULL, 
	amount_minor INTEGER NOT NULL, 
	currency VARCHAR(3) NOT NULL, 
	payee_id VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	psp_confirmation_id VARCHAR(64) NOT NULL, 
	executed_at INTEGER NOT NULL, 
	PRIMARY KEY (idempotency_key)
);

CREATE TABLE IF NOT EXISTS protocol_artifacts (
	id VARCHAR(64) NOT NULL, 
	grant_id VARCHAR(64), 
	claim_id VARCHAR(64), 
	artifact_type VARCHAR(64) NOT NULL, 
	profile VARCHAR(16) NOT NULL, 
	issuer_id VARCHAR(128) NOT NULL, 
	encrypted_object_reference VARCHAR(64) NOT NULL, 
	digest VARCHAR(64) NOT NULL, 
	allowed_reader_roles JSON NOT NULL, 
	created_at INTEGER NOT NULL, 
	retention_until INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_protocol_artifacts_claim_id ON protocol_artifacts (claim_id);
CREATE INDEX IF NOT EXISTS ix_protocol_artifacts_grant_id ON protocol_artifacts (grant_id);

CREATE TABLE IF NOT EXISTS receipts (
	id VARCHAR(64) NOT NULL, 
	claim_id VARCHAR(64) NOT NULL, 
	receipt_type VARCHAR(32) NOT NULL, 
	issuer_id VARCHAR(128) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	reference VARCHAR(64) NOT NULL, 
	jwt TEXT NOT NULL, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_receipts_claim_id ON receipts (claim_id);

CREATE TABLE IF NOT EXISTS request_replay_records (
	id VARCHAR(64) NOT NULL, 
	key_id VARCHAR(128) NOT NULL, 
	nonce VARCHAR(128) NOT NULL, 
	created INTEGER NOT NULL, 
	expires INTEGER NOT NULL, 
	first_seen_at INTEGER NOT NULL, 
	trace_id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_replay_key_nonce UNIQUE (key_id, nonce)
);

CREATE TABLE IF NOT EXISTS trusted_keys (
	id VARCHAR(64) NOT NULL, 
	participant_type VARCHAR(32) NOT NULL, 
	issuer_or_agent_id VARCHAR(128) NOT NULL, 
	key_id VARCHAR(128) NOT NULL, 
	public_key JSON NOT NULL, 
	algorithm VARCHAR(32) NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	valid_from INTEGER NOT NULL, 
	valid_until INTEGER, 
	local_status VARCHAR(32) NOT NULL, 
	fetched_at INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_trusted_key UNIQUE (participant_type, issuer_or_agent_id, key_id)
);

CREATE TABLE IF NOT EXISTS users (
	id VARCHAR(64) NOT NULL, 
	display_name VARCHAR(128) NOT NULL, 
	api_token VARCHAR(128) NOT NULL, 
	created_at INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (api_token)
);

CREATE TABLE IF NOT EXISTS verification_attempts (
	id VARCHAR(64) NOT NULL, 
	grant_id VARCHAR(64), 
	claim_id VARCHAR(64), 
	checkout_reference VARCHAR(128), 
	trace_id VARCHAR(64) NOT NULL, 
	verifier_role VARCHAR(32) NOT NULL, 
	profile VARCHAR(16), 
	ruleset_version VARCHAR(64) NOT NULL, 
	decision VARCHAR(32) NOT NULL, 
	reason_codes JSON NOT NULL, 
	diagnostic_json JSON NOT NULL, 
	latency_ms INTEGER NOT NULL, 
	verified_at INTEGER NOT NULL, 
	redacted_evidence_reference VARCHAR(64), 
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_verification_attempts_grant_id ON verification_attempts (grant_id);
CREATE INDEX IF NOT EXISTS ix_verification_attempts_claim_id ON verification_attempts (claim_id);
CREATE INDEX IF NOT EXISTS ix_verification_attempts_trace_id ON verification_attempts (trace_id);

COMMIT;
