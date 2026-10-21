CREATE TABLE IF NOT EXISTS app_user (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    auth_verifier TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_session (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sync_blob (
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    envelope BYTEA NOT NULL,
    version BIGINT NOT NULL,
    deleted_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, entity_type, entity_id)
);

CREATE SEQUENCE IF NOT EXISTS sync_revision_seq;

CREATE INDEX IF NOT EXISTS sync_blob_changes
    ON sync_blob (user_id, version);
