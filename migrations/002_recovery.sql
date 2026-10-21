CREATE TABLE IF NOT EXISTS account_recovery (
    user_id UUID PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    recovery_key_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sync_conflict (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    local_envelope BYTEA NOT NULL,
    remote_envelope BYTEA NOT NULL,
    local_revision BIGINT NOT NULL,
    remote_revision BIGINT NOT NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sync_conflict_pending
    ON sync_conflict (user_id, resolved_at)
    WHERE resolved_at IS NULL;
