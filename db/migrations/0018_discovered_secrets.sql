-- Secrets discovered by scanners are kept encrypted at rest and separated from
-- ordinary facts/activity so plaintext never enters prompts, logs or reports.
CREATE TABLE IF NOT EXISTS discovered_secrets (
    id              BIGSERIAL PRIMARY KEY,
    task_id         BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    detector        TEXT NOT NULL,
    source_type     TEXT NOT NULL DEFAULT '',
    source_name     TEXT NOT NULL DEFAULT '',
    repository      TEXT NOT NULL DEFAULT '',
    file_path       TEXT NOT NULL DEFAULT '',
    line_number     INTEGER NOT NULL DEFAULT 0,
    commit_hash     TEXT NOT NULL DEFAULT '',
    verified        BOOLEAN NOT NULL DEFAULT false,
    secret_value    TEXT NOT NULL,
    secret_value_v2 TEXT NOT NULL DEFAULT '',
    secret_sha256   TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    scanner_redacted TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(task_id, detector, secret_sha256, repository, file_path, line_number, commit_hash)
);
CREATE INDEX IF NOT EXISTS idx_discovered_secrets_task
    ON discovered_secrets(task_id, verified DESC, id DESC);

CREATE TABLE IF NOT EXISTS secret_access_audit (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    secret_id   BIGINT NOT NULL REFERENCES discovered_secrets(id) ON DELETE CASCADE,
    actor       TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL CHECK (action IN ('reveal','copy','validation-use')),
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_secret_access_audit_task
    ON secret_access_audit(task_id, created_at DESC);
