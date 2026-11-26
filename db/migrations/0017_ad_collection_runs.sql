-- Auditable lifecycle for internal/AD collection jobs and their artifacts.
CREATE TABLE IF NOT EXISTS ad_collection_runs (
    id              BIGSERIAL PRIMARY KEY,
    exploration_id  BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    collector       TEXT NOT NULL CHECK (collector IN ('sharphound','bloodhound-python','adexplorer','ldap','operator-upload')),
    mode            TEXT NOT NULL DEFAULT 'offline-import' CHECK (mode IN ('offline-import','remote','on-host')),
    state           TEXT NOT NULL CHECK (state IN ('queued','approved','running','ingesting','complete','partial','rejected','failed','cancelled')),
    requested_by    TEXT NOT NULL DEFAULT '',
    approved_by     TEXT NOT NULL DEFAULT '',
    blocker_reason  TEXT NOT NULL DEFAULT '',
    error_detail    TEXT NOT NULL DEFAULT '',
    records         INTEGER NOT NULL DEFAULT 0,
    entities        INTEGER NOT NULL DEFAULT 0,
    edges           INTEGER NOT NULL DEFAULT 0,
    skipped         INTEGER NOT NULL DEFAULT 0,
    over_cap        INTEGER NOT NULL DEFAULT 0,
    truncated       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ad_collection_runs_exploration
    ON ad_collection_runs(exploration_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS ad_collection_artifacts (
    id           BIGSERIAL PRIMARY KEY,
    run_id       BIGINT NOT NULL REFERENCES ad_collection_runs(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('bloodhound-json','bloodhound-zip','adexplorer-snapshot','collector-log')),
    logical_path TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    byte_size    BIGINT NOT NULL CHECK (byte_size >= 0),
    state        TEXT NOT NULL DEFAULT 'ingested' CHECK (state IN ('received','ingested','rejected','failed')),
    error_detail TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(run_id, sha256)
);

CREATE INDEX IF NOT EXISTS idx_ad_collection_artifacts_run
    ON ad_collection_artifacts(run_id, id);
