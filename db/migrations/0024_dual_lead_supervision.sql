-- Stable project supervision for one or two independent LLM leads. Leads
-- review one immutable snapshot; the canonical Planner remains the only intent
-- writer, preventing split-brain queues.
CREATE TABLE IF NOT EXISTS task_supervisor_config (
    task_id              BIGINT PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    mode                 TEXT NOT NULL DEFAULT 'off'
                           CHECK (mode IN ('off','single','dual')),
    primary_profile_id   BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    secondary_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    checkpoint_policy    TEXT NOT NULL DEFAULT 'strategic'
                           CHECK (checkpoint_policy IN ('strategic','every_round','manual')),
    revision             BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (primary_profile_id IS NULL OR secondary_profile_id IS NULL OR primary_profile_id <> secondary_profile_id)
);
CREATE INDEX IF NOT EXISTS idx_task_supervisor_primary ON task_supervisor_config(primary_profile_id)
    WHERE primary_profile_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_task_supervisor_secondary ON task_supervisor_config(secondary_profile_id)
    WHERE secondary_profile_id IS NOT NULL;
DROP TRIGGER IF EXISTS trg_task_supervisor_config_upd ON task_supervisor_config;
CREATE TRIGGER trg_task_supervisor_config_upd BEFORE UPDATE ON task_supervisor_config
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS supervisor_rounds (
    id            BIGSERIAL PRIMARY KEY,
    task_id       BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    trigger_kind  TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','running','merging','completed','partial','failed','cancelled')),
    snapshot_hash TEXT NOT NULL CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    snapshot      JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_supervisor_rounds_task ON supervisor_rounds(task_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_supervisor_round_open ON supervisor_rounds(task_id)
    WHERE state IN ('pending','running','merging');
DROP TRIGGER IF EXISTS trg_supervisor_rounds_upd ON supervisor_rounds;
CREATE TRIGGER trg_supervisor_rounds_upd BEFORE UPDATE ON supervisor_rounds
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS supervisor_reviews (
    id            BIGSERIAL PRIMARY KEY,
    round_id      BIGINT NOT NULL REFERENCES supervisor_rounds(id) ON DELETE CASCADE,
    lead_role     TEXT NOT NULL CHECK (lead_role IN ('primary','secondary')),
    profile_id    BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    provider      TEXT NOT NULL DEFAULT '',
    model         TEXT NOT NULL DEFAULT '',
    account_label TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','running','completed','failed','cancelled')),
    proposal      JSONB CHECK (proposal IS NULL OR jsonb_typeof(proposal) = 'object'),
    summary       TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    input_tokens  INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (round_id, lead_role)
);
CREATE INDEX IF NOT EXISTS idx_supervisor_reviews_round ON supervisor_reviews(round_id, lead_role);
DROP TRIGGER IF EXISTS trg_supervisor_reviews_upd ON supervisor_reviews;
CREATE TRIGGER trg_supervisor_reviews_upd BEFORE UPDATE ON supervisor_reviews
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS supervisor_decisions (
    id                 BIGSERIAL PRIMARY KEY,
    round_id           BIGINT NOT NULL UNIQUE REFERENCES supervisor_rounds(id) ON DELETE CASCADE,
    arbiter_profile_id BIGINT REFERENCES llm_profiles(id) ON DELETE SET NULL,
    decision           JSONB NOT NULL CHECK (jsonb_typeof(decision) = 'object'),
    rationale          TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_supervisor_decisions_arbiter ON supervisor_decisions(arbiter_profile_id)
    WHERE arbiter_profile_id IS NOT NULL;
