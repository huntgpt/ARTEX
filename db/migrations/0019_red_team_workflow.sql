-- Deterministic, dependency-aware red-team phase state for each task.
CREATE TABLE IF NOT EXISTS red_team_phase_runs (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    phase          TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'pending'
                   CHECK (state IN ('pending','ready','running','blocked','complete','skipped','failed')),
    owner          TEXT NOT NULL DEFAULT '',
    tool           TEXT NOT NULL DEFAULT '',
    current_result TEXT NOT NULL DEFAULT '',
    blocker_reason TEXT NOT NULL DEFAULT '',
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, phase)
);

CREATE INDEX IF NOT EXISTS idx_red_team_phase_runs_progress
    ON red_team_phase_runs(exploration_id, state, updated_at DESC);
