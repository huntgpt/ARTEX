-- Preserve why a red-team phase is blocked and which durable fact, intent,
-- approval, or dependency supplied that conclusion.  Empty defaults keep all
-- existing phase rows backward compatible.
ALTER TABLE red_team_phase_runs
    ADD COLUMN IF NOT EXISTS blocker_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS blocker_source TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_red_team_phase_runs_blockers
    ON red_team_phase_runs(exploration_id, state, blocker_kind)
    WHERE state = 'blocked';
