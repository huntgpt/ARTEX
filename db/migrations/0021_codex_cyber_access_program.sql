-- Codex CLI requires an explicit cyber policy tier for authorized red-team
-- prompts. Store only the selected tier; OAuth credentials remain CLI-owned.
ALTER TABLE llm_profiles
    ADD COLUMN IF NOT EXISTS cyber_access_program TEXT NOT NULL DEFAULT '';

ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_cyber_access_program_check;
ALTER TABLE llm_profiles ADD CONSTRAINT llm_profiles_cyber_access_program_check
    CHECK (cyber_access_program IN ('','standard','daybreak_blue','daybreak_red'));
