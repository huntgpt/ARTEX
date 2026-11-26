-- Optional per-profile Claude OAuth token file. ARTEX stores only the path;
-- the bridge passes the token over a private inherited file descriptor.
ALTER TABLE llm_profiles
    ADD COLUMN IF NOT EXISTS cli_auth_token_file TEXT NOT NULL DEFAULT '';
