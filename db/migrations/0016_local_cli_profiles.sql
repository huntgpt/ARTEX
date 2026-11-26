-- Local AI CLI profiles keep OAuth material in each CLI's own configuration
-- directory. ARTEX stores only the executable and directory paths; it never
-- copies refresh/access tokens into PostgreSQL.
ALTER TABLE llm_profiles
    ADD COLUMN IF NOT EXISTS cli_path TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cli_config_dir TEXT NOT NULL DEFAULT '';

ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;
ALTER TABLE llm_profiles ADD CONSTRAINT llm_profiles_format_check CHECK (
    format IN (
        'openai', 'anthropic', 'openai-responses', 'ollama',
        'bedrock-gateway', 'claude-cli', 'codex-cli'
    )
);
