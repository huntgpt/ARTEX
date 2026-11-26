-- Finding-linked Worker follow-ups are independent validation runs just like a
-- Retester conversation, but their server-owned identity is an exploration
-- intent.  Keep that provenance explicit and unique so an intent can never
-- materialize two contradictory formal retest records.
ALTER TABLE finding_retests
    ADD COLUMN IF NOT EXISTS source_intent_id BIGINT UNIQUE
        REFERENCES exploration_nodes(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_finding_retests_source_intent
    ON finding_retests(source_intent_id)
    WHERE source_intent_id IS NOT NULL;
