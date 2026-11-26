-- Durable planner scratchpad. The planner is recreated on backend restart, so
-- keeping serial attack-chain prerequisites only in process memory can cause a
-- later step to be dispatched out of order after recovery.
CREATE TABLE IF NOT EXISTS planner_todos (
    exploration_id BIGINT PRIMARY KEY REFERENCES explorations(id) ON DELETE CASCADE,
    items          JSONB NOT NULL DEFAULT '[]'::jsonb
                   CHECK (jsonb_typeof(items) = 'array'),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

