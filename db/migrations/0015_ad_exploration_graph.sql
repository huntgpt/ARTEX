-- Task-scoped Active Directory observations. These tables extend the
-- exploration graph; they deliberately do not reference or populate assets or
-- company_scope. AD principals are engagement evidence, not shared inventory.
CREATE TABLE IF NOT EXISTS ad_nodes (
    exploration_id BIGINT NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    object_key     TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('domain','user','group','computer')),
    sid            TEXT NOT NULL DEFAULT '',
    dns_hostname   TEXT NOT NULL DEFAULT '',
    domain_sid     TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL CHECK (state IN ('observed','inferred')),
    detail         JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, object_key)
);

CREATE INDEX IF NOT EXISTS idx_ad_nodes_kind
    ON ad_nodes(exploration_id, kind, object_key);
CREATE INDEX IF NOT EXISTS idx_ad_nodes_dns
    ON ad_nodes(exploration_id, dns_hostname)
    WHERE dns_hostname <> '';

CREATE TABLE IF NOT EXISTS ad_edges (
    exploration_id BIGINT NOT NULL,
    source_key     TEXT NOT NULL,
    relation       TEXT NOT NULL CHECK (relation IN ('member_of','admin_to','has_session')),
    target_key     TEXT NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('observed','inferred')),
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (exploration_id, source_key, relation, target_key),
    CONSTRAINT fk_ad_edges_source FOREIGN KEY (exploration_id, source_key)
        REFERENCES ad_nodes(exploration_id, object_key) ON DELETE CASCADE,
    CONSTRAINT fk_ad_edges_target FOREIGN KEY (exploration_id, target_key)
        REFERENCES ad_nodes(exploration_id, object_key) ON DELETE CASCADE,
    CONSTRAINT ck_ad_edges_noself CHECK (source_key <> target_key)
);

CREATE INDEX IF NOT EXISTS idx_ad_edges_target
    ON ad_edges(exploration_id, target_key, relation);
