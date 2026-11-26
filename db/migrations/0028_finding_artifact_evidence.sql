-- Durable idempotency ledger for hash-verified, finding-linked artifacts.
-- The artifact files remain in the protected evidence store; this table records
-- only immutable provenance identifiers used to advance evidence_version once.
CREATE TABLE IF NOT EXISTS finding_artifact_evidence (
    finding_id  BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    sha256      TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    activity_id BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (finding_id, sha256)
);

CREATE INDEX IF NOT EXISTS idx_finding_artifact_evidence_activity
    ON finding_artifact_evidence(activity_id);
