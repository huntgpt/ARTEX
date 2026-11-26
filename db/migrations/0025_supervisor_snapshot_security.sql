-- The original Duo Lead snapshot hash covered Go's compact JSON bytes, while
-- PostgreSQL JSONB normalizes whitespace and object order. More importantly,
-- early snapshots could persist free-text credentials from hints/facts. New
-- snapshots are canonicalized and scrubbed in Go. Existing rows are replaced
-- with one deterministic tombstone; their original audit hash is retained so
-- an operator can correlate exported historical reviews without retaining the
-- unsafe plaintext snapshot.
ALTER TABLE supervisor_rounds
    ADD COLUMN IF NOT EXISTS legacy_snapshot_hash TEXT
        CHECK (legacy_snapshot_hash IS NULL OR legacy_snapshot_hash ~ '^[0-9a-f]{64}$');

UPDATE supervisor_rounds
SET legacy_snapshot_hash = snapshot_hash,
    snapshot = '{"legacy_snapshot_redacted":true}'::jsonb,
    snapshot_hash = 'e704b77163acea7bf8b4f599a79461d024629ea0f0ddc4c67431a1a4c87c18de'
WHERE legacy_snapshot_hash IS NULL;
