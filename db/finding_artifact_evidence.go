package db

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
)

// FindingArtifactEvidence is one server-validated artifact declaration. The
// bytes remain in the evidence store; this durable tuple is only the
// idempotency/provenance ledger used for finding evidence revisions.
type FindingArtifactEvidence struct {
	SHA256     string
	ActivityID int64
}

// SyncFindingArtifactEvidence records newly observed verified artifacts and
// advances evidence_version once for the resulting evidence-set revision. A
// retry with the same digests is a no-op. Invalid declarations are ignored:
// callers must already have validated the file, but this layer still refuses
// malformed identifiers rather than persisting ambiguous provenance.
func (d *DB) SyncFindingArtifactEvidence(ctx context.Context, findingID int64, in []FindingArtifactEvidence) (version int64, added int, err error) {
	if findingID <= 0 {
		return 0, 0, nil
	}
	byDigest := make(map[string]int64, len(in))
	for _, item := range in {
		digest := strings.TrimSpace(item.SHA256)
		if item.ActivityID <= 0 || len(digest) != 64 || digest != strings.ToLower(digest) {
			continue
		}
		if raw, decodeErr := hex.DecodeString(digest); decodeErr != nil || len(raw) != 32 {
			continue
		}
		if _, exists := byDigest[digest]; !exists {
			byDigest[digest] = item.ActivityID
		}
	}
	digests := make([]string, 0, len(byDigest))
	for digest := range byDigest {
		digests = append(digests, digest)
	}
	sort.Strings(digests)

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if err := tx.QueryRowContext(ctx, `SELECT evidence_version FROM findings WHERE id=$1 FOR UPDATE`, findingID).Scan(&version); err != nil {
		return 0, 0, err
	}
	for _, digest := range digests {
		res, execErr := tx.ExecContext(ctx, `INSERT INTO finding_artifact_evidence(finding_id,sha256,activity_id)
			VALUES($1,$2,$3) ON CONFLICT(finding_id,sha256) DO NOTHING`, findingID, digest, byDigest[digest])
		if execErr != nil {
			return 0, 0, execErr
		}
		if n, rowsErr := res.RowsAffected(); rowsErr != nil {
			return 0, 0, rowsErr
		} else {
			added += int(n)
		}
	}
	if added > 0 {
		if err := tx.QueryRowContext(ctx, `UPDATE findings SET evidence_version=evidence_version+1
			WHERE id=$1 RETURNING evidence_version`, findingID).Scan(&version); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return version, added, nil
}
