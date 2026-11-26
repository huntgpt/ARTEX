package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrFindingRetestActive keeps the one-live-retest invariant shared by manual
// Retester conversations and finding-linked Worker follow-ups.
var ErrFindingRetestActive = errors.New("this finding already has an active retest")

// ErrFindingRetestExcluded prevents a worker from turning a duplicate, false
// positive, or ignored finding back into an actionable result through a stale
// follow-up intent.
var ErrFindingRetestExcluded = errors.New("this finding is excluded from retesting by its current disposition")

func excludedFindingRetestStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case FindingFalsePositive, FindingDuplicate, FindingIgnored:
		return true
	default:
		return false
	}
}

// createFindingFollowUpRetestTx materializes the formal pending retest in the
// same transaction that creates its finding --derived_from--> intent edge. The
// source intent is server-owned provenance; the model never supplies it.
func createFindingFollowUpRetestTx(tx *sql.Tx, findingID, intentID int64, notes string) error {
	var status string
	var snapshot []byte
	err := tx.QueryRow(`SELECT f.status,
	jsonb_build_object('finding', to_jsonb(f),
	 'assets', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])), '[]'::jsonb),
	 'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id), '[]'::jsonb),
	 'source_intent_id', $2::bigint)
	FROM findings f WHERE f.id=$1 FOR SHARE OF f`, findingID, intentID).Scan(&status, &snapshot)
	if err != nil {
		return err
	}
	if excludedFindingRetestStatus(status) {
		return nil
	}
	var active bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_retests WHERE finding_id=$1 AND status IN ('pending','running'))`, findingID).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrFindingRetestActive
	}
	_, err = tx.Exec(`INSERT INTO finding_retests(finding_id,source_intent_id,notes,snapshot)
		VALUES ($1,$2,$3,$4)`, findingID, intentID, strings.TrimSpace(notes), snapshot)
	return err
}

func validateFindingFollowUpRetestResult(verdict, summary, evidence string) (string, string, string, error) {
	verdict = strings.TrimSpace(verdict)
	if verdict != "reproduced" && verdict != "fixed" && verdict != "inconclusive" {
		return "", "", "", errors.New("verdict must be reproduced / fixed / inconclusive")
	}
	summary, evidence = strings.TrimSpace(summary), strings.TrimSpace(evidence)
	if summary == "" || evidence == "" {
		return "", "", "", errors.New("summary and evidence must not be empty; when the result cannot be confirmed, describe the actual checks and the blocking reason")
	}
	if len(summary) > 16000 || len(evidence) > 128000 {
		return "", "", "", errors.New("retest conclusion is too long (summary ≤ 16KB, evidence ≤ 128KB)")
	}
	return verdict, summary, evidence, nil
}

// RecordFindingFollowUpRetestResult stages the explicit conclusion of the
// currently running Worker intent. Ownership is proved by the exact graph edge
// and the store's exploration id; callers cannot redirect a result to a finding.
func (s *ExplorationStore) RecordFindingFollowUpRetestResult(ctx context.Context, intentID int64, verdict, summary, evidence string) error {
	verdict, summary, evidence, err := validateFindingFollowUpRetestResult(verdict, summary, evidence)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE finding_retests r SET
		status='running', started_at=COALESCE(started_at,now()), verdict=$3, summary=$4, evidence=$5
	FROM findings f, exploration_nodes intent, exploration_edges edge
	WHERE r.source_intent_id=$1 AND r.finding_id=f.id
	  AND intent.id=$1 AND intent.exploration_id=$2 AND intent.kind='intent' AND intent.state='running'
	  AND edge.exploration_id=$2 AND edge.src_id=f.node_id AND edge.rel=$6 AND edge.dst_id=intent.id
	  AND f.status NOT IN ($7,$8,$9)
	  AND r.status IN ('pending','running')
	  AND (r.verdict='' OR (r.verdict=$3 AND r.summary=$4 AND r.evidence=$5))`,
		intentID, s.expID, verdict, summary, evidence, RelDerivedFrom,
		FindingFalsePositive, FindingDuplicate, FindingIgnored)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 1 {
		return nil
	}

	// Give the Worker a precise, non-leaky reason without accepting model-owned
	// finding ids. The broad not-running error remains the fail-closed fallback.
	var status string
	err = s.db.QueryRowContext(ctx, `SELECT f.status FROM finding_retests r
		JOIN findings f ON f.id=r.finding_id WHERE r.source_intent_id=$1`, intentID).Scan(&status)
	if err == nil && excludedFindingRetestStatus(status) {
		return ErrFindingRetestExcluded
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return ErrRetestNotRunning
}

// FinishFindingFollowUpRetest seals a formal Worker retest after the fenced
// intent state write succeeds. A normal Worker completion with no explicit
// verdict is recorded as failed, never guessed into reproduced/fixed.
func (s *ExplorationStore) FinishFindingFollowUpRetest(intentID int64, intentState, reason string) error {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM finding_retests WHERE source_intent_id=$1 AND status IN ('pending','running')`, intentID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // excluded finding or an already-sealed idempotent retry
	}
	if err != nil {
		return err
	}
	status := "failed"
	switch intentState {
	case "done":
		status = "completed"
	case "stopped":
		status = "stopped"
	case "blocked", "exhausted":
		status = "failed"
	default:
		return fmt.Errorf("intent state %q is not terminal", intentState)
	}
	if strings.TrimSpace(reason) == "" && status != "completed" {
		reason = "finding-linked Worker intent ended with state " + intentState
	}
	return s.db.FinishFindingRetest(id, status, reason)
}
