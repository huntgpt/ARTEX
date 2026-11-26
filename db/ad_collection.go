package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/ad"
)

var ErrADRunStateConflict = errors.New("AD collection run state changed concurrently")

type ADCollectionRun struct {
	ID            int64                  `json:"id"`
	ExplorationID int64                  `json:"exploration_id"`
	Collector     string                 `json:"collector"`
	Mode          string                 `json:"mode"`
	State         ad.RunState            `json:"state"`
	RequestedBy   string                 `json:"requested_by"`
	ApprovedBy    string                 `json:"approved_by"`
	BlockerReason string                 `json:"blocker_reason,omitempty"`
	ErrorDetail   string                 `json:"error_detail,omitempty"`
	Records       int                    `json:"records"`
	Entities      int                    `json:"entities"`
	Edges         int                    `json:"edges"`
	Skipped       int                    `json:"skipped"`
	OverCap       int                    `json:"over_cap"`
	Truncated     bool                   `json:"truncated"`
	CreatedAt     time.Time              `json:"created_at"`
	ApprovedAt    *time.Time             `json:"approved_at,omitempty"`
	StartedAt     *time.Time             `json:"started_at,omitempty"`
	FinishedAt    *time.Time             `json:"finished_at,omitempty"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Artifacts     []ADCollectionArtifact `json:"artifacts,omitempty"`
}

type ADCollectionArtifact struct {
	ID          int64     `json:"id"`
	RunID       int64     `json:"run_id"`
	Kind        string    `json:"kind"`
	LogicalPath string    `json:"logical_path"`
	SHA256      string    `json:"sha256"`
	ByteSize    int64     `json:"byte_size"`
	State       string    `json:"state"`
	ErrorDetail string    `json:"error_detail,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

var validADCollectors = map[string]bool{
	"sharphound": true, "bloodhound-python": true, "adexplorer": true,
	"ldap": true, "operator-upload": true,
}
var validADModes = map[string]bool{"offline-import": true, "remote": true, "on-host": true}

func (d *DB) CreateADCollectionRun(ctx context.Context, explorationID int64, collector, mode, requestedBy string) (*ADCollectionRun, error) {
	collector = strings.ToLower(strings.TrimSpace(collector))
	mode = strings.ToLower(strings.TrimSpace(mode))
	if !validADCollectors[collector] {
		return nil, fmt.Errorf("unsupported AD collector %q", collector)
	}
	if !validADModes[mode] {
		return nil, fmt.Errorf("unsupported AD collection mode %q", mode)
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO ad_collection_runs(exploration_id,collector,mode,state,requested_by)
VALUES($1,$2,$3,$4,$5) RETURNING id`, explorationID, collector, mode, ad.RunQueued, utf8Clean(requestedBy)).Scan(&id)
	if err != nil {
		return nil, err
	}
	return d.ADCollectionRun(ctx, explorationID, id)
}

func (d *DB) TransitionADCollectionRun(ctx context.Context, explorationID, runID int64, to ad.RunState, actor, reason string) (*ADCollectionRun, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var from ad.RunState
	if err := tx.QueryRowContext(ctx, `SELECT state FROM ad_collection_runs WHERE id=$1 AND exploration_id=$2 FOR UPDATE`, runID, explorationID).Scan(&from); err != nil {
		return nil, err
	}
	if err := ad.ValidateTransition(from, to); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrADRunStateConflict, err)
	}
	approvedBy := ""
	if to == ad.RunApproved {
		approvedBy = utf8Clean(actor)
	}
	_, err = tx.ExecContext(ctx, `
UPDATE ad_collection_runs SET state=$1,
 approved_by=CASE WHEN $1='approved' THEN $2 ELSE approved_by END,
 approved_at=CASE WHEN $1='approved' THEN now() ELSE approved_at END,
 started_at=CASE WHEN $1 IN ('running','ingesting') AND started_at IS NULL THEN now() ELSE started_at END,
 finished_at=CASE WHEN $1 IN ('complete','partial','rejected','failed','cancelled') THEN now() ELSE finished_at END,
 blocker_reason=CASE WHEN $1 IN ('rejected','failed','cancelled') THEN $3 ELSE blocker_reason END,
 updated_at=now() WHERE id=$4 AND exploration_id=$5`, to, approvedBy, utf8Clean(reason), runID, explorationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.ADCollectionRun(ctx, explorationID, runID)
}

func (d *DB) FinishADCollectionRun(ctx context.Context, explorationID, runID int64, state ad.RunState, result ADIngestResult, errorDetail string) error {
	if state != ad.RunComplete && state != ad.RunPartial && state != ad.RunFailed {
		return fmt.Errorf("invalid AD collection terminal state %q", state)
	}
	res, err := d.ExecContext(ctx, `
UPDATE ad_collection_runs SET state=$1,records=$2,entities=$3,edges=$4,skipped=$5,over_cap=$6,truncated=$7,
 error_detail=$8,finished_at=now(),updated_at=now()
WHERE id=$9 AND exploration_id=$10 AND state='ingesting'`, state, result.Records, result.EntitiesUpserted,
		result.EdgesUpserted, result.Skipped, result.OverCap, result.Truncated, utf8Clean(errorDetail), runID, explorationID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrADRunStateConflict
	}
	return nil
}

func (d *DB) AddADCollectionArtifact(ctx context.Context, explorationID, runID int64, artifact ADCollectionArtifact) error {
	if len(artifact.SHA256) != 64 || artifact.ByteSize < 0 {
		return errors.New("invalid AD collection artifact digest or size")
	}
	_, err := d.ExecContext(ctx, `
INSERT INTO ad_collection_artifacts(run_id,kind,logical_path,sha256,byte_size,state,error_detail)
SELECT $2,$3,$4,$5,$6,$7,$8 FROM ad_collection_runs WHERE id=$2 AND exploration_id=$1
ON CONFLICT(run_id,sha256) DO UPDATE SET state=EXCLUDED.state,error_detail=EXCLUDED.error_detail`,
		explorationID, runID, artifact.Kind, utf8Clean(artifact.LogicalPath), artifact.SHA256,
		artifact.ByteSize, artifact.State, utf8Clean(artifact.ErrorDetail))
	return err
}

func scanADCollectionRun(scanner interface{ Scan(...any) error }) (*ADCollectionRun, error) {
	var run ADCollectionRun
	err := scanner.Scan(&run.ID, &run.ExplorationID, &run.Collector, &run.Mode, &run.State,
		&run.RequestedBy, &run.ApprovedBy, &run.BlockerReason, &run.ErrorDetail,
		&run.Records, &run.Entities, &run.Edges, &run.Skipped, &run.OverCap, &run.Truncated,
		&run.CreatedAt, &run.ApprovedAt, &run.StartedAt, &run.FinishedAt, &run.UpdatedAt)
	return &run, err
}

const adRunColumns = `id,exploration_id,collector,mode,state,requested_by,approved_by,blocker_reason,error_detail,records,entities,edges,skipped,over_cap,truncated,created_at,approved_at,started_at,finished_at,updated_at`

func (d *DB) ADCollectionRun(ctx context.Context, explorationID, runID int64) (*ADCollectionRun, error) {
	run, err := scanADCollectionRun(d.QueryRowContext(ctx, `SELECT `+adRunColumns+` FROM ad_collection_runs WHERE exploration_id=$1 AND id=$2`, explorationID, runID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	run.Artifacts, err = d.ADCollectionArtifacts(ctx, runID)
	return run, err
}

func (d *DB) ListADCollectionRuns(ctx context.Context, explorationID int64) ([]ADCollectionRun, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+adRunColumns+` FROM ad_collection_runs WHERE exploration_id=$1 ORDER BY id DESC`, explorationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ADCollectionRun
	for rows.Next() {
		run, err := scanADCollectionRun(rows)
		if err != nil {
			return nil, err
		}
		run.Artifacts, err = d.ADCollectionArtifacts(ctx, run.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, *run)
	}
	return out, rows.Err()
}

func (d *DB) ADCollectionArtifacts(ctx context.Context, runID int64) ([]ADCollectionArtifact, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,run_id,kind,logical_path,sha256,byte_size,state,error_detail,created_at FROM ad_collection_artifacts WHERE run_id=$1 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ADCollectionArtifact
	for rows.Next() {
		var artifact ADCollectionArtifact
		if err := rows.Scan(&artifact.ID, &artifact.RunID, &artifact.Kind, &artifact.LogicalPath, &artifact.SHA256, &artifact.ByteSize, &artifact.State, &artifact.ErrorDetail, &artifact.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, artifact)
	}
	return out, rows.Err()
}

func (s *ExplorationStore) CreateADCollectionRun(ctx context.Context, collector, mode, requestedBy string) (*ADCollectionRun, error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return nil, errors.New("AD collection run requires an exploration")
	}
	return s.db.CreateADCollectionRun(ctx, s.expID, collector, mode, requestedBy)
}

func (s *ExplorationStore) TransitionADCollectionRun(ctx context.Context, runID int64, to ad.RunState, actor, reason string) (*ADCollectionRun, error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return nil, errors.New("AD collection run requires an exploration")
	}
	return s.db.TransitionADCollectionRun(ctx, s.expID, runID, to, actor, reason)
}

func (s *ExplorationStore) FinishADCollectionRun(ctx context.Context, runID int64, state ad.RunState, result ADIngestResult, errorDetail string) error {
	if s == nil || s.db == nil || s.expID <= 0 {
		return errors.New("AD collection run requires an exploration")
	}
	return s.db.FinishADCollectionRun(ctx, s.expID, runID, state, result, errorDetail)
}

func (s *ExplorationStore) AddADCollectionArtifact(ctx context.Context, runID int64, artifact ADCollectionArtifact) error {
	if s == nil || s.db == nil || s.expID <= 0 {
		return errors.New("AD collection run requires an exploration")
	}
	return s.db.AddADCollectionArtifact(ctx, s.expID, runID, artifact)
}

func (s *ExplorationStore) ADCollectionRun(ctx context.Context, runID int64) (*ADCollectionRun, error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return nil, errors.New("AD collection run requires an exploration")
	}
	return s.db.ADCollectionRun(ctx, s.expID, runID)
}
