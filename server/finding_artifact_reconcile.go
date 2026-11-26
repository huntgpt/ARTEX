package server

import (
	"context"
	"log"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

// reconcilingFindingRecorder adds the missing link-time half of artifact
// materialization. Tool output commonly exists before report_finding creates
// the finding edge, so the activity-ingestion hook cannot map it yet.
type reconcilingFindingRecorder struct {
	server *Server
	store  *evidence.Store
}

func (r reconcilingFindingRecorder) Record(ctx context.Context, in db.RecordFindingInput, refs []db.TrafficRef) (*db.RecordedFinding, error) {
	out, err := r.store.Record(ctx, in, refs)
	if err != nil || out == nil {
		return out, err
	}
	if err := r.server.reconcileFindingArtifactEvidence(ctx, out.FindingID); err != nil {
		log.Printf("[finding-evidence] reconcile finding %d after report: %v", out.FindingID, err)
	}
	return out, nil
}

func (r reconcilingFindingRecorder) TrafficExists(ctx context.Context, trafficID string) (bool, error) {
	return r.store.TrafficExists(ctx, trafficID)
}

func (s *Server) findingRecorder() reconcilingFindingRecorder {
	return reconcilingFindingRecorder{server: s, store: s.evidenceStore()}
}

// reconcileFindingArtifactEvidence validates the current bounded lineage and
// materializes only immutable artifact digests. It is invoked at ingestion/link
// time and by the explicit startup legacy reconciliation, never by a GET.
func (s *Server) reconcileFindingArtifactEvidence(ctx context.Context, findingID int64) error {
	artifacts, err := s.findingArtifacts(findingID)
	if err != nil {
		return err
	}
	ledger := make([]db.FindingArtifactEvidence, 0, len(artifacts))
	for _, artifact := range artifacts {
		ledger = append(ledger, db.FindingArtifactEvidence{SHA256: artifact.SHA256, ActivityID: artifact.ActivityID})
	}
	_, _, err = s.m.pg.SyncFindingArtifactEvidence(ctx, findingID, ledger)
	return err
}

func (s *Server) reconcileActivityArtifactEvidence(task *Task, activity db.Activity) {
	if s == nil || s.m == nil || s.m.pg == nil || task == nil || task.Store == nil ||
		activity.NodeID == nil || activity.Kind != "tool_result" || activity.ToolUseID == "" {
		return
	}
	ids, err := task.Store.FindingIDsForEvidenceNode(*activity.NodeID)
	if err != nil {
		log.Printf("[finding-evidence] map activity %d: %v", activity.ID, err)
		return
	}
	for _, findingID := range ids {
		if err := s.reconcileFindingArtifactEvidence(context.Background(), findingID); err != nil {
			log.Printf("[finding-evidence] reconcile finding %d after activity %d: %v", findingID, activity.ID, err)
		}
	}
}

// reconcileLegacyFindingArtifactEvidence is the explicit migration path for
// artifacts ingested before the ledger existed. It runs once at startup after
// task stores are restored; ordinary artifact/traffic GETs remain read-only.
func (s *Server) reconcileLegacyFindingArtifactEvidence() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	rows, err := s.m.pg.Query(`SELECT id FROM findings WHERE task_id IS NOT NULL AND node_id IS NOT NULL ORDER BY id`)
	if err != nil {
		log.Printf("[finding-evidence] legacy reconciliation list: %v", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			log.Printf("[finding-evidence] legacy reconciliation scan: %v", err)
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		log.Printf("[finding-evidence] legacy reconciliation rows: %v", err)
		return
	}
	for _, id := range ids {
		ctx := s.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := s.reconcileFindingArtifactEvidence(ctx, id); err != nil {
			log.Printf("[finding-evidence] legacy finding %d: %v", id, err)
		}
	}
}
