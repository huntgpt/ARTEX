package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MergeDuplicateFindingResult describes a lossless duplicate consolidation.
// The duplicate row remains addressable for audit/history, while all useful
// evidence is materialized onto the canonical row before it is marked duplicate.
type MergeDuplicateFindingResult struct {
	CanonicalID        int64 `json:"canonical_id,string"`
	DuplicateID        int64 `json:"duplicate_id,string"`
	AssetsAdded        int   `json:"assets_added"`
	TrafficAdded       int   `json:"traffic_added"`
	ArtifactsAdded     int   `json:"artifacts_added"`
	EvidenceLinksAdded int   `json:"evidence_links_added"`
}

type mergeFindingRow struct {
	id                  int64
	taskID              int64
	nodeID              int64
	explorationID       int64
	vulnClass           string
	name                string
	severity            string
	summary             string
	evidence            string
	counterevidence     string
	confidenceRationale string
	verificationStatus  string
	verificationNote    string
	status              string
	reportState         string
	poeLevel            int
	assetIDs            []int64
}

// MergeDuplicateFinding consolidates two findings from the same task without
// deleting either record. Evidence text, assets, traffic snapshots and audited
// artifact lineage are attached to canonicalID first. duplicateID is then
// marked duplicate in both triage and report workflow state.
//
// The caller deliberately chooses the canonical record. Prefer the earliest
// root-cause record: later evidence nodes are descendants of it, which permits
// direct bounded evidence links without introducing graph cycles.
func (d *DB) MergeDuplicateFinding(ctx context.Context, canonicalID, duplicateID int64, promoteDuplicatePresentation bool) (MergeDuplicateFindingResult, error) {
	out := MergeDuplicateFindingResult{CanonicalID: canonicalID, DuplicateID: duplicateID}
	if canonicalID <= 0 || duplicateID <= 0 || canonicalID == duplicateID {
		return out, errors.New("canonical_id and duplicate_id must be distinct positive finding ids")
	}

	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var canonicalTaskID, duplicateTaskID sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT task_id FROM findings WHERE id=$1`, canonicalID).Scan(&canonicalTaskID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("canonical finding %d does not exist", canonicalID)
			}
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT task_id FROM findings WHERE id=$1`, duplicateID).Scan(&duplicateTaskID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("duplicate finding %d does not exist", duplicateID)
			}
			return err
		}
		if !canonicalTaskID.Valid || !duplicateTaskID.Valid || canonicalTaskID.Int64 != duplicateTaskID.Int64 {
			return errors.New("findings must belong to the same live task")
		}
		if err := LockTaskEvidenceTx(tx, canonicalTaskID.Int64); err != nil {
			return err
		}

		rows, err := tx.QueryContext(ctx, `SELECT f.id,f.task_id,f.node_id,t.exploration_id,
			f.vulnclass,f.name,f.severity,f.summary,f.evidence,f.counterevidence,f.confidence_rationale,
			f.verification_status,f.verification_note,COALESCE(f.status,'pending'),COALESCE(f.report_state,'none'),
			f.poe_level,f.asset_ids
			FROM findings f JOIN tasks t ON t.id=f.task_id
			WHERE f.id IN ($1,$2) ORDER BY f.id FOR UPDATE OF f`, canonicalID, duplicateID)
		if err != nil {
			return err
		}
		byID := map[int64]*mergeFindingRow{}
		for rows.Next() {
			var row mergeFindingRow
			var raw []byte
			if err := rows.Scan(&row.id, &row.taskID, &row.nodeID, &row.explorationID,
				&row.vulnClass, &row.name, &row.severity, &row.summary, &row.evidence,
				&row.counterevidence, &row.confidenceRationale, &row.verificationStatus,
				&row.verificationNote, &row.status, &row.reportState, &row.poeLevel, &raw); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(raw, &row.assetIDs)
			byID[row.id] = &row
		}
		if err := rows.Close(); err != nil {
			return err
		}
		canonical, duplicate := byID[canonicalID], byID[duplicateID]
		if canonical == nil || duplicate == nil {
			return errors.New("one or both findings are unavailable for merge")
		}
		if canonical.taskID != duplicate.taskID || canonical.explorationID != duplicate.explorationID {
			return errors.New("findings must belong to the same task exploration")
		}
		if canonical.status == FindingDuplicate {
			return fmt.Errorf("canonical finding %d is itself marked duplicate", canonicalID)
		}
		if normalizeFindingText(canonical.vulnClass) != normalizeFindingText(duplicate.vulnClass) {
			return fmt.Errorf("finding vulnerability classes are incompatible: %q and %q", canonical.vulnClass, duplicate.vulnClass)
		}
		duplicateMarker := fmt.Sprintf("Duplicate of canonical finding #%d; evidence, assets and provenance were merged without deleting this audit record.", canonicalID)
		if duplicate.status == FindingDuplicate && duplicate.reportState == FindingReportDuplicate &&
			strings.Contains(duplicate.confidenceRationale, duplicateMarker) {
			return nil
		}

		assets := unionInt64(canonical.assetIDs, duplicate.assetIDs)
		out.AssetsAdded = len(assets) - len(unionInt64(nil, canonical.assetIDs))
		assetsRaw, _ := json.Marshal(assets)
		evidence, evidenceChanged := mergeFindingEvidence(canonical.evidence, duplicate.evidence)
		counter, counterChanged := mergeFindingEvidence(canonical.counterevidence, duplicate.counterevidence)
		rationale, rationaleChanged := mergeFindingEvidence(canonical.confidenceRationale, duplicate.confidenceRationale)

		name, summary, severity := canonical.name, canonical.summary, canonical.severity
		if promoteDuplicatePresentation {
			if strings.TrimSpace(duplicate.name) != "" {
				name = duplicate.name
			}
			if strings.TrimSpace(duplicate.summary) != "" {
				summary = duplicate.summary
			}
			if severityRank(duplicate.severity) > severityRank(severity) {
				severity = duplicate.severity
			}
		}
		verificationStatus, verificationNote := canonical.verificationStatus, canonical.verificationNote
		if duplicate.verificationStatus == VerificationVerified && verificationStatus != VerificationVerified {
			verificationStatus, verificationNote = VerificationVerified, ""
		}
		poe := canonical.poeLevel
		if duplicate.poeLevel > poe {
			poe = duplicate.poeLevel
		}

		changed := evidenceChanged || counterChanged || rationaleChanged || out.AssetsAdded > 0 ||
			name != canonical.name || summary != canonical.summary || severity != canonical.severity ||
			verificationStatus != canonical.verificationStatus || verificationNote != canonical.verificationNote || poe != canonical.poeLevel
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET asset_ids=$2,evidence=$3,counterevidence=$4,
			confidence_rationale=$5,name=$6,summary=$7,severity=$8,verification_status=$9,
			verification_note=$10,poe_level=$11 WHERE id=$1`, canonicalID, string(assetsRaw), evidence,
			counter, rationale, name, summary, severity, verificationStatus, verificationNote, poe); err != nil {
			return err
		}
		for _, assetID := range assets {
			res, err := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id)
				VALUES($1,$2) ON CONFLICT DO NOTHING`, canonical.nodeID, assetID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				changed = true
			}
		}

		// Preserve exact audited artifact provenance. The direct finding-to-intent
		// edge is the bounded lineage contract used by findingArtifacts; only
		// intent nodes already attested in the duplicate's immutable ledger qualify.
		artifactRows, err := tx.QueryContext(ctx, `SELECT DISTINCT a.node_id
			FROM finding_artifact_evidence fe
			JOIN activity a ON a.id=fe.activity_id
			JOIN exploration_nodes n ON n.id=a.node_id
			WHERE fe.finding_id=$1 AND a.node_id IS NOT NULL
			  AND n.exploration_id=$2 AND n.kind='intent'`, duplicateID, canonical.explorationID)
		if err != nil {
			return err
		}
		var evidenceNodes []int64
		for artifactRows.Next() {
			var nodeID int64
			if err := artifactRows.Scan(&nodeID); err != nil {
				artifactRows.Close()
				return err
			}
			evidenceNodes = append(evidenceNodes, nodeID)
		}
		if err := artifactRows.Close(); err != nil {
			return err
		}
		for _, nodeID := range evidenceNodes {
			var wouldCycle bool
			if err := tx.QueryRowContext(ctx, `WITH RECURSIVE reach(id) AS (
				SELECT $1::bigint UNION SELECT e.dst_id FROM exploration_edges e
				JOIN reach r ON r.id=e.src_id WHERE e.exploration_id=$2)
				SELECT EXISTS(SELECT 1 FROM reach WHERE id=$3)`, nodeID, canonical.explorationID, canonical.nodeID).Scan(&wouldCycle); err != nil {
				return err
			}
			if wouldCycle {
				return fmt.Errorf("artifact evidence node %d would create a canonical finding lineage cycle", nodeID)
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
				VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, canonical.explorationID, canonical.nodeID, RelDerivedFrom, nodeID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				out.EvidenceLinksAdded += int(n)
				changed = true
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO finding_artifact_evidence(finding_id,sha256,activity_id)
			SELECT $1,sha256,activity_id FROM finding_artifact_evidence WHERE finding_id=$2
			ON CONFLICT(finding_id,sha256) DO NOTHING`, canonicalID, duplicateID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			out.ArtifactsAdded = int(n)
			changed = true
		}

		var nextPosition int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(position)+1,0)
			FROM finding_traffic_bindings WHERE finding_id=$1`, canonicalID).Scan(&nextPosition); err != nil {
			return err
		}
		trafficRows, err := tx.QueryContext(ctx, `SELECT snapshot_id,role,note FROM finding_traffic_bindings
			WHERE finding_id=$1 ORDER BY position,id`, duplicateID)
		if err != nil {
			return err
		}
		type trafficBinding struct{ snapshotID, role, note string }
		var traffic []trafficBinding
		for trafficRows.Next() {
			var binding trafficBinding
			if err := trafficRows.Scan(&binding.snapshotID, &binding.role, &binding.note); err != nil {
				trafficRows.Close()
				return err
			}
			traffic = append(traffic, binding)
		}
		if err := trafficRows.Close(); err != nil {
			return err
		}
		// database/sql transactions use one connection. Finish and close the
		// SELECT before issuing INSERTs; interleaving them leaves lib/pq with an
		// unread result set and surfaces as the misleading driver.ErrBadConn.
		for _, binding := range traffic {
			res, err := tx.ExecContext(ctx, `INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,role,note,position)
				VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id,snapshot_id) DO NOTHING`, canonicalID, binding.snapshotID, binding.role, binding.note, nextPosition)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				out.TrafficAdded += int(n)
				nextPosition++
				changed = true
			}
		}

		// Preserve goal proof continuity before the duplicate is terminalized.
		if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
			SELECT exploration_id,$1,rel,dst_id FROM exploration_edges
			WHERE exploration_id=$2 AND src_id=$3 AND rel=$4 ON CONFLICT DO NOTHING`,
			canonical.nodeID, canonical.explorationID, duplicate.nodeID, RelProves); err != nil {
			return err
		}

		duplicateRationale, _ := mergeFindingEvidence(duplicate.confidenceRationale, duplicateMarker)
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=$2,report_state=$3,confidence_rationale=$4 WHERE id=$1`,
			duplicateID, FindingDuplicate, FindingReportDuplicate, duplicateRationale); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=
			jsonb_set(jsonb_set(payload,'{status}',to_jsonb($1::text),true),'{report_state}',to_jsonb($2::text),true)
			WHERE id=$3`, FindingDuplicate, FindingReportDuplicate, duplicate.nodeID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=
			jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(payload,
			'{evidence,poc}',to_jsonb($1::text),true),'{name}',to_jsonb($2::text),true),
			'{summary}',to_jsonb($3::text),true),'{severity}',to_jsonb($4::text),true),
			'{status}',to_jsonb(COALESCE(payload->>'status','pending')),true)
			WHERE id=$5`, evidence, name, summary, severity, canonical.nodeID); err != nil {
			return err
		}
		if changed {
			if err := bumpEvidenceVersionTx(tx, canonicalID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
