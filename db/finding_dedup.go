package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// findingDedupCandidate is deliberately task-local. Cross-task findings may be
// useful to the advisory LLM, but silently mutating another task's finding would
// make task provenance and report ownership ambiguous.
type findingDedupCandidate struct {
	FindingID           int64
	NodeID              int64
	VulnClass           string
	Name                string
	Summary             string
	Evidence            string
	Counterevidence     string
	ConfidenceRationale string
	AssetIDs            []int64
	Status              string
}

// DeterministicFindingMatch is the read-only fast path used before advisory LLM
// triage. RecordFindingTx repeats the decision under the task lock, so this hint
// cannot introduce a check/write race.
func (s *ExplorationStore) DeterministicFindingMatch(ctx context.Context, in RecordFindingInput) (findingID, nodeID int64, ok bool, err error) {
	if s == nil || in.TaskID <= 0 || in.SkipDuplicateCheck {
		return 0, 0, false, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,node_id,vulnclass,name,summary,evidence,
		counterevidence,confidence_rationale,asset_ids,COALESCE(status,'pending')
		FROM findings WHERE task_id=$1 AND node_id IS NOT NULL ORDER BY id ASC`, in.TaskID)
	if err != nil {
		return 0, 0, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var c findingDedupCandidate
		var raw []byte
		if err := rows.Scan(&c.FindingID, &c.NodeID, &c.VulnClass, &c.Name, &c.Summary,
			&c.Evidence, &c.Counterevidence, &c.ConfidenceRationale, &raw, &c.Status); err != nil {
			return 0, 0, false, err
		}
		_ = json.Unmarshal(raw, &c.AssetIDs)
		if automaticFindingDedupStatus(c.Status) && deterministicFindingMatch(in, c) {
			return c.FindingID, c.NodeID, true, nil
		}
	}
	return 0, 0, false, rows.Err()
}

// reuseExistingFindingTx deterministically extends an existing same-task finding
// before the optional LLM triage path can fail open. Automatic matching is
// intentionally conservative: a non-empty normalized class and name and the
// complete non-empty asset set must match. An explicit id has to be a live
// finding in the same task whose vulnerability class is compatible with the
// proposed extension. This prevents a stale or hallucinated id from merging an
// unrelated defect while still allowing a follow-up to refine the finding name
// and affected asset set.
func reuseExistingFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, bool, error) {
	if in.TaskID <= 0 {
		if in.ExistingFindingID > 0 {
			return nil, false, errors.New("existing_finding_id requires a task context")
		}
		return nil, false, nil
	}

	rows, err := tx.QueryContext(ctx, `SELECT id,node_id,vulnclass,name,summary,evidence,
		counterevidence,confidence_rationale,asset_ids,COALESCE(status,'pending')
		FROM findings
		WHERE task_id=$1 AND node_id IS NOT NULL
		ORDER BY id ASC FOR UPDATE`, in.TaskID)
	if err != nil {
		return nil, false, err
	}
	var candidates []findingDedupCandidate
	for rows.Next() {
		var c findingDedupCandidate
		var raw []byte
		if err := rows.Scan(&c.FindingID, &c.NodeID, &c.VulnClass, &c.Name, &c.Summary,
			&c.Evidence, &c.Counterevidence, &c.ConfidenceRationale, &raw, &c.Status); err != nil {
			rows.Close()
			return nil, false, err
		}
		_ = json.Unmarshal(raw, &c.AssetIDs)
		candidates = append(candidates, c)
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}

	var match *findingDedupCandidate
	if in.ExistingFindingID > 0 {
		for i := range candidates {
			if candidates[i].FindingID == in.ExistingFindingID {
				// Explicit extension is operator/agent intent and is allowed for
				// terminal canonical records (for example, adding retest evidence to
				// a fixed finding). A duplicate row is never canonical.
				if candidates[i].Status == FindingDuplicate {
					return nil, false, fmt.Errorf("existing_finding_id %d is itself marked duplicate; reference its canonical finding", in.ExistingFindingID)
				}
				if !explicitFindingExtensionCompatible(in, candidates[i]) {
					return nil, false, fmt.Errorf("existing_finding_id %d has vulnerability class %q, which is incompatible with extension class %q", in.ExistingFindingID, candidates[i].VulnClass, in.VulnClass)
				}
				match = &candidates[i]
				break
			}
		}
		if match == nil {
			return nil, false, fmt.Errorf("existing_finding_id %d must reference a finding in task %d", in.ExistingFindingID, in.TaskID)
		}
	} else if !in.SkipDuplicateCheck {
		for i := range candidates {
			if automaticFindingDedupStatus(candidates[i].Status) && deterministicFindingMatch(in, candidates[i]) {
				match = &candidates[i]
				break // oldest matching row is the canonical record
			}
		}
	}
	if match == nil {
		return nil, false, nil
	}

	oldAssets := unionInt64(nil, match.AssetIDs)
	assets := unionInt64(match.AssetIDs, in.AssetIDs)
	assetsChanged := len(assets) != len(oldAssets)
	evidence, evidenceChanged := mergeFindingEvidence(match.Evidence, in.Evidence)
	counter, counterChanged := mergeFindingEvidence(match.Counterevidence, in.Counterevidence)
	rationale, rationaleChanged := mergeFindingEvidence(match.ConfidenceRationale, in.ConfidenceRationale)
	assetsRaw, _ := json.Marshal(assets)
	if _, err := tx.ExecContext(ctx, `UPDATE findings
		SET asset_ids=$2,evidence=$3,counterevidence=$4,confidence_rationale=$5
		WHERE id=$1`, match.FindingID, string(assetsRaw), evidence, counter, rationale); err != nil {
		return nil, false, err
	}
	anchorAdded := false
	for _, assetID := range assets {
		if assetID <= 0 {
			continue
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id)
			VALUES($1,$2) ON CONFLICT DO NOTHING`, match.NodeID, assetID)
		if err != nil {
			return nil, false, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, false, err
		} else if n > 0 {
			anchorAdded = true
		}
	}
	followupAdded := false
	if in.IntentID > 0 {
		// The canonical finding keeps exactly one producer (the original
		// intent --yields--> finding). A revalidation is follow-up lineage and
		// uses finding --derived_from--> intent; adding another yields edge makes
		// the producer nondeterministic and can create a cycle with an existing
		// follow-up edge.
		var originalProducer bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM exploration_edges
			WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
			in.ExplorationID, in.IntentID, RelYields, match.NodeID).Scan(&originalProducer); err != nil {
			return nil, false, err
		}
		if !originalProducer {
			res, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
				VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, in.ExplorationID, match.NodeID, RelDerivedFrom, in.IntentID)
			if err != nil {
				return nil, false, err
			}
			if n, err := res.RowsAffected(); err != nil {
				return nil, false, err
			} else if n > 0 {
				followupAdded = true
			}
		}
	}
	if evidenceChanged {
		if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes
			SET payload=jsonb_set(payload,'{evidence,poc}',to_jsonb($1::text),true),
				content_version=content_version+1
			WHERE id=$2`, evidence, match.NodeID); err != nil {
			return nil, false, err
		}
	}
	// The report describes more than text: affected assets and bounded follow-up
	// lineage are report artifacts too. Mark it stale only when one of those facts
	// was actually added; an idempotent retry must not churn the version.
	if evidenceChanged || counterChanged || rationaleChanged || assetsChanged || anchorAdded || followupAdded {
		if err := bumpEvidenceVersionTx(tx, match.FindingID); err != nil {
			return nil, false, err
		}
	}
	if err := AddFindingTrafficTx(tx, match.FindingID, prepared); err != nil {
		return nil, false, err
	}
	traffic, err := FindingTrafficTx(tx, match.FindingID)
	if err != nil {
		return nil, false, err
	}
	return &RecordedFinding{FindingID: match.FindingID, NodeID: match.NodeID, Traffic: traffic, ReusedExisting: true}, true, nil
}

func deterministicFindingMatch(in RecordFindingInput, c findingDedupCandidate) bool {
	class := normalizeFindingText(in.VulnClass)
	name := normalizeFindingText(in.Name)
	if class == "" || name == "" || class != normalizeFindingText(c.VulnClass) || name != normalizeFindingText(c.Name) {
		return false
	}
	return identicalNonEmptyAssetSet(in.AssetIDs, c.AssetIDs)
}

// explicitFindingExtensionCompatible is deliberately narrower than trusting an
// explicit database id alone. report_finding requires vulnclass, so a non-empty
// canonical class is a stable semantic anchor even when a retest reasonably
// rephrases the finding name or adds a newly affected asset. Legacy records with
// an empty class remain extendable rather than becoming impossible to repair.
func explicitFindingExtensionCompatible(in RecordFindingInput, c findingDedupCandidate) bool {
	incoming, canonical := normalizeFindingText(in.VulnClass), normalizeFindingText(c.VulnClass)
	return incoming == "" || canonical == "" || incoming == canonical
}

// Automatic reuse must never hide fresh evidence under a terminal disposition.
// Explicit ExistingFindingID remains the deliberate path for extending such a
// record (for example, a retest of a fixed or risk-accepted issue).
func automaticFindingDedupStatus(status string) bool {
	switch status {
	case FindingPending, FindingInProgress, FindingConfirmed:
		return true
	default:
		return false
	}
}

func normalizeFindingText(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

func identicalNonEmptyAssetSet(a, b []int64) bool {
	a, b = unionInt64(nil, a), unionInt64(nil, b)
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func unionInt64(a, b []int64) []int64 {
	seen := map[int64]bool{}
	for _, ids := range [][]int64{a, b} {
		for _, id := range ids {
			if id > 0 {
				seen[id] = true
			}
		}
	}
	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func mergeFindingEvidence(old, add string) (string, bool) {
	old, add = strings.TrimSpace(old), strings.TrimSpace(add)
	if add == "" || normalizeFindingText(old) == normalizeFindingText(add) {
		return old, false
	}
	if old == "" {
		return add, true
	}
	return old + "\n\n--- Follow-up evidence ---\n" + add, true
}
