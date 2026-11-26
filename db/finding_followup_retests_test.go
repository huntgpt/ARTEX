package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type followUpRetestFixture struct {
	d             *DB
	task          *Task
	store         *ExplorationStore
	findingID     int64
	findingNodeID int64
}

func newFollowUpRetestFixture(t *testing.T) followUpRetestFixture {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	task, err := d.CreateTask(fmt.Sprintf("formal follow-up retest %d", time.Now().UnixNano()), "verify finding", nil, 0, 0)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	nodeID, err := store.AddNode(KindFinding, map[string]any{"summary": "source finding"}, 8, "confirmed", "worker", nil)
	if err != nil {
		_ = d.DeleteTask(task.ID)
		d.Close()
		t.Fatal(err)
	}
	findingID, err := d.AddFinding(task.ID, nodeID, "test", "formal follow-up", SeverityHigh, "summary", "original evidence", "worker", nil)
	if err != nil {
		_ = d.DeleteTask(task.ID)
		d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFinding(findingID)
		_ = d.DeleteTask(task.ID)
		d.Close()
	})
	return followUpRetestFixture{d: d, task: task, store: store, findingID: findingID, findingNodeID: nodeID}
}

func (f followUpRetestFixture) addIntent(t *testing.T) int64 {
	t.Helper()
	id, _, err := f.store.AddFindingFollowUpIntent(f.findingID, f.findingNodeID, "validate the original finding", Activity{
		Worker: "system", Kind: "text", Summary: "finding follow-up", Detail: "validate the original finding",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFindingFollowUpRetestMaterializesWithExactProvenance(t *testing.T) {
	f := newFollowUpRetestFixture(t)
	if _, err := f.d.SetFindingStatus(f.findingID, FindingInProgress); err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetFindingVerification(f.findingID, VerificationBlocked, 2, "needs independent evidence"); err != nil {
		t.Fatal(err)
	}
	intentID := f.addIntent(t)

	rows, err := f.d.ListFindingRetests(f.findingID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("formal history: rows=%+v err=%v", rows, err)
	}
	r := rows[0]
	if r.SourceIntentID == nil || *r.SourceIntentID != intentID || r.ConversationID != nil || r.Status != "pending" {
		t.Fatalf("pending Worker retest provenance: %+v", r)
	}
	var snapshot string
	if err := f.d.QueryRow(`SELECT snapshot::text FROM finding_retests WHERE id=$1`, r.ID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snapshot, fmt.Sprintf(`"source_intent_id": %d`, intentID)) &&
		!strings.Contains(snapshot, fmt.Sprintf(`"source_intent_id":%d`, intentID)) {
		t.Fatalf("snapshot lacks source intent provenance: %s", snapshot)
	}
	if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "reproduced", "still reproducible", "actual bounded validation evidence"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatalf("pending intent accepted result: %v", err)
	}
	if _, err := f.store.ClaimIntentToken(intentID, "worker-1"); err != nil {
		t.Fatal(err)
	}

	otherExpID, err := f.d.CreateExploration("wrong exploration", "provenance rejection")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.d.Exec(`DELETE FROM explorations WHERE id=$1`, otherExpID) })
	if err := f.d.Exploration(otherExpID).RecordFindingFollowUpRetestResult(t.Context(), intentID, "reproduced", "still reproducible", "actual bounded validation evidence"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatalf("wrong exploration accepted result: %v", err)
	}

	if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "reproduced", "still reproducible", "actual bounded validation evidence"); err != nil {
		t.Fatal(err)
	}
	// An exact tool retry is idempotent; a conflicting conclusion cannot replace it.
	if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "reproduced", "still reproducible", "actual bounded validation evidence"); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "fixed", "different", "different proof"); !errors.Is(err, ErrRetestNotRunning) {
		t.Fatalf("conflicting verdict replaced staged result: %v", err)
	}
	if err := f.store.FinishFindingFollowUpRetest(intentID, "done", ""); err != nil {
		t.Fatal(err)
	}

	rows, err = f.d.ListFindingRetests(f.findingID)
	if err != nil || len(rows) != 1 || rows[0].Status != "completed" || rows[0].Verdict != "reproduced" || rows[0].Evidence != "actual bounded validation evidence" {
		t.Fatalf("sealed formal history: rows=%+v err=%v", rows, err)
	}
	finding, err := f.d.GetFinding(f.findingID)
	if err != nil || finding.Status != FindingInProgress || finding.VerificationStatus != VerificationBlocked || finding.PoELevel != 2 {
		t.Fatalf("model verdict promoted finding: finding=%+v err=%v", finding, err)
	}
}

func TestFindingFollowUpRetestTerminalFailuresRemainVisible(t *testing.T) {
	for _, tc := range []struct {
		name, intentState, wantStatus, wantError string
	}{
		{"done_without_verdict", "done", "failed", "did not save"},
		{"blocked", "blocked", "failed", "blocked"},
		{"exhausted", "exhausted", "failed", "exhausted"},
		{"stopped", "stopped", "stopped", "stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFollowUpRetestFixture(t)
			intentID := f.addIntent(t)
			if _, err := f.store.ClaimIntentToken(intentID, "worker"); err != nil {
				t.Fatal(err)
			}
			if err := f.store.FinishFindingFollowUpRetest(intentID, tc.intentState, ""); err != nil {
				t.Fatal(err)
			}
			rows, err := f.d.ListFindingRetests(f.findingID)
			if err != nil || len(rows) != 1 || rows[0].Status != tc.wantStatus || !strings.Contains(strings.ToLower(rows[0].Error), tc.wantError) {
				t.Fatalf("terminal history: rows=%+v err=%v", rows, err)
			}
		})
	}
}

func TestFindingFollowUpRetestExcludesNonActionableDispositions(t *testing.T) {
	for _, status := range []string{FindingFalsePositive, FindingDuplicate, FindingIgnored} {
		t.Run(status, func(t *testing.T) {
			f := newFollowUpRetestFixture(t)
			if _, err := f.d.SetFindingStatus(f.findingID, status); err != nil {
				t.Fatal(err)
			}
			intentID := f.addIntent(t)
			var count int
			if err := f.d.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, f.findingID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("%s finding received %d formal retests", status, count)
			}
			if _, err := f.store.ClaimIntentToken(intentID, "worker"); err != nil {
				t.Fatal(err)
			}
			if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "reproduced", "stale result", "stale evidence"); !errors.Is(err, ErrRetestNotRunning) {
				t.Fatalf("excluded finding accepted result: %v", err)
			}
		})
	}
}

func TestFindingFollowUpRetestActiveManualRunRollsBackIntent(t *testing.T) {
	f := newFollowUpRetestFixture(t)
	r, _, _, err := f.d.CreateFindingRetest(t.Context(), f.findingID, "manual retest")
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err := f.d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, f.task.ExplorationID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.store.AddFindingFollowUpIntent(f.findingID, f.findingNodeID, "must not leak", Activity{Worker: "system", Kind: "text", Summary: "must roll back"})
	if !errors.Is(err, ErrFindingRetestActive) {
		t.Fatalf("want ErrFindingRetestActive, got %v", err)
	}
	var after int
	if err := f.d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, f.task.ExplorationID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("rejected follow-up leaked graph node: %d -> %d", before, after)
	}
	if err := f.d.FinishFindingRetest(r.ID, "stopped", "test cleanup"); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverFindingFollowUpRetestsUsesPersistedIntentState(t *testing.T) {
	f := newFollowUpRetestFixture(t)
	intentID := f.addIntent(t)
	if _, err := f.store.ClaimIntentToken(intentID, "worker"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordFindingFollowUpRetestResult(t.Context(), intentID, "inconclusive", "blocked on prerequisite", "operator-controlled prerequisite unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetIntentState(intentID, "blocked"); err != nil {
		t.Fatal(err)
	}
	if err := f.d.RecoverFindingRetests(); err != nil {
		t.Fatal(err)
	}
	rows, err := f.d.ListFindingRetests(f.findingID)
	if err != nil || len(rows) != 1 || rows[0].Status != "failed" || !strings.Contains(rows[0].Error, "blocked") {
		t.Fatalf("recovered formal history: rows=%+v err=%v", rows, err)
	}
}
