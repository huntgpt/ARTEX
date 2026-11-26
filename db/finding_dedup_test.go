package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestDeterministicFindingMatchExactAndDistinctAssets(t *testing.T) {
	base := findingDedupCandidate{
		VulnClass: " Content Hosting / Brand Abuse ",
		Name:      "PTT Digital hostname serves gambling content from a historical backend",
		AssetIDs:  []int64{17, 9, 17},
	}
	exact := RecordFindingInput{
		VulnClass: "content-hosting brand abuse",
		Name:      "ptt digital hostname serves GAMBLING content from a historical backend",
		AssetIDs:  []int64{9, 17},
	}
	if !deterministicFindingMatch(exact, base) {
		t.Fatal("normalized #149/#151 pattern with the same complete asset set must match")
	}
	for _, tc := range []RecordFindingInput{
		{VulnClass: exact.VulnClass, Name: exact.Name, AssetIDs: []int64{9}},
		{VulnClass: exact.VulnClass, Name: exact.Name, AssetIDs: []int64{9, 18}},
		{VulnClass: exact.VulnClass, Name: exact.Name},
		{VulnClass: "credential exposure", Name: exact.Name, AssetIDs: []int64{9, 17}},
		{VulnClass: exact.VulnClass, Name: "different issue on the same host", AssetIDs: []int64{9, 17}},
	} {
		if deterministicFindingMatch(tc, base) {
			t.Fatalf("distinct finding was merged: %+v", tc)
		}
	}
}

func TestAutomaticFindingDedupStatusOnlyUsesActionableFindings(t *testing.T) {
	for _, status := range []string{FindingPending, FindingInProgress, FindingConfirmed} {
		if !automaticFindingDedupStatus(status) {
			t.Errorf("active status %q is not eligible", status)
		}
	}
	for _, status := range []string{
		FindingFalsePositive, FindingIgnored, FindingResolved, FindingFixed,
		FindingRiskAccepted, FindingDuplicate, "",
	} {
		if automaticFindingDedupStatus(status) {
			t.Errorf("terminal status %q is eligible for automatic reuse", status)
		}
	}
}

func openFindingDedupTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func findingDedupFixture(t *testing.T, d *DB, suffix string) (*Task, *ExplorationStore, int64) {
	t.Helper()
	task, err := d.CreateTask("finding dedup "+suffix, "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	assetID, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{
		Domain: fmt.Sprintf("finding-dedup-%d-%s.example", task.ID, suffix), TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFindingsByTask(task.ID)
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetID)
	})
	return task, d.Exploration(task.ExplorationID), assetID
}

func TestRecordFindingReusesExactSameTaskFinding(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetID := findingDedupFixture(t, d, "exact")
	intentA, err := es.AddIntent(map[string]any{"summary": "first observation"}, 1, []int64{assetID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intentB, err := es.AddIntent(map[string]any{"summary": "fresh revalidation"}, 1, []int64{assetID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	first, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, IntentID: intentA, VulnClass: "Content Hosting / Brand Abuse",
		Name:     "PTT Digital hostname serves gambling content from a historical backend",
		Severity: "high", Summary: "historical result", Evidence: "first proof", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, IntentID: intentB, VulnClass: " content-hosting brand abuse ",
		Name:     "ptt digital hostname serves GAMBLING content from a historical backend",
		Severity: "high", Summary: "fresh result", Evidence: "second proof", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReusedExisting || second.FindingID != first.FindingID || second.NodeID != first.NodeID {
		t.Fatalf("second report = %+v, first = %+v", second, first)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same-task finding count=%d err=%v, want 1", count, err)
	}
	var linked bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
		task.ExplorationID, first.NodeID, RelDerivedFrom, intentB).Scan(&linked); err != nil || !linked {
		t.Fatalf("follow-up intent was not linked to canonical finding: linked=%v err=%v", linked, err)
	}
	producers, err := es.FindingIntents()
	if err != nil {
		t.Fatal(err)
	}
	if len(producers) != 1 || producers[first.NodeID] != intentA {
		t.Fatalf("canonical producer changed after reuse: producers=%v, want node %d -> intent %d", producers, first.NodeID, intentA)
	}
	evidenceNodes, err := es.FindingEvidenceNodes(first.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	followupIncluded := false
	for _, n := range evidenceNodes {
		if n.ID == intentB {
			followupIncluded = true
			break
		}
	}
	if !followupIncluded {
		t.Fatalf("follow-up intent %d missing from canonical evidence lineage", intentB)
	}
	// A retry from the original producer must not add the reverse follow-up edge,
	// which would form intentA --yields--> finding --derived_from--> intentA.
	if _, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, IntentID: intentA, VulnClass: "content hosting brand abuse",
		Name:     "PTT Digital hostname serves gambling content from a historical backend",
		Severity: "high", Summary: "retry", AssetIDs: []int64{assetID},
	}); err != nil {
		t.Fatal(err)
	}
	var reverseProducerEdge bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
		task.ExplorationID, first.NodeID, RelDerivedFrom, intentA).Scan(&reverseProducerEdge); err != nil || reverseProducerEdge {
		t.Fatalf("reuse formed a producer cycle: reverse=%v err=%v", reverseProducerEdge, err)
	}
	f, err := d.GetFinding(first.FindingID)
	if err != nil || f == nil || f.Evidence != "first proof\n\n--- Follow-up evidence ---\nsecond proof" {
		t.Fatalf("canonical evidence not extended: finding=%+v err=%v", f, err)
	}
}

func TestRecordFindingKeepsDistinctAssetSets(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetA := findingDedupFixture(t, d, "distinct")
	assetB, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("finding-dedup-%d-other.example", task.ID), TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Registered after the fixture cleanup, so repeat the task cleanup here before
	// deleting assetB (LIFO cleanup order would otherwise leave its anchor alive).
	t.Cleanup(func() {
		_, _ = d.DeleteFindingsByTask(task.ID)
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetB)
	})
	in := RecordFindingInput{TaskID: task.ID, VulnClass: "secret exposure", Name: "public repository contains a credential", Severity: "high"}
	in.AssetIDs = []int64{assetA}
	first, err := es.RecordFinding(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.AssetIDs = []int64{assetB}
	second, err := es.RecordFinding(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if second.ReusedExisting || second.FindingID == first.FindingID {
		t.Fatalf("different repository/host assets were merged: first=%+v second=%+v", first, second)
	}
}

func TestRecordFindingDoesNotAutoReuseTerminalFindings(t *testing.T) {
	d := openFindingDedupTestDB(t)
	for _, status := range []string{
		FindingFalsePositive, FindingIgnored, FindingResolved, FindingFixed, FindingRiskAccepted,
	} {
		t.Run(status, func(t *testing.T) {
			task, es, assetID := findingDedupFixture(t, d, "terminal-"+status)
			in := RecordFindingInput{
				TaskID: task.ID, VulnClass: "credential exposure", Name: "public repository contains a credential",
				Severity: "high", Summary: "same observation", Evidence: "fresh proof", AssetIDs: []int64{assetID},
			}
			first, err := es.RecordFinding(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.SetFindingStatus(first.FindingID, status); err != nil {
				t.Fatal(err)
			}
			second, err := es.RecordFinding(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			if second.ReusedExisting || second.FindingID == first.FindingID {
				t.Fatalf("fresh evidence was hidden under terminal %q finding: first=%+v second=%+v", status, first, second)
			}
			var count int
			if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 2 {
				t.Fatalf("finding count=%d err=%v, want 2", count, err)
			}
		})
	}
}

func TestRecordFindingConcurrentExactReportsCreateOneRow(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetID := findingDedupFixture(t, d, "concurrent")
	in := RecordFindingInput{
		TaskID: task.ID, VulnClass: "misconfiguration", Name: "same externally observable defect",
		Severity: "medium", Summary: "same result", Evidence: "same proof", AssetIDs: []int64{assetID},
	}
	const callers = 6
	results := make(chan *RecordedFinding, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := es.RecordFinding(context.Background(), in)
			if err != nil {
				errs <- err
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var id int64
	for r := range results {
		if id == 0 {
			id = r.FindingID
		} else if r.FindingID != id {
			t.Fatalf("concurrent calls returned finding ids %d and %d", id, r.FindingID)
		}
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent finding count=%d err=%v, want 1", count, err)
	}
}

func TestRecordFindingReuseVersionsArtifactOnlyChanges(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetA := findingDedupFixture(t, d, "artifact-version")
	assetB, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{Domain: fmt.Sprintf("finding-dedup-%d-artifact-extra.example", task.ID), TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFindingsByTask(task.ID)
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetB)
	})
	producer, err := es.AddIntent(map[string]any{"summary": "producer"}, 1, []int64{assetA}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	followup, err := es.AddIntent(map[string]any{"summary": "follow-up"}, 1, []int64{assetA, assetB}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	in := RecordFindingInput{
		TaskID: task.ID, IntentID: producer, VulnClass: "configuration", Name: "artifact version fixture",
		Severity: "medium", Summary: "fixture", AssetIDs: []int64{assetA},
	}
	first, err := es.RecordFinding(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	version := func() int64 {
		t.Helper()
		f, err := d.GetFinding(first.FindingID)
		if err != nil {
			t.Fatal(err)
		}
		return f.EvidenceVersion
	}
	if got := version(); got != 0 {
		t.Fatalf("initial evidence version=%d, want 0", got)
	}

	// Explicit extension may add an affected asset without adding any prose.
	if _, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExistingFindingID: first.FindingID, VulnClass: in.VulnClass,
		Name: in.Name, Severity: in.Severity, AssetIDs: []int64{assetA, assetB},
	}); err != nil {
		t.Fatal(err)
	}
	if got := version(); got != 1 {
		t.Fatalf("asset-only extension version=%d, want 1", got)
	}

	// A new bounded follow-up edge changes the evidence lineage without prose.
	if _, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExistingFindingID: first.FindingID, IntentID: followup,
		VulnClass: in.VulnClass, Name: in.Name, Severity: in.Severity,
		AssetIDs: []int64{assetA, assetB},
	}); err != nil {
		t.Fatal(err)
	}
	if got := version(); got != 2 {
		t.Fatalf("follow-up-lineage extension version=%d, want 2", got)
	}

	// Exact retry adds neither anchor nor edge nor text and must remain stable.
	if _, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExistingFindingID: first.FindingID, IntentID: followup,
		VulnClass: in.VulnClass, Name: in.Name, Severity: in.Severity,
		AssetIDs: []int64{assetB, assetA},
	}); err != nil {
		t.Fatal(err)
	}
	if got := version(); got != 2 {
		t.Fatalf("no-op retry changed evidence version to %d, want 2", got)
	}
}

func TestRecordFindingExplicitCanonicalIDIsSameTaskOnly(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetID := findingDedupFixture(t, d, "explicit")
	first, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, VulnClass: "x", Name: "canonical", Severity: "low", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExistingFindingID: first.FindingID, VulnClass: "renamed", Name: "follow up", Severity: "low", Evidence: "extra",
	})
	if err != nil || !reused.ReusedExisting || reused.FindingID != first.FindingID {
		t.Fatalf("explicit canonical reuse=%+v err=%v", reused, err)
	}
	// Explicit IDs intentionally may extend a terminal canonical finding; this is
	// useful for retest evidence and does not silently choose a hidden record.
	if _, err := d.SetFindingStatus(first.FindingID, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	reused, err = es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExistingFindingID: first.FindingID, VulnClass: "x", Name: "explicit terminal extension", Severity: "low", Evidence: "retest evidence",
	})
	if err != nil || !reused.ReusedExisting || reused.FindingID != first.FindingID {
		t.Fatalf("explicit terminal canonical reuse=%+v err=%v", reused, err)
	}
	other, otherES, _ := findingDedupFixture(t, d, "explicit-other")
	if _, err := otherES.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: other.ID, ExistingFindingID: first.FindingID, VulnClass: "x", Name: "canonical", Severity: "low",
	}); err == nil {
		t.Fatal("cross-task existing_finding_id was accepted")
	}
}
