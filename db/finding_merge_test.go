package db

import (
	"fmt"
	"strings"
	"testing"
)

func TestMergeDuplicateFindingPreservesEvidenceAndAuditRow(t *testing.T) {
	d := openFindingDedupTestDB(t)
	task, es, assetA := findingDedupFixture(t, d, "merge")
	assetB, err := d.Assets().UpsertRootDomain(UpsertRootDomainReq{
		Domain: fmt.Sprintf("finding-merge-%d-second.example", task.ID), TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFindingsByTask(task.ID)
		_ = d.DeleteTask(task.ID)
		_, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, assetB)
	})

	producer, err := es.AddIntent(map[string]any{"summary": "initial observation"}, 1, []int64{assetA}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	followup, err := es.AddIntent(map[string]any{"summary": "fresh verified proof"}, 1, []int64{assetB}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, IntentID: producer, VulnClass: "information disclosure",
		Name: "anonymous inventory disclosure", Severity: SeverityLow,
		Summary: "inventory exposed", Evidence: "first bounded proof", AssetIDs: []int64{assetA},
	})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, IntentID: followup, VulnClass: "information disclosure",
		Name: "anonymous raw source disclosure", Severity: SeverityMedium,
		Summary: "raw source exposed", Evidence: "fresh signed proof", AssetIDs: []int64{assetB},
		Counterevidence: "bounded to one file", ConfidenceRationale: "signed output",
	})
	if err != nil {
		t.Fatal(err)
	}
	if canonical.FindingID == duplicate.FindingID {
		t.Fatal("fixture unexpectedly deduplicated before explicit merge")
	}
	activityID, err := es.AppendActivity(Activity{
		NodeID: &followup, Worker: "work#1", Kind: "tool_result", Tool: "Bash",
		ToolUseID: "merge-artifact", Detail: "signed proof activity",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if _, err := d.Exec(`INSERT INTO finding_artifact_evidence(finding_id,sha256,activity_id) VALUES($1,$2,$3)`,
		duplicate.FindingID, digest, activityID); err != nil {
		t.Fatal(err)
	}
	if err := d.SetFindingVerification(duplicate.FindingID, VerificationVerified, 3, ""); err != nil {
		t.Fatal(err)
	}

	result, err := d.MergeDuplicateFinding(t.Context(), canonical.FindingID, duplicate.FindingID, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.AssetsAdded != 1 || result.ArtifactsAdded != 1 || result.EvidenceLinksAdded != 1 {
		t.Fatalf("merge result=%+v", result)
	}
	got, err := d.GetFinding(canonical.FindingID)
	if err != nil || got == nil {
		t.Fatalf("canonical=%+v err=%v", got, err)
	}
	if got.Name != "anonymous raw source disclosure" || got.Summary != "raw source exposed" || got.Severity != SeverityMedium {
		t.Fatalf("promoted presentation not applied: %+v", got)
	}
	if got.VerificationStatus != VerificationVerified || got.PoELevel != 3 {
		t.Fatalf("verification not preserved: status=%s poe=%d", got.VerificationStatus, got.PoELevel)
	}
	if !strings.Contains(got.Evidence, "first bounded proof") || !strings.Contains(got.Evidence, "fresh signed proof") {
		t.Fatalf("evidence not merged: %q", got.Evidence)
	}
	if len(got.AssetIDs) != 2 {
		t.Fatalf("assets=%v, want both", got.AssetIDs)
	}
	var duplicateStatus, duplicateReport, duplicateRationale string
	if err := d.QueryRow(`SELECT status,report_state,confidence_rationale FROM findings WHERE id=$1`, duplicate.FindingID).
		Scan(&duplicateStatus, &duplicateReport, &duplicateRationale); err != nil {
		t.Fatal(err)
	}
	if duplicateStatus != FindingDuplicate || duplicateReport != FindingReportDuplicate ||
		!strings.Contains(duplicateRationale, fmt.Sprintf("canonical finding #%d", canonical.FindingID)) {
		t.Fatalf("duplicate audit row status=%q report=%q rationale=%q", duplicateStatus, duplicateReport, duplicateRationale)
	}
	var linked, ledger bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`,
		task.ExplorationID, canonical.NodeID, RelDerivedFrom, followup).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM finding_artifact_evidence WHERE finding_id=$1 AND sha256=$2)`,
		canonical.FindingID, digest).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if !linked || !ledger {
		t.Fatalf("artifact provenance linked=%v ledger=%v", linked, ledger)
	}

	// An API retry after a lost response is a no-op, not another evidence append.
	before := got.Evidence
	result, err = d.MergeDuplicateFinding(t.Context(), canonical.FindingID, duplicate.FindingID, true)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetFinding(canonical.FindingID)
	if result.AssetsAdded != 0 || result.ArtifactsAdded != 0 || result.EvidenceLinksAdded != 0 || got.Evidence != before {
		t.Fatalf("idempotent retry changed canonical: result=%+v evidence=%q", result, got.Evidence)
	}
}

func TestMergeDuplicateFindingRejectsCrossTaskAndIncompatibleClass(t *testing.T) {
	d := openFindingDedupTestDB(t)
	taskA, esA, assetA := findingDedupFixture(t, d, "merge-a")
	taskB, esB, assetB := findingDedupFixture(t, d, "merge-b")
	a, err := esA.RecordFinding(t.Context(), RecordFindingInput{TaskID: taskA.ID, VulnClass: "xss", Name: "a", Severity: SeverityLow, AssetIDs: []int64{assetA}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := esB.RecordFinding(t.Context(), RecordFindingInput{TaskID: taskB.ID, VulnClass: "xss", Name: "b", Severity: SeverityLow, AssetIDs: []int64{assetB}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.MergeDuplicateFinding(t.Context(), a.FindingID, b.FindingID, false); err == nil || !strings.Contains(err.Error(), "same live task") {
		t.Fatalf("cross-task merge error=%v", err)
	}

	c, err := esA.RecordFinding(t.Context(), RecordFindingInput{TaskID: taskA.ID, VulnClass: "sql injection", Name: "c", Severity: SeverityHigh, AssetIDs: []int64{assetA}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.MergeDuplicateFinding(t.Context(), a.FindingID, c.FindingID, false); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("incompatible merge error=%v", err)
	}
}
