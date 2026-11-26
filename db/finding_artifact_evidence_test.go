package db

import (
	"sync"
	"testing"
)

func TestSyncFindingArtifactEvidenceAdvancesVersionOnce(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	task, err := d.CreateTask("artifact evidence version", "idempotent ledger", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	findingID, err := d.AddFinding(task.ID, 0, "evidence", "artifact revision", "medium", "summary", "evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFinding(findingID)

	first := FindingArtifactEvidence{SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ActivityID: 11}
	version, added, err := d.SyncFindingArtifactEvidence(t.Context(), findingID, []FindingArtifactEvidence{first, first})
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || added != 1 {
		t.Fatalf("first sync version=%d added=%d, want 1/1", version, added)
	}
	version, added, err = d.SyncFindingArtifactEvidence(t.Context(), findingID, []FindingArtifactEvidence{first})
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || added != 0 {
		t.Fatalf("retry sync version=%d added=%d, want 1/0", version, added)
	}
	second := FindingArtifactEvidence{SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ActivityID: 12}
	version, added, err = d.SyncFindingArtifactEvidence(t.Context(), findingID, []FindingArtifactEvidence{second})
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 || added != 1 {
		t.Fatalf("second sync version=%d added=%d, want 2/1", version, added)
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM finding_artifact_evidence WHERE finding_id=$1`, findingID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("ledger rows=%d, want 2", rows)
	}
}

func TestSyncFindingArtifactEvidenceConcurrentRetryIsIdempotent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	task, err := d.CreateTask("artifact evidence concurrent", "idempotent ledger", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	findingID, err := d.AddFinding(task.ID, 0, "evidence", "artifact revision", "medium", "summary", "evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFinding(findingID)
	item := FindingArtifactEvidence{SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ActivityID: 44}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := d.SyncFindingArtifactEvidence(t.Context(), findingID, []FindingArtifactEvidence{item})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var version int64
	var rows int
	if err := d.QueryRow(`SELECT evidence_version FROM findings WHERE id=$1`, findingID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM finding_artifact_evidence WHERE finding_id=$1`, findingID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if version != 1 || rows != 1 {
		t.Fatalf("concurrent sync version=%d rows=%d, want 1/1", version, rows)
	}
}
