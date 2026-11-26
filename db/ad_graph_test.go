package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/ad"
)

func TestADObservationStaysInExplorationGraph(t *testing.T) {
	database, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer database.Close()
	explorationID, err := database.CreateExploration("AD ingest isolation test", "read-only ingest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM explorations WHERE id=$1`, explorationID) })
	store := database.Exploration(explorationID)

	var assetsBefore int
	if err := database.QueryRow(`SELECT count(*) FROM assets`).Scan(&assetsBefore); err != nil {
		t.Fatal(err)
	}
	observation := ad.Observation{
		Source:  "bloodhound-json",
		Records: 2,
		Entities: []ad.Entity{
			{Key: "S-1-5-21-7-8-9-1104", Kind: ad.EntityUser, State: ad.Observed, Detail: json.RawMessage(`{"name":"target-controlled"}`)},
			{Key: "S-1-5-21-7-8-9-512", Kind: ad.EntityGroup, State: ad.Observed},
		},
		Edges: []ad.Edge{{SourceKey: "S-1-5-21-7-8-9-1104", Relation: ad.RelationMemberOf, TargetKey: "S-1-5-21-7-8-9-512", State: ad.Observed}},
	}
	result, err := store.IngestADObservation(context.Background(), observation)
	if err != nil {
		t.Fatal(err)
	}
	if result.EntitiesUpserted != 2 || result.EdgesUpserted != 1 {
		t.Fatalf("unexpected ingest result: %+v", result)
	}
	entities, edges, err := store.ADGraphCounts(context.Background())
	if err != nil || entities != 2 || edges != 1 {
		t.Fatalf("graph counts entities=%d edges=%d err=%v", entities, edges, err)
	}

	var assetsAfter int
	if err := database.QueryRow(`SELECT count(*) FROM assets`).Scan(&assetsAfter); err != nil {
		t.Fatal(err)
	}
	if assetsAfter != assetsBefore {
		t.Fatalf("AD ingest leaked into asset graph: assets before=%d after=%d", assetsBefore, assetsAfter)
	}
}

func TestADObservationIsIdempotent(t *testing.T) {
	database, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer database.Close()
	explorationID, err := database.CreateExploration("AD idempotence test", "read-only ingest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM explorations WHERE id=$1`, explorationID) })
	store := database.Exploration(explorationID)
	observation := ad.Observation{Entities: []ad.Entity{{
		Key: "S-1-5-21-71-81-91-1001", Kind: ad.EntityComputer,
		DNSHostname: "DC01.CORP.EXAMPLE.COM", State: ad.Observed,
	}}}
	for i := 0; i < 2; i++ {
		if _, err := store.IngestADObservation(context.Background(), observation); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := store.ADGraph(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Entities) != 1 || graph.Entities[0].DNSHostname != "dc01.corp.example.com" {
		t.Fatalf("unexpected graph: %+v", graph)
	}
}

func TestADCollectionRunLifecycleAndArtifacts(t *testing.T) {
	database, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer database.Close()
	explorationID, err := database.CreateExploration("AD lifecycle test", "audited collection")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM explorations WHERE id=$1`, explorationID) })
	store := database.Exploration(explorationID)
	ctx := context.Background()
	run, err := store.CreateADCollectionRun(ctx, "sharphound", "on-host", "operator@example")
	if err != nil || run.State != ad.RunQueued {
		t.Fatalf("create run=%+v err=%v", run, err)
	}
	if _, err = store.TransitionADCollectionRun(ctx, run.ID, ad.RunApproved, "approver@example", "authorized"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionADCollectionRun(ctx, run.ID, ad.RunRunning, "agent", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = store.TransitionADCollectionRun(ctx, run.ID, ad.RunIngesting, "agent", ""); err != nil {
		t.Fatal(err)
	}
	artifact := ADCollectionArtifact{
		Kind: "bloodhound-json", LogicalPath: "artifacts/users.json",
		SHA256:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ByteSize: 1234, State: "ingested",
	}
	if err := store.AddADCollectionArtifact(ctx, run.ID, artifact); err != nil {
		t.Fatal(err)
	}
	result := ADIngestResult{Records: 2, EntitiesUpserted: 2, EdgesUpserted: 1}
	if err := store.FinishADCollectionRun(ctx, run.ID, ad.RunComplete, result, ""); err != nil {
		t.Fatal(err)
	}
	runs, err := database.ListADCollectionRuns(ctx, explorationID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	got := runs[0]
	if got.State != ad.RunComplete || got.Entities != 2 || got.Edges != 1 || len(got.Artifacts) != 1 || got.ApprovedBy != "approver@example" {
		t.Fatalf("completed run=%+v", got)
	}
	if _, err := store.TransitionADCollectionRun(ctx, run.ID, ad.RunRunning, "agent", ""); !errors.Is(err, ErrADRunStateConflict) {
		t.Fatalf("terminal transition error=%v", err)
	}
}
