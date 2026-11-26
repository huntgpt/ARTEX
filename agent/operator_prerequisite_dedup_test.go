package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestOperatorPrerequisiteKeyIsNarrowAndStable(t *testing.T) {
	a := "For goal #112, check whether the operator enabled ARTEX traffic capture and matching-host binding for finding #182 on https://sonarqube-dgt.pttdigital.com/."
	b := "For goal #112, perform one prerequisite closure handoff for finding #182 at https://sonarqube-dgt.pttdigital.com/: approval is required for matching-host evidence and traffic capture."
	keyA := operatorPrerequisiteKey(a)
	keyB := operatorPrerequisiteKey(b)
	if keyA == "" || keyA != keyB {
		t.Fatalf("equivalent blockers should have one stable key: a=%q b=%q", keyA, keyB)
	}

	for _, summary := range []string{
		"Enumerate JavaScript bundles on https://sonarqube-dgt.pttdigital.com/.",
		"Wait for operator approval before destructive validation on https://sonarqube-dgt.pttdigital.com/.",
		"For goal #112, capture traffic for https://sonarqube-dgt.pttdigital.com/.",
	} {
		if got := operatorPrerequisiteKey(summary); got != "" {
			t.Errorf("ordinary work must not be deduplicated: summary=%q key=%q", summary, got)
		}
	}

	otherFinding := "For goal #112, check operator approval for traffic capture and matching-host binding for finding #999 on https://sonarqube-dgt.pttdigital.com/."
	if got := operatorPrerequisiteKey(otherFinding); got == keyA {
		t.Fatalf("different findings must remain separate: %q", got)
	}
}

func TestAddOneIntentDeduplicatesOperatorPrerequisiteAndHumanReopens(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTask("operator prerequisite dedup", "test stable dependency", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	plannerTools := NewToolSet(store, "planner")

	firstSummary := "For goal #112, check whether the operator enabled traffic capture and matching-host binding for finding #182 on https://sonarqube-dgt.pttdigital.com/."
	firstID, err := plannerTools.addOneIntent(intentItem{Summary: firstSummary, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	secondSummary := "For goal #112, perform the prerequisite check for finding #182 at https://sonarqube-dgt.pttdigital.com/: operator approval is needed for matching-host binding and traffic capture."
	secondID, err := plannerTools.addOneIntent(intentItem{Summary: secondSummary, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("duplicate blocker created a new intent: first=%d second=%d", firstID, secondID)
	}
	intents, err := store.ListByKind(db.KindIntent, 20)
	if err != nil || len(intents) != 1 {
		t.Fatalf("deduped intent count=%d err=%v", len(intents), err)
	}

	if err := store.SetIntentState(firstID, "blocked"); err != nil {
		t.Fatal(err)
	}
	humanTools := NewToolSet(store, "mainagent")
	resumed := 0
	humanTools.SetResumeTask(func() { resumed++ })
	reusedID, err := humanTools.addOneIntent(intentItem{Summary: secondSummary, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if reusedID != firstID {
		t.Fatalf("human action should reuse retained blocker: got=%d want=%d", reusedID, firstID)
	}
	node, err := store.GetNode(firstID)
	if err != nil || node == nil || node.State != "open" {
		t.Fatalf("human action did not reopen blocked intent: node=%+v err=%v", node, err)
	}
	if resumed != 0 {
		t.Fatalf("addOneIntent should reopen the retained work without double-resuming the task; callback count=%d", resumed)
	}

	if err := store.SetIntentState(firstID, "stopped"); err != nil {
		t.Fatal(err)
	}
	if _, err := humanTools.addOneIntent(intentItem{Summary: firstSummary, Priority: 10}); err != nil {
		t.Fatal(err)
	}
	node, err = store.GetNode(firstID)
	if err != nil || node == nil || node.State != "open" {
		t.Fatalf("human action did not reopen stopped intent: node=%+v err=%v", node, err)
	}
}
