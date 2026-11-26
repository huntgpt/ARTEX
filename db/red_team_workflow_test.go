package db

import (
	"context"
	"strings"
	"testing"
)

func TestRedTeamWorkflowDependenciesAndBlockers(t *testing.T) {
	database, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer database.Close()
	explorationID, err := database.CreateExploration("red-team workflow test", "dependency state")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM explorations WHERE id=$1`, explorationID) })
	ctx := context.Background()
	runs, err := database.RedTeamWorkflowRuns(ctx, explorationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != len(RedTeamWorkflow) || runs[0].Phase != "passive_discovery" || runs[0].State != "ready" {
		t.Fatalf("initial workflow=%+v", runs)
	}
	if runs[0].Dependencies == nil || runs[0].Tools == nil {
		t.Fatalf("workflow arrays must serialize as [] rather than null: %+v", runs[0])
	}
	if runs[1].State != "pending" {
		t.Fatalf("ownership should wait, got %s", runs[1].State)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "subdomain_dns", "running", "agent", "subfinder", "", ""); err == nil || !strings.Contains(err.Error(), "waits for") {
		t.Fatalf("dependency gate error=%v", err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "passive_discovery", "running", "codex", "web_search", "collecting", ""); err != nil {
		t.Fatal(err)
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "passive_discovery", "complete", "codex", "web_search", "ownership evidence collected", "")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, run := range runs {
		states[run.Phase] = run.State
	}
	if states["ownership"] != "ready" || states["public_source"] != "pending" {
		t.Fatalf("unexpected released states: %+v", states)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "operator", "rdap", "", ""); err == nil {
		t.Fatal("blocked phase without reason was accepted")
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "operator", "rdap", "", "registrant evidence missing")
	if err != nil {
		t.Fatal(err)
	}
	if runs[1].State != "blocked" || runs[1].BlockerReason != "registrant evidence missing" {
		t.Fatalf("blocked ownership=%+v", runs[1])
	}
}
