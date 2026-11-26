package db

import (
	"context"
	"fmt"
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
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "subdomain_dns", "running", "agent", "subfinder", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "waits for") {
		t.Fatalf("dependency gate error=%v", err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "planner", "phase-ledger", "", "passive evidence is incomplete", "", ""); err == nil || !strings.Contains(err.Error(), "blocker_kind") {
		t.Fatalf("pending phase accepted blocker without typed provenance: %v", err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "planner", "phase-ledger", "", "passive evidence is incomplete", "dependency", "phase:not_a_dependency"); err == nil || !strings.Contains(err.Error(), "not a dependency") {
		t.Fatalf("pending phase accepted forged dependency provenance: %v", err)
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "planner", "phase-ledger", "waiting for passive discovery", "passive evidence is incomplete", "dependency", "phase:passive_discovery")
	if err != nil {
		t.Fatal(err)
	}
	if runs[1].State != "blocked" || runs[1].BlockerKind != "dependency" || runs[1].BlockerSource != "phase:passive_discovery" {
		t.Fatalf("pending dependency blocker=%+v", runs[1])
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "passive_discovery", "running", "codex", "web_search", "collecting", "", "", ""); err != nil {
		t.Fatal(err)
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "passive_discovery", "complete", "codex", "web_search", "ownership evidence collected", "", "", "")
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
	if runs[1].BlockerReason != "" || runs[1].BlockerKind != "" || runs[1].BlockerSource != "" {
		t.Fatalf("released dependency blocker retained stale metadata: %+v", runs[1])
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "planner", "phase-ledger", "", "passive evidence is incomplete", "dependency", "phase:passive_discovery"); err == nil || !strings.Contains(err.Error(), "already complete") {
		t.Fatalf("phase accepted stale completed-dependency provenance: %v", err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "operator", "rdap", "", "", "", ""); err == nil {
		t.Fatal("blocked phase without reason was accepted")
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "ownership", "blocked", "operator", "rdap", "", "registrant evidence missing", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if runs[1].State != "blocked" || runs[1].BlockerReason != "registrant evidence missing" || runs[1].BlockerKind != "operational" {
		t.Fatalf("blocked ownership=%+v", runs[1])
	}

	// A durable fact can block a not-yet-ready phase without pretending its
	// dependencies ran. Explicitly reopening it clears stale blocker metadata;
	// refresh leaves it pending until its real dependency completes.
	store := database.Exploration(explorationID)
	factID, err := store.AddNode(KindFact, map[string]any{"summary": "identity gate checked"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	intentID, err := store.AddIntent(map[string]any{"summary": "evidence source wrong-kind fixture"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "blocked", "planner", "phase-ledger", "", "no approved AD identity", "evidence", "fact:999999999"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("phase accepted missing evidence provenance: %v", err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "blocked", "planner", "phase-ledger", "", "no approved AD identity", "evidence", fmt.Sprintf("fact:%d", intentID)); err == nil || !strings.Contains(err.Error(), "node is intent") {
		t.Fatalf("phase accepted wrong-kind evidence provenance: %v", err)
	}
	otherExplorationID, err := database.CreateExploration("phase blocker cross-exploration", "provenance isolation")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM explorations WHERE id=$1`, otherExplorationID) })
	foreignFactID, err := database.Exploration(otherExplorationID).AddNode(KindFact, map[string]any{"summary": "foreign"}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "blocked", "planner", "phase-ledger", "", "no approved AD identity", "evidence", fmt.Sprintf("fact:%d", foreignFactID)); err == nil || !strings.Contains(err.Error(), "does not exist in this exploration") {
		t.Fatalf("phase accepted cross-exploration evidence provenance: %v", err)
	}
	factSource := fmt.Sprintf("fact:%d", factID)
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "blocked", "planner", "phase-ledger", "identity gate checked", "no approved AD identity", "evidence", factSource)
	if err != nil {
		t.Fatal(err)
	}
	var initialAccess RedTeamPhaseRun
	for _, run := range runs {
		if run.Phase == "initial_access" {
			initialAccess = run
			break
		}
	}
	if initialAccess.State != "blocked" || initialAccess.BlockerKind != "evidence" || initialAccess.BlockerSource != factSource {
		t.Fatalf("pending evidence blocker=%+v", initialAccess)
	}
	issues, err := database.Exploration(explorationID).GoalCompletionIssues(ctx, GoalCompletionRequirements{WorkflowComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(issues, " | "), "initial_access=blocked") {
		t.Fatalf("workflow completion did not fail closed on blocked phase: %v", issues)
	}
	if _, err := database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "ready", "planner", "phase-ledger", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "waits for findings") {
		t.Fatalf("blocked phase bypassed unfinished dependencies via ready: %v", err)
	}
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "initial_access", "pending", "planner", "phase-ledger", "dependency state refreshed", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.Phase == "initial_access" {
			if run.State != "pending" || run.BlockerReason != "" || run.BlockerKind != "" || run.BlockerSource != "" {
				t.Fatalf("reopened evidence blocker=%+v", run)
			}
		}
	}
	intentSource := fmt.Sprintf("intent:%d", intentID)
	runs, err = database.TransitionRedTeamPhase(ctx, explorationID, "ad_collection", "blocked", "planner", "phase-ledger", "identity-gated worker stopped", "collector needs an approved identity", "evidence", intentSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if run.Phase == "ad_collection" && (run.State != "blocked" || run.BlockerSource != intentSource) {
			t.Fatalf("intent-backed evidence blocker=%+v", run)
		}
	}
}
