package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func completionGoalNode(t *testing.T, text string) *db.Node {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"text": text})
	if err != nil {
		t.Fatal(err)
	}
	return &db.Node{Kind: db.KindGoal, Payload: payload}
}

func TestGoalCompletionRequirementsClassifiesBroadDeliverables(t *testing.T) {
	tests := []struct {
		name string
		text string
		want db.GoalCompletionRequirements
	}{
		{
			name: "narrow finding",
			text: "Verify SQL injection on /login",
		},
		{
			name: "complete evidence",
			text: "Create a complete ARTEX evidence package containing every newly observed asset",
			want: db.GoalCompletionRequirements{WorkflowComplete: true, FindingsVerified: true},
		},
		{
			name: "confirmed and retested",
			text: "Deliver confirmed and retested findings",
			want: db.GoalCompletionRequirements{WorkflowComplete: true, FindingsVerified: true, RetestsComplete: true},
		},
		{
			name: "final report",
			text: "Produce a final red-team assessment report with confirmed and retested findings",
			want: db.GoalCompletionRequirements{WorkflowComplete: true, FindingsVerified: true, RetestsComplete: true, ReportAvailable: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := goalCompletionRequirements(completionGoalNode(t, tc.text)); got != tc.want {
				t.Fatalf("requirements for %q = %+v, want %+v", tc.text, got, tc.want)
			}
		})
	}
}

func newGoalCompletionTask(t *testing.T) (*db.DB, *db.Task, *db.ExplorationStore) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTaskWithOptions("goal completion gate", "deterministic completion guard test", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	return d, task, d.Exploration(task.ExplorationID)
}

func TestProveBroadGoalRefusesWhileWorkflowPhasesUnfinished(t *testing.T) {
	d, task, store := newGoalCompletionTask(t)
	if err := d.EnsureRedTeamWorkflow(context.Background(), task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	goalID, err := store.AddGoal(map[string]any{"text": "Create a complete evidence package for the assessment"}, "goals")
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, err := store.OriginFactID()
	if err != nil || evidenceID == 0 {
		t.Fatalf("origin fact: id=%d err=%v", evidenceID, err)
	}

	ts := NewToolSet(store, "planner")
	res := callGuardTool(t, ts.proveGoal(), fmt.Sprintf(`{"goal_id":%d,"evidence_id":%d,"reason":"complete"}`, goalID, evidenceID))
	if !res.IsError || !strings.Contains(res.Flatten(), "red-team phases are unfinished") || !strings.Contains(res.Flatten(), "passive_discovery=ready") {
		t.Fatalf("want precise unfinished phase refusal, got IsError=%v %q", res.IsError, res.Flatten())
	}
	if got := nodeState(t, store, goalID); got != "open" {
		t.Fatalf("goal state=%q, want open", got)
	}
}

func TestGoalCompletionIssuesFailClosedWithoutPhaseLedger(t *testing.T) {
	_, _, store := newGoalCompletionTask(t)
	issues, err := store.GoalCompletionIssues(context.Background(), db.GoalCompletionRequirements{WorkflowComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 || issues[0] != "required red-team phase ledger is missing" {
		t.Fatalf("issues=%v, want missing-ledger prerequisite", issues)
	}
}

func TestGoalMetReopensHistoricallyMetBroadGoal(t *testing.T) {
	d, task, store := newGoalCompletionTask(t)
	if err := d.EnsureRedTeamWorkflow(context.Background(), task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	goalID, err := store.AddGoal(map[string]any{"text": "Produce the final report"}, "goals")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeState(goalID, "met"); err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(store, "planner")
	res := callGuardTool(t, ts.goalMet(), `{"reason":"legacy task said complete"}`)
	if !res.IsError || !strings.Contains(res.Flatten(), fmt.Sprintf("goal %d", goalID)) || !strings.Contains(res.Flatten(), "red-team phases are unfinished") {
		t.Fatalf("want precise reopened-goal refusal, got IsError=%v %q", res.IsError, res.Flatten())
	}
	if got := nodeState(t, store, goalID); got != "open" {
		t.Fatalf("goal state=%q, want reopened", got)
	}
	if ts.GoalMet {
		t.Fatal("goal_met completed a task whose broad goal failed completion guards")
	}
}

func TestGoalCompletionIssuesRequireVerifiedFindingsRetestsAndReport(t *testing.T) {
	d, task, store := newGoalCompletionTask(t)
	ctx := context.Background()
	if err := d.EnsureRedTeamWorkflow(ctx, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx, `UPDATE red_team_phase_runs
		SET state='complete', current_result=CASE WHEN phase='report' THEN '' ELSE current_result END
		WHERE exploration_id=$1`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	var findingID int64
	if err := d.QueryRowContext(ctx, `INSERT INTO findings
		(task_id,name,status,verification_status,evidence_version,report_evidence_version)
		VALUES($1,'completion gate finding','pending','unverified',1,0) RETURNING id`, task.ID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, findingID) })

	req := db.GoalCompletionRequirements{WorkflowComplete: true, FindingsVerified: true, RetestsComplete: true, ReportAvailable: true}
	issues, err := store.GoalCompletionIssues(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(issues, " | ")
	for _, want := range []string{
		"1 actionable findings still await triage",
		"1 actionable findings are not verified",
		"1 of 1 actionable findings have no completed retest",
		"report phase has no recorded report artifact",
		"1 actionable findings have no current report artifact",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("issues %q do not include %q", joined, want)
		}
	}

	if _, err := d.ExecContext(ctx, `UPDATE findings SET status='confirmed', verification_status='verified',
		report='current report', report_evidence_version=evidence_version WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO finding_retests(finding_id,status,verdict,snapshot)
		VALUES($1,'completed','reproduced','{}'::jsonb)`, findingID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExecContext(ctx, `UPDATE red_team_phase_runs SET current_result='artifact://final-report'
		WHERE exploration_id=$1 AND phase='report'`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	issues, err = store.GoalCompletionIssues(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("completion issues after satisfying prerequisites: %v", issues)
	}
}
