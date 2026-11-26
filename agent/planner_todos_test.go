package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPlannerTodoStoreSurvivesPlannerRecreation(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	expID, err := d.CreateExploration("planner restart", "continue an ordered chain")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck
	ts := d.Exploration(expID)

	first := NewPlanner(nil, "", t.TempDir(), nil, 0, 0)
	store, err := first.todoFor(ts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"todos": []map[string]string{
		{"content": "discover injection", "status": "completed"},
		{"content": "validate credential", "status": "in_progress"},
		{"content": "collect AD graph", "status": "pending"},
	}})
	if _, err := store.Tool().Call(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := savePlannerTodos(ts, store); err != nil {
		t.Fatal(err)
	}

	// A new Planner represents a fresh backend process: its in-memory map is empty
	// and must be rehydrated solely from the database row.
	second := NewPlanner(nil, "", t.TempDir(), nil, 0, 0)
	restored, err := second.todoFor(d.Exploration(expID))
	if err != nil {
		t.Fatal(err)
	}
	got := restored.List()
	if len(got) != 3 || got[0].Content != "discover injection" || got[0].Status != "completed" ||
		got[1].Status != "in_progress" || got[2].Content != "collect AD graph" || got[2].Status != "pending" {
		t.Fatalf("restored todos = %+v", got)
	}
}

func TestSavePlannerTodosRejectsInvalidSDKState(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	expID, err := d.CreateExploration("planner invalid state", "reject corrupt scratchpad")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck

	if err := d.Exploration(expID).SavePlannerTodos([]db.PlannerTodo{{Content: "x", Status: "invalid"}}); err == nil {
		t.Fatal("invalid planner todo state was accepted")
	}
}

func TestPlannerTodoHookPersistsSuccessfulWriteImmediately(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	expID, err := d.CreateExploration("planner immediate save", "survive a mid-round restart")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck
	ts := d.Exploration(expID)
	plan := NewPlanner(nil, "", t.TempDir(), nil, 0, 0)
	store, err := plan.todoFor(ts)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"todos":[{"content":"obtain foothold","status":"in_progress"}]}`)
	if _, err := store.Tool().Call(context.Background(), raw, nil); err != nil {
		t.Fatal(err)
	}

	h := plannerTodoHooks{ts: ts, store: store}
	h.PostToolUse(context.Background(), "TodoWrite", raw, []byte("ok"), false)
	got, err := ts.LoadPlannerTodos()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Content != "obtain foothold" || got[0].Status != "in_progress" {
		t.Fatalf("persisted todos = %+v", got)
	}
}
