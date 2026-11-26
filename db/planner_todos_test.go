package db

import "testing"

func TestPlannerTodosRoundTripAndCascade(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("durable planner test", "advance an ordered chain")
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(expID)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })

	if got, err := es.LoadPlannerTodos(); err != nil || len(got) != 0 {
		t.Fatalf("initial load = %+v, err=%v", got, err)
	}
	want := []PlannerTodo{
		{Content: "obtain credential", Status: "completed"},
		{Content: "validate credential", Status: "in_progress"},
		{Content: "collect AD graph", Status: "pending"},
	}
	if err := es.SavePlannerTodos(want); err != nil {
		t.Fatal(err)
	}
	got, err := d.Exploration(expID).LoadPlannerTodos()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("loaded %d todos, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("todo %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	if _, err := d.Exec(`DELETE FROM explorations WHERE id=$1`, expID); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM planner_todos WHERE exploration_id=$1`, expID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("planner todo row survived exploration cascade: %d", rows)
	}
}

func TestPlannerTodosRejectInvalidState(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("invalid planner todo", "reject bad state")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) //nolint:errcheck
	if err := d.Exploration(expID).SavePlannerTodos([]PlannerTodo{{Content: "x", Status: "unknown"}}); err == nil {
		t.Fatal("SavePlannerTodos accepted an unknown status")
	}
}
