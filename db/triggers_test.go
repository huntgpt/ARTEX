package db

import "testing"

func TestNewFindingsSinceCarriesBothFindingIDs(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()

	task, err := d.CreateTask("finding event ids", "report every source path", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	nodeID, err := store.AddNode(KindFinding, map[string]any{
		"summary": "committed database credential", "vulnclass": "Secret Exposure", "severity": "high",
	}, 9, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := d.AddFinding(task.ID, nodeID, "Secret Exposure", "PostgreSQL credential", "high", "committed database credential", "proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFinding(findingID)
		_ = d.DeleteTask(task.ID)
	})

	events, err := d.NewFindingsSince(nodeID - 1)
	if err != nil {
		t.Fatal(err)
	}
	var got *TaskEvent
	for i := range events {
		if events[i].NodeID == nodeID {
			got = &events[i]
			break
		}
	}
	if got == nil || got.FindingID != findingID || got.TaskID != task.ID {
		t.Fatalf("finding event=%+v want node=%d finding=%d task=%d", got, nodeID, findingID, task.ID)
	}
}
