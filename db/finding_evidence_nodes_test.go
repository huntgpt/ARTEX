package db

import "testing"

func TestFindingIDsForEvidenceNodeBoundsLineage(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	task, err := d.CreateTask("inverse evidence lineage", "map ingest-time artifacts", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	es := d.Exploration(task.ExplorationID)
	producer, err := es.AddIntent(map[string]any{"summary": "producer"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	findingNode, err := es.AddNode(KindFinding, map[string]any{"name": "finding"}, 8, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(producer, RelYields, findingNode); err != nil {
		t.Fatal(err)
	}
	findingID, err := d.AddFinding(task.ID, findingNode, "test", "finding", "medium", "summary", "evidence", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFinding(findingID)
	followup, err := es.AddIntent(map[string]any{"summary": "direct retest"}, 5, nil, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(findingNode, RelDerivedFrom, followup); err != nil {
		t.Fatal(err)
	}
	unrelated, err := es.AddIntent(map[string]any{"summary": "unrelated"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	for label, nodeID := range map[string]int64{"producer": producer, "finding": findingNode, "followup": followup} {
		ids, err := es.FindingIDsForEvidenceNode(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 1 || ids[0] != findingID {
			t.Fatalf("%s node mapping=%v, want [%d]", label, ids, findingID)
		}
	}
	if ids, err := es.FindingIDsForEvidenceNode(unrelated); err != nil {
		t.Fatal(err)
	} else if len(ids) != 0 {
		t.Fatalf("unrelated mapping=%v, want empty", ids)
	}
}
