package agent

import (
	"strings"
	"testing"
)

func TestPlannerParallelismBlockReportsRealIdleSlots(t *testing.T) {
	block := plannerParallelismBlock(3, map[string]any{
		"frontier_open":   int64(1),
		"running_intents": []map[string]any{{"id": 10}},
	})
	for _, want := range []string{
		"worker_capacity=3",
		"open_intents=1",
		"running_intents=1",
		"available_worker_slots=1",
		"prerequisite-ready",
		"Never invent padding",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("capacity block missing %q: %s", want, block)
		}
	}
}

func TestPlannerParallelismBlockNeverReportsNegativeSlots(t *testing.T) {
	block := plannerParallelismBlock(2, map[string]any{
		"frontier_open":   4,
		"running_intents": []any{map[string]any{"id": 10}},
	})
	if !strings.Contains(block, "available_worker_slots=0") {
		t.Fatalf("capacity block = %q", block)
	}
}

func TestPlannerParallelismBlockDisabledWithoutCapacity(t *testing.T) {
	if got := plannerParallelismBlock(0, nil); got != "" {
		t.Fatalf("disabled capacity block = %q, want empty", got)
	}
}
