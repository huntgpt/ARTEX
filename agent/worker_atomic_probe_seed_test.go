package agent

import (
	"strings"
	"testing"
)

func TestWorkerPromptKeepsDNSAndExpensiveLocalAnalysisBounded(t *testing.T) {
	prompt := BuiltinPromptSeeds()["worker"]
	for _, required := range []string{
		"Keep DNS discovery separate from connection attempts",
		"Treat NXDOMAIN and an empty DNS answer as observed DNS results",
		"one hostname and one protocol family per call",
		"avoid context regexes such as .{0,N}...",
		"First locate fixed anchors with rg -F or rg -n",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("worker prompt lacks atomic-probe contract %q", required)
		}
	}
}
