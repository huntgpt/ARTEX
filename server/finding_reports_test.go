package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestReporterRunMessageKeepsNodeAndStandaloneFindingIDsDistinct(t *testing.T) {
	taskID, nodeID := int64(2), int64(417)
	message := reporterRunMessage(&db.DBFinding{
		ID: 147, TaskID: &taskID, NodeID: &nodeID, EvidenceVersion: 3,
		VulnClass: "Secret Exposure", Severity: "high", Summary: "PostgreSQL credential committed to public source",
	})
	for _, want := range []string{
		"Task: #2", "Exploration node_id: 417", "Standalone finding_id: 147", "Current evidence_version: 3",
		"list_finding_artifacts", "artifact://<sha256>",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("reporter message missing %q: %s", want, message)
		}
	}
}
