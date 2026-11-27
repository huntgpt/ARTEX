package server

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func reporterRunMessage(f *db.DBFinding) string {
	if f == nil || f.TaskID == nil || f.NodeID == nil {
		return ""
	}
	return reporterFindingMessage + fmt.Sprintf(
		"\n\n[This report run was explicitly queued for an existing finding]"+
			"\nTask: #%d\nExploration node_id: %d\nStandalone finding_id: %d"+
			"\nCurrent evidence_version: %d\nFinding: [%s/%s] %s",
		*f.TaskID, *f.NodeID, f.ID, f.EvidenceVersion, f.VulnClass, f.Severity, f.Summary,
	)
}

// generateFindingReport queues one Reporter run for an existing finding. This
// repairs historical records that predate the source-agnostic on_finding trigger
// and also gives operators an explicit regenerate action after evidence changes.
func (s *Server) generateFindingReport(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	finding, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if finding == nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	if finding.TaskID == nil || finding.NodeID == nil {
		writeErr(w, http.StatusConflict, "finding origin task or node is no longer available")
		return
	}
	task := s.m.ResolveTask(strconv.FormatInt(*finding.TaskID, 10))
	if task == nil {
		writeErr(w, http.StatusConflict, "finding origin task is no longer available")
		return
	}
	if finding.Status == db.FindingDuplicate || finding.Status == db.FindingFalsePositive || finding.ReportState == db.FindingReportDuplicate {
		writeErr(w, http.StatusConflict, "duplicate and false-positive findings do not receive independent detailed reports")
		return
	}
	reporter, err := pg.GetAgentByKey("reporter")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reporter == nil || !reporter.Enabled {
		writeErr(w, http.StatusConflict, "the report writer agent does not exist or is disabled")
		return
	}
	for _, key := range []string{"update_finding_report", "get_task_node_detail", "get_finding_traffic", "list_finding_artifacts"} {
		tool, err := pg.GetTool(key)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tool == nil || !tool.Enabled || !slices.Contains(tool.Agents, reporter.Key) {
			writeErr(w, http.StatusConflict, "enable and bind the tool for the report writer agent: "+key)
			return
		}
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: reporter.Key}) == nil {
		writeErr(w, http.StatusServiceUnavailable, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, http.StatusServiceUnavailable, "server is shutting down")
		return
	}
	message := reporterRunMessage(finding)
	title := "Detailed report · finding #" + strconv.FormatInt(finding.ID, 10)
	s.StartTriggeredRun(reporter.Key, title, message, *finding.TaskID, false, task.Description, strings.TrimSpace(task.Goal))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued": true, "finding_id": finding.ID, "node_id": *finding.NodeID,
	})
}
