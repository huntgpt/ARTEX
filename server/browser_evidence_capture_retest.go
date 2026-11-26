package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// toolCaptureRetestPlaywrightEvidence gives the retester the same code-owned
// capture helper as a Worker while deriving task/workspace identity solely from
// its server-owned conversation. Its URL remains visible to the target gate.
func (s *Server) toolCaptureRetestPlaywrightEvidence() actool.CoreTool {
	template := agent.NewToolSet(nil, "").CapturePlaywrightEvidenceTool()
	return actool.Build(actool.Spec{
		Name:        "capture_retest_playwright_evidence",
		Description: template.Description() + " In a finding retest, pass the returned receipt_path to ingest_retest_browser_evidence.",
		Schema:      template.InputSchema(),
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			conversationID := intercept.ConvIDFromContext(ctx)
			retest, err := s.m.pg.FindingRetestForConversation(ctx, conversationID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if retest == nil || retest.Status != "running" {
				return actool.Errorf("browser evidence can only be captured during the current running finding retest"), nil
			}
			finding, err := s.m.pg.GetFinding(retest.FindingID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if finding == nil || finding.TaskID == nil || finding.NodeID == nil {
				return actool.Errorf("the retested finding has no live task/graph context for browser capture"), nil
			}
			task := s.m.ResolveTask(i64s(*finding.TaskID))
			if task == nil {
				return actool.Errorf("the retested finding's task is unavailable"), nil
			}
			if tc == nil || strings.TrimSpace(tc.ToolUseID) == "" {
				return actool.Errorf("browser capture requires an audited tool call id"), nil
			}
			expected, _ := filepath.Abs(filepath.Join(s.m.dir, "sessions", fmt.Sprintf("conv-%d", conversationID)))
			actual, pathErr := filepath.Abs(tc.WorkingDir)
			if pathErr != nil || actual != expected {
				return actool.Errorf("browser capture requires this retest conversation's working directory"), nil
			}
			tsx := agent.NewToolSet(task.Store, "retester")
			tsx.SetTaskID(*finding.TaskID)
			tsx.SetWorkBase(s.m.dir)
			result, callErr := tsx.CapturePlaywrightEvidenceTool().Call(ctx, in, tc)
			if callErr != nil || result.IsError {
				return result, callErr
			}
			var output map[string]any
			if json.Unmarshal([]byte(result.Flatten()), &output) == nil {
				output["next_action"] = "call ingest_retest_browser_evidence with receipt_path"
				return jsonResult(output)
			}
			return result, nil
		},
	})
}
