package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// toolIngestRetestBrowserEvidence is the conversation-safe adapter for the
// task-bound Playwright importer. Retest agents run in isolated conversation
// directories and do not receive a ToolSet with a task store, so the adapter
// derives the task exclusively from the server-owned retest/conversation row.
// Tool input cannot redirect evidence to another task or finding.
func (s *Server) toolIngestRetestBrowserEvidence() actool.CoreTool {
	template := agent.NewToolSet(nil, "").IngestBrowserEvidenceTool()
	return actool.Build(actool.Spec{
		Name:        "ingest_retest_browser_evidence",
		Description: template.Description() + " This retest-only adapter derives the destination finding and task from the current retest conversation; no task or finding ID is accepted from the model.",
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
			if retest == nil {
				return actool.Errorf("the current session is not associated with a finding retest"), nil
			}
			if retest.Status != "running" {
				return actool.Errorf("browser evidence can only be attached while this finding retest is running"), nil
			}
			finding, err := s.m.pg.GetFinding(retest.FindingID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if finding == nil || finding.TaskID == nil || finding.NodeID == nil {
				return actool.Errorf("the retested finding has no live task/graph context for evidence storage"), nil
			}
			task := s.m.ResolveTask(i64s(*finding.TaskID))
			if task == nil {
				return actool.Errorf("the retested finding's task is unavailable"), nil
			}
			if tc == nil || strings.TrimSpace(tc.ToolUseID) == "" {
				return actool.Errorf("browser evidence import requires an audited tool call id"), nil
			}
			expectedRunDir := filepath.Join(s.m.dir, "sessions", fmt.Sprintf("conv-%d", conversationID))
			actualRunDir, pathErr := filepath.Abs(tc.WorkingDir)
			expectedRunDir, expectedErr := filepath.Abs(expectedRunDir)
			if pathErr != nil || expectedErr != nil || actualRunDir != expectedRunDir {
				return actool.Errorf("browser evidence import requires this retest conversation's working directory"), nil
			}
			tsx := agent.NewToolSet(task.Store, "retester")
			tsx.SetTaskID(*finding.TaskID)
			tsx.SetWorkBase(s.m.dir)
			result, callErr := tsx.IngestBrowserEvidenceTool().Call(ctx, in, tc)
			if callErr != nil || result.IsError {
				return result, callErr
			}

			// Retest conversations have their own transcript store. Mirror the
			// successful code-owned result into the finding's exploration so its
			// immutable file/hash declaration is visible through the ordinary
			// finding-evidence lineage. This is deliberately done here, from the
			// Result returned by ARTEX's importer, rather than by accepting an
			// arbitrary JSON blob supplied by the model or a shell command.
			output := result.Flatten()
			artifacts := agent.EvidenceArtifactsFromToolResult("ingest_retest_browser_evidence", output)
			if len(artifacts) == 0 {
				return actool.Errorf("browser evidence importer returned no verified screenshot declaration"), nil
			}
			metadata, marshalErr := json.Marshal(map[string]any{
				"evidence_artifacts": artifacts,
				"evidence_import": map[string]any{
					"source": "finding_retest", "code_owned": true,
					"finding_id": finding.ID, "retest_id": retest.ID,
					"conversation_id":    conversationID,
					"source_tool_use_id": strings.TrimSpace(tc.ToolUseID),
					"tool":               "ingest_retest_browser_evidence",
				},
			})
			if marshalErr != nil {
				return actool.Errorf("browser evidence audit metadata could not be encoded"), nil
			}
			toolUseID := fmt.Sprintf("retest-%d-%s", retest.ID, strings.TrimSpace(tc.ToolUseID))
			activity := db.Activity{
				NodeID: finding.NodeID, Worker: db.FindingRetestAgentKey,
				Kind: "tool_result", Tool: "ingest_retest_browser_evidence", ToolUseID: toolUseID,
				Summary: "Imported hash-verified Playwright evidence for finding retest",
				Detail:  output, Metadata: metadata, CreatedAt: time.Now().UTC(),
			}
			activityID, appendErr := task.Store.AppendActivity(activity)
			if appendErr != nil {
				return actool.Errorf("browser evidence was stored but its finding audit record could not be written"), nil
			}
			activity.ID = activityID
			if err := s.reconcileFindingArtifactEvidence(ctx, finding.ID); err != nil {
				return actool.Errorf("browser evidence was stored but its finding evidence revision could not be recorded"), nil
			}
			if s.engine != nil {
				s.engine.Broadcaster().Publish(task.ID, activity)
				s.engine.touch(task.ID)
			}
			return result, nil
		},
	})
}
