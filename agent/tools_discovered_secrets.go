package agent

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// listDiscoveredSecrets gives agents enough non-plaintext evidence to verify a
// scanner import without ever revealing a secret. Plaintext access remains an
// explicit audited operator action through the server reveal endpoint.
func (t *ToolSet) listDiscoveredSecrets() actool.CoreTool {
	return readTool(
		"list_discovered_secrets",
		"List this task's discovered-secret metadata without plaintext. Returns detector, source/location, commit, verification state, SHA-256 and booleans proving that encrypted Raw/RawV2 values are present. Use this to reconcile TruffleHog ingestion; use no other tool to retrieve plaintext.",
		obj(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.ts == nil {
				return actool.Errorf("list_discovered_secrets is not enabled: task store is not initialized"), nil
			}
			taskID := t.taskID
			if taskID <= 0 {
				var err error
				taskID, err = t.ts.TaskID()
				if err != nil || taskID <= 0 {
					return actool.Errorf("list_discovered_secrets is only available inside a task"), nil
				}
				t.taskID = taskID
			}
			items, err := t.ts.ListDiscoveredSecrets(taskID)
			if err != nil {
				return actool.Errorf("list_discovered_secrets failed: " + err.Error()), nil
			}
			out := make([]map[string]any, 0, len(items))
			for _, item := range items {
				out = append(out, map[string]any{
					"id": item.ID, "detector": item.Detector,
					"source_type": item.SourceType, "source_name": item.SourceName,
					"repository": item.Repository, "file_path": item.FilePath,
					"line_number": item.LineNumber, "commit_hash": item.CommitHash,
					"verified": item.Verified, "secret_sha256": item.SecretSHA256,
					"encrypted_value_present":    item.EncryptedValuePresent,
					"encrypted_value_v2_present": item.EncryptedValueV2Present,
				})
			}
			return jsonResult(map[string]any{"count": len(out), "secrets": out})
		})
}
