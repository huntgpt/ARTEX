package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Autumn-27/artex/ad"
	"github.com/Autumn-27/artex/db"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// ingestADObservation imports operator-supplied, read-only AD collector output.
// It does not execute a collector, contact a target or promote AD principals to
// the shared asset graph. The tool is catalogued but unbound by default.
func (t *ToolSet) ingestADObservation() actool.CoreTool {
	const name = "ingest_ad_observation"
	return actool.Build(actool.Spec{
		Name: name,
		Description: "Import an operator-supplied BloodHound/SharpHound JSON or normalized ARTEX AD/OpenGraph artifact into this task's private AD exploration graph. " +
			"This tool only parses an existing file; it does not run a collector or contact a target. " +
			"Only typed SIDs/GUIDs, object types and validated DNS hostnames become graph fields. Target-controlled text remains inert JSON detail. " +
			"The path must be inside the current working directory; symlinks, hard links, non-regular files and files over 256 MiB are refused. " +
			"Returns entity/relationship counts plus skipped, over-cap and truncation status.",
		Schema: obj(map[string]any{
			"format": map[string]any{"type": "string", "enum": []string{"bloodhound-json", "artex-ad-graph-json"}, "description": "collector artifact format"},
			"path":   str("artifact path relative to the current working directory"),
			"run_id": map[string]any{"type": "integer", "description": "optional existing approved/running AD collection run; omitted creates an audited operator-upload run"},
		}, "format", "path"),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision {
			return acperm.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return t.needExploration(name, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				if t.ts == nil {
					return actool.Errorf("ingest_ad_observation requires a task exploration"), nil
				}
				var input struct {
					Format string `json:"format"`
					Path   string `json:"path"`
					RunID  int64  `json:"run_id"`
				}
				if err := json.Unmarshal(in, &input); err != nil {
					return actool.Errorf("invalid input: " + err.Error()), nil
				}
				if (input.Format != "bloodhound-json" && input.Format != "artex-ad-graph-json") || strings.TrimSpace(input.Path) == "" {
					return actool.Errorf("format must be bloodhound-json or artex-ad-graph-json and path is required"), nil
				}
				workingDir := ""
				if tc != nil {
					workingDir = tc.WorkingDir
				}
				file, err := openScanOutputInBase(t.workBase, workingDir, input.Path)
				if err != nil {
					return actool.Errorf("open: " + err.Error()), nil
				}
				defer file.Close()
				info, err := file.Stat()
				if err != nil {
					return actool.Errorf("stat: " + err.Error()), nil
				}
				hasher := sha256.New()
				if _, err := io.Copy(hasher, io.LimitReader(file, scanMaxFileBytes+1)); err != nil {
					return actool.Errorf("hash: " + err.Error()), nil
				}
				if _, err := file.Seek(0, io.SeekStart); err != nil {
					return actool.Errorf("rewind: " + err.Error()), nil
				}
				digest := fmt.Sprintf("%x", hasher.Sum(nil))

				runID := input.RunID
				if runID == 0 {
					run, err := t.ts.CreateADCollectionRun(ctx, "operator-upload", "offline-import", "agent")
					if err != nil {
						return actool.Errorf("create AD collection run: " + err.Error()), nil
					}
					runID = run.ID
					if _, err = t.ts.TransitionADCollectionRun(ctx, runID, ad.RunApproved, "agent", "operator-supplied offline artifact"); err != nil {
						return actool.Errorf("approve AD collection run: " + err.Error()), nil
					}
				}
				run, err := t.ts.ADCollectionRun(ctx, runID)
				if err != nil || run == nil {
					return actool.Errorf("AD collection run not found"), nil
				}
				if run.State == ad.RunApproved || run.State == ad.RunRunning {
					if _, err = t.ts.TransitionADCollectionRun(ctx, runID, ad.RunIngesting, "agent", ""); err != nil {
						return actool.Errorf("start AD ingest: " + err.Error()), nil
					}
				} else if run.State != ad.RunIngesting {
					return actool.Errorf("AD collection run must be approved, running, or ingesting"), nil
				}
				artifact := db.ADCollectionArtifact{Kind: input.Format, LogicalPath: input.Path, SHA256: digest, ByteSize: info.Size(), State: "received"}
				if err := t.ts.AddADCollectionArtifact(ctx, runID, artifact); err != nil {
					_ = t.ts.FinishADCollectionRun(ctx, runID, ad.RunFailed, db.ADIngestResult{}, "record artifact: "+err.Error())
					return actool.Errorf("record AD artifact: " + err.Error()), nil
				}
				var observation ad.Observation
				if input.Format == "artex-ad-graph-json" {
					observation, err = ad.ParseARTEXGraph(io.LimitReader(file, scanMaxFileBytes))
				} else {
					observation, err = ad.ParseBloodHound(io.LimitReader(file, scanMaxFileBytes))
				}
				if err != nil {
					artifact.State, artifact.ErrorDetail = "rejected", "artifact could not be parsed"
					_ = t.ts.AddADCollectionArtifact(ctx, runID, artifact)
					_ = t.ts.FinishADCollectionRun(ctx, runID, ad.RunFailed, db.ADIngestResult{}, "artifact could not be parsed as BloodHound JSON")
					return actool.Errorf("artifact could not be parsed as BloodHound JSON"), nil
				}
				result, err := t.ts.IngestADObservation(ctx, observation)
				if err != nil {
					artifact.State, artifact.ErrorDetail = "failed", "store AD observation failed"
					_ = t.ts.AddADCollectionArtifact(ctx, runID, artifact)
					_ = t.ts.FinishADCollectionRun(ctx, runID, ad.RunFailed, result, "store AD observation: "+err.Error())
					return actool.Errorf("store AD observation: " + err.Error()), nil
				}
				artifact.State, artifact.ErrorDetail = "ingested", ""
				if err := t.ts.AddADCollectionArtifact(ctx, runID, artifact); err != nil {
					return actool.Errorf("finalize AD artifact: " + err.Error()), nil
				}
				terminal := ad.RunComplete
				if result.Truncated || result.OverCap > 0 {
					terminal = ad.RunPartial
				}
				if err := t.ts.FinishADCollectionRun(ctx, runID, terminal, result, ""); err != nil {
					return actool.Errorf("finish AD collection run: " + err.Error()), nil
				}
				return jsonResult(map[string]any{
					"format": input.Format, "run_id": runID, "artifact_sha256": digest, "records": result.Records,
					"entities_upserted": result.EntitiesUpserted, "edges_upserted": result.EdgesUpserted,
					"skipped": result.Skipped, "over_cap": result.OverCap, "truncated": result.Truncated,
				})
			})(ctx, in)
		},
	})
}
