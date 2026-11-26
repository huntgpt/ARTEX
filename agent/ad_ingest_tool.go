package agent

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/Autumn-27/artex/ad"
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
		Description: "Import an operator-supplied BloodHound/SharpHound JSON artifact into this task's private AD exploration graph. " +
			"This tool only parses an existing file; it does not run a collector or contact a target. " +
			"Only typed SIDs/GUIDs, object types and validated DNS hostnames become graph fields. Target-controlled text remains inert JSON detail. " +
			"The path must be inside the current working directory; symlinks, hard links, non-regular files and files over 256 MiB are refused. " +
			"Returns entity/relationship counts plus skipped, over-cap and truncation status.",
		Schema: obj(map[string]any{
			"format": map[string]any{"type": "string", "enum": []string{"bloodhound-json"}, "description": "collector artifact format"},
			"path":   str("artifact path relative to the current working directory"),
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
				}
				if err := json.Unmarshal(in, &input); err != nil {
					return actool.Errorf("invalid input: " + err.Error()), nil
				}
				if input.Format != "bloodhound-json" || strings.TrimSpace(input.Path) == "" {
					return actool.Errorf("format must be bloodhound-json and path is required"), nil
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
				observation, err := ad.ParseBloodHound(io.LimitReader(file, scanMaxFileBytes))
				if err != nil {
					return actool.Errorf("artifact could not be parsed as BloodHound JSON"), nil
				}
				result, err := t.ts.IngestADObservation(ctx, observation)
				if err != nil {
					return actool.Errorf("store AD observation: " + err.Error()), nil
				}
				return jsonResult(map[string]any{
					"format": input.Format, "records": result.Records,
					"entities_upserted": result.EntitiesUpserted, "edges_upserted": result.EdgesUpserted,
					"skipped": result.Skipped, "over_cap": result.OverCap, "truncated": result.Truncated,
				})
			})(ctx, in)
		},
	})
}
