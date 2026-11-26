package agent

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// recordFindingFollowUpRetestResult is the Worker-side form of the Retester
// tool. It deliberately accepts no finding or intent id: the server-owned
// RunInfo and exact finding --derived_from--> intent edge own attribution.
func (t *ToolSet) recordFindingFollowUpRetestResult() actool.CoreTool {
	return t.writeExpTool("record_finding_followup_retest_result", "Save the single formal conclusion for this finding-linked Worker follow-up. This tool is available to every Worker but succeeds only when the current intent was derived directly from an actionable finding. Record only this run's actual verification; use inconclusive for missing prerequisites, unreachable targets, or insufficient evidence. Do not pass a finding or intent id: ARTEX binds both from the current run.",
		obj(map[string]any{
			"verdict":  map[string]any{"type": "string", "enum": []string{"reproduced", "fixed", "inconclusive"}},
			"summary":  str("summary of this follow-up validation conclusion"),
			"evidence": str("Markdown: actual checks, observations, comparisons, and the evidence or blocker supporting the conclusion"),
		}, "verdict", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Verdict  string `json:"verdict"`
				Summary  string `json:"summary"`
				Evidence string `json:"evidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ri := RunInfoFrom(ctx)
			if ri.IntentID <= 0 {
				return actool.Errorf("record_finding_followup_retest_result requires the current Worker intent context"), nil
			}
			if err := t.ts.RecordFindingFollowUpRetestResult(ctx, ri.IntentID, a.Verdict, a.Summary, a.Evidence); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict, "source_intent_id": ri.IntentID})
		})
}
