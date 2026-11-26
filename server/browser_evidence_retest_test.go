package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

func writeRetestEvidencePNG(t *testing.T, path string) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 5, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 5; x++ {
			img.Set(x, y, color.RGBA{R: uint8(40 + x), G: uint8(80 + y), B: 120, A: 255})
		}
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRetestBrowserEvidenceCreatesFindingLinkedAuditedActivity(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}

	taskRow, err := pg.CreateTaskWithOptions("Playwright retest evidence", "attach real browser proof", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	es := pg.Exploration(taskRow.ExplorationID)
	producer, err := es.AddIntent(map[string]any{"summary": "produce finding"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	findingNode, err := es.AddNode(db.KindFinding, map[string]any{"name": "browser retest proof"}, 9, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(producer, db.RelYields, findingNode); err != nil {
		t.Fatal(err)
	}
	findingID, err := pg.AddFinding(taskRow.ID, findingNode, "browser", "browser evidence test", "medium", "summary", "proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	retest, conv, _, err := pg.CreateFindingRetest(t.Context(), findingID, "capture original browser proof")
	if err != nil {
		t.Fatal(err)
	}
	if started, err := pg.StartFindingRetest(t.Context(), retest.ID); err != nil || !started {
		t.Fatalf("start retest: started=%v err=%v", started, err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID)
		_, _ = pg.DeleteFinding(findingID)
		_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskRow.ID)
		_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, taskRow.ExplorationID)
		pg.Close()
	})

	dataDir := t.TempDir()
	runDir := filepath.Join(dataDir, "sessions", "conv-"+strconv.FormatInt(conv.ID, 10))
	imageBytes := writeRetestEvidencePNG(t, filepath.Join(dataDir, "fake-playwright-source.png"))
	digest := sha256.Sum256(imageBytes)
	fakeBin := filepath.Join(dataDir, "fake-bin")
	if err := os.MkdirAll(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	fakePlaywright := filepath.Join(fakeBin, "playwright")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Version fixture-2758"; exit 0; fi
har=""; previous=""; last=""
for argument in "$@"; do
  if [ "$previous" = "--save-har" ]; then har="$argument"; fi
  previous="$argument"; last="$argument"
done
cp "$FAKE_PLAYWRIGHT_SOURCE" "$last"
if [ -n "$har" ]; then printf '%s' '{"log":{"entries":[]}}' > "$har"; fi
`
	if err := os.WriteFile(fakePlaywright, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_PLAYWRIGHT_SOURCE", filepath.Join(dataDir, "fake-playwright-source.png"))
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	captureInput := json.RawMessage(`{"source_url":"https://hermes.example.test/retest","save_trace":true}`)
	if err != nil {
		t.Fatal(err)
	}
	taskID := strconv.FormatInt(taskRow.ID, 10)
	s := &Server{m: &Manager{pg: pg, dir: dataDir, tasks: map[string]*Task{
		taskID: {ID: taskID, ExpID: taskRow.ExplorationID, Store: es},
	}}}
	ctx := intercept.WithConvID(context.Background(), conv.ID)
	wrongResult, err := s.toolCaptureRetestPlaywrightEvidence().Call(ctx, captureInput, &actool.ToolContext{
		WorkingDir: filepath.Join(dataDir, "tasks", taskID, "i999"), ToolUseID: "wrong-workspace",
	})
	if err != nil || !wrongResult.IsError {
		t.Fatalf("cross-workspace capture result=%s is_error=%v err=%v", wrongResult.Flatten(), wrongResult.IsError, err)
	}
	captureResult, err := s.toolCaptureRetestPlaywrightEvidence().Call(ctx, captureInput, &actool.ToolContext{
		WorkingDir: runDir, ToolUseID: "browser-capture-1",
	})
	if err != nil || captureResult.IsError {
		t.Fatalf("capture result=%s is_error=%v err=%v", captureResult.Flatten(), captureResult.IsError, err)
	}
	var captureEnvelope struct {
		ReceiptPath string `json:"receipt_path"`
		NextAction  string `json:"next_action"`
	}
	if err := json.Unmarshal([]byte(captureResult.Flatten()), &captureEnvelope); err != nil || captureEnvelope.ReceiptPath == "" || !strings.Contains(captureEnvelope.NextAction, "ingest_retest_browser_evidence") {
		t.Fatalf("capture envelope=%s err=%v", captureResult.Flatten(), err)
	}
	input, _ := json.Marshal(map[string]any{"receipt_path": captureEnvelope.ReceiptPath})
	result, err := s.toolIngestRetestBrowserEvidence().Call(ctx, input, &actool.ToolContext{
		WorkingDir: runDir, ToolUseID: "browser-proof-1",
	})
	if err != nil || result.IsError {
		t.Fatalf("import result=%s is_error=%v err=%v", result.Flatten(), result.IsError, err)
	}

	activities, err := es.EvidenceActivities([]int64{findingNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(activities) != 1 {
		t.Fatalf("evidence activities=%+v", activities)
	}
	a := activities[0]
	if a.Tool != "ingest_retest_browser_evidence" || a.ToolUseID != "retest-"+strconv.FormatInt(retest.ID, 10)+"-browser-proof-1" || a.NodeID == nil || *a.NodeID != findingNode {
		t.Fatalf("audited activity=%+v", a)
	}
	var metadata struct {
		Artifacts []json.RawMessage `json:"evidence_artifacts"`
		Import    struct {
			CodeOwned      bool   `json:"code_owned"`
			FindingID      int64  `json:"finding_id"`
			RetestID       int64  `json:"retest_id"`
			ConversationID int64  `json:"conversation_id"`
			SourceToolUse  string `json:"source_tool_use_id"`
		} `json:"evidence_import"`
	}
	if err := json.Unmarshal(a.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Artifacts) != 1 || !metadata.Import.CodeOwned || metadata.Import.FindingID != findingID || metadata.Import.RetestID != retest.ID || metadata.Import.ConversationID != conv.ID || metadata.Import.SourceToolUse != "browser-proof-1" {
		t.Fatalf("audit metadata=%s", a.Metadata)
	}

	items, err := s.findingArtifacts(findingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].Verified || items[0].SHA256 != hex.EncodeToString(digest[:]) || items[0].SourceURL != "https://hermes.example.test/retest" {
		t.Fatalf("finding artifacts=%+v", items)
	}
}
