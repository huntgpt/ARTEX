package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestIngestBrowserEvidenceManagedBindingIsWorkerOnly(t *testing.T) {
	wanted := map[string]bool{"capture_playwright_evidence": false, "ingest_browser_evidence": false}
	for _, seed := range BuiltinToolSeeds() {
		if _, ok := wanted[seed.Key]; !ok {
			continue
		}
		if len(seed.Agents) != 1 || seed.Agents[0] != "worker" {
			t.Fatalf("%s agents=%v, want [worker]", seed.Key, seed.Agents)
		}
		wanted[seed.Key] = true
	}
	for key, found := range wanted {
		if !found {
			t.Fatalf("%s was not added to the managed tool catalog", key)
		}
	}
}

func writeBrowserEvidencePNG(t *testing.T, path string) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for y := 0; y < 6; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: uint8(20 + x), G: uint8(30 + y), B: 40, A: 255})
		}
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func browserEvidenceCall(t *testing.T, base, runDir string, input map[string]any) (string, bool) {
	t.Helper()
	tsx := NewToolSet(&db.ExplorationStore{}, "worker-test")
	tsx.SetTaskID(7)
	tsx.SetWorkBase(base)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tsx.IngestBrowserEvidenceTool().Call(context.Background(), raw, &actool.ToolContext{WorkingDir: runDir, ToolUseID: "import-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Flatten(), res.IsError
}

func writeBrowserReceiptFixture(t *testing.T, base, runDir string, claims browserCaptureReceipt) string {
	t.Helper()
	workspace, err := browserRunWorkspace(base, runDir)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Version == 0 {
		claims.Version = browserCaptureReceiptVersion
	}
	if claims.ReceiptID == "" {
		claims.ReceiptID = "fixture-receipt"
	}
	if claims.TaskID == 0 {
		claims.TaskID = 7
	}
	if claims.Workspace == "" {
		claims.Workspace = workspace
	}
	if claims.CaptureTool == "" {
		claims.CaptureTool = "artex_playwright_cli"
	}
	if claims.CaptureToolUseID == "" {
		claims.CaptureToolUseID = "capture-fixture-2758"
	}
	if claims.Browser == "" {
		claims.Browser = "chromium"
	}
	if claims.PlaywrightVersion == "" {
		claims.PlaywrightVersion = "Version fixture"
	}
	name := claims.ReceiptID + ".receipt.json"
	if err := writeBrowserCaptureReceipt(filepath.Join(runDir, name), claims); err != nil {
		t.Fatal(err)
	}
	return name
}

func shaText(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestIngestBrowserEvidenceValidPlaywrightScreenshotAndTrace(t *testing.T) {
	// Local-only fixture follows the Hermes #2758 artifact shape: one original
	// browser screenshot plus one optional Playwright network-event JSON file.
	// No request is sent to the referenced URL.
	base := t.TempDir()
	runDir := filepath.Join(base, "tasks", "7", "i42")
	imageBytes := writeBrowserEvidencePNG(t, filepath.Join(runDir, "hermes.png"))
	traceBytes := []byte(`[{"url":"https://hermes.example.test/","method":"GET"}]`)
	if err := os.WriteFile(filepath.Join(runDir, "network.json"), traceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := writeBrowserReceiptFixture(t, base, runDir, browserCaptureReceipt{
		SourceURL: "https://hermes.example.test/app", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "hermes.png", ScreenshotSHA256: shaText(imageBytes),
		TracePath: "network.json", TraceSHA256: shaText(traceBytes), TraceFormat: "json",
	})
	out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": receipt})
	if isErr {
		t.Fatal(out)
	}
	var envelope struct {
		Artifacts []EvidenceArtifact `json:"artifacts"`
		Trace     struct {
			Ref       string `json:"ref"`
			SHA256    string `json:"sha256"`
			ByteSize  int64  `json:"byte_size"`
			Sensitive bool   `json:"sensitive"`
			Visible   bool   `json:"gallery_visible"`
		} `json:"network_trace"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Artifacts) != 1 {
		t.Fatalf("artifacts=%+v", envelope.Artifacts)
	}
	a := envelope.Artifacts[0]
	if a.Kind != "browser_screenshot" || a.Tool != "playwright" || a.MIMEType != "image/png" || a.SHA256 != shaText(imageBytes) || a.SourceURL != "https://hermes.example.test/app" {
		t.Fatalf("artifact=%+v", a)
	}
	if envelope.Trace.Ref == "" || envelope.Trace.SHA256 != shaText(traceBytes) || envelope.Trace.ByteSize != int64(len(traceBytes)) || !envelope.Trace.Sensitive || envelope.Trace.Visible {
		t.Fatalf("trace=%+v", envelope.Trace)
	}
	imageStored, err := os.ReadFile(filepath.Join(base, "evidence", filepath.FromSlash(a.Ref)))
	if err != nil || string(imageStored) != string(imageBytes) {
		t.Fatalf("stored image changed: err=%v", err)
	}
	traceStored, err := os.ReadFile(filepath.Join(base, "evidence", filepath.FromSlash(envelope.Trace.Ref)))
	if err != nil || string(traceStored) != string(traceBytes) {
		t.Fatalf("stored trace changed: err=%v", err)
	}
	// A source-file change after import cannot mutate the protected copy.
	if err := os.WriteFile(filepath.Join(runDir, "hermes.png"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(base, "evidence", filepath.FromSlash(a.Ref)))
	if string(after) != string(imageBytes) {
		t.Fatal("evidence changed after source tamper")
	}
}

func TestIngestBrowserEvidenceRejectsForgeryAndUnsafePaths(t *testing.T) {
	base := t.TempDir()
	runDir := filepath.Join(base, "tasks", "7", "i42")
	imageBytes := writeBrowserEvidencePNG(t, filepath.Join(runDir, "real.png"))

	// Regression: valid image bytes and a caller-supplied hash/URL are not
	// capture provenance. Without a code-owned signed receipt the image cannot
	// become verified Playwright evidence.
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{
		"screenshot_path": "real.png", "screenshot_sha256": shaText(imageBytes),
		"source_url": "https://app.example.test/", "captured_at": "2026-11-26T12:00:00Z",
	}); !isErr {
		t.Fatalf("accepted arbitrary valid PNG without receipt: %s", out)
	}

	unsigned := filepath.Join(runDir, "forged.receipt.json")
	if err := os.WriteFile(unsigned, []byte(`{"claims":{"version":1},"signature":"`+strings.Repeat("0", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": filepath.Base(unsigned)}); !isErr {
		t.Fatalf("accepted unsigned receipt: %s", out)
	}
	validReceipt := writeBrowserReceiptFixture(t, base, runDir, browserCaptureReceipt{
		ReceiptID: "tampered-receipt", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "real.png", ScreenshotSHA256: shaText(imageBytes),
	})
	validReceiptPath := filepath.Join(runDir, validReceipt)
	validReceiptBytes, err := os.ReadFile(validReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedReceiptBytes := bytes.Replace(validReceiptBytes, []byte("app.example.test"), []byte("evil.example.test"), 1)
	if err := os.WriteFile(validReceiptPath, tamperedReceiptBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": validReceipt}); !isErr {
		t.Fatalf("accepted tampered signed receipt: %s", out)
	}

	cases := map[string]browserCaptureReceipt{
		"hash mismatch": {
			ReceiptID: "bad-hash", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
			ScreenshotPath: "real.png", ScreenshotSHA256: strings.Repeat("0", 64),
		},
		"userinfo URL": {
			ReceiptID: "bad-url", SourceURL: "https://user:secret@app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
			ScreenshotPath: "real.png", ScreenshotSHA256: shaText(imageBytes),
		},
		"future capture": {
			ReceiptID: "future", SourceURL: "https://app.example.test/", CapturedAt: "2999-01-01T00:00:00Z",
			ScreenshotPath: "real.png", ScreenshotSHA256: shaText(imageBytes),
		},
		"trace declaration incomplete": {
			ReceiptID: "bad-trace", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
			ScreenshotPath: "real.png", ScreenshotSHA256: shaText(imageBytes), TracePath: "trace.json",
		},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			receipt := writeBrowserReceiptFixture(t, base, runDir, claims)
			if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": receipt}); !isErr {
				t.Fatalf("accepted unsafe receipt: %s", out)
			}
		})
	}
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": "../forged.receipt.json"}); !isErr {
		t.Fatalf("accepted receipt path traversal: %s", out)
	}

	if err := os.WriteFile(filepath.Join(runDir, "fake.png"), []byte("not a PNG"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeReceipt := writeBrowserReceiptFixture(t, base, runDir, browserCaptureReceipt{
		ReceiptID: "fake-image", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "fake.png", ScreenshotSHA256: shaText([]byte("not a PNG")),
	})
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": fakeReceipt}); !isErr {
		t.Fatalf("accepted forged image: %s", out)
	}

	outside := filepath.Join(base, "outside.png")
	outsideBytes := writeBrowserEvidencePNG(t, outside)
	if err := os.Symlink(outside, filepath.Join(runDir, "link.png")); err != nil {
		t.Fatal(err)
	}
	linkReceipt := writeBrowserReceiptFixture(t, base, runDir, browserCaptureReceipt{
		ReceiptID: "link-image", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "link.png", ScreenshotSHA256: shaText(outsideBytes),
	})
	if out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": linkReceipt}); !isErr {
		t.Fatalf("accepted symlink: %s", out)
	}

	otherTaskDir := filepath.Join(base, "tasks", "8", "i42")
	otherTaskBytes := writeBrowserEvidencePNG(t, filepath.Join(otherTaskDir, "other-task.png"))
	otherReceipt := writeBrowserReceiptFixture(t, base, otherTaskDir, browserCaptureReceipt{
		ReceiptID: "other-task", TaskID: 8, SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "other-task.png", ScreenshotSHA256: shaText(otherTaskBytes),
	})
	if out, isErr := browserEvidenceCall(t, base, otherTaskDir, map[string]any{"receipt_path": otherReceipt}); !isErr {
		t.Fatalf("accepted another task's workspace: %s", out)
	}
}

func TestIngestBrowserEvidenceRejectsMalformedTrace(t *testing.T) {
	base := t.TempDir()
	runDir := filepath.Join(base, "tasks", "7", "i42")
	imageBytes := writeBrowserEvidencePNG(t, filepath.Join(runDir, "real.png"))
	trace := []byte(`{"log":{"entries":"not-an-array"}}`)
	if err := os.WriteFile(filepath.Join(runDir, "bad.har"), trace, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := writeBrowserReceiptFixture(t, base, runDir, browserCaptureReceipt{
		ReceiptID: "malformed-har", SourceURL: "https://app.example.test/", CapturedAt: "2026-11-26T12:00:00Z",
		ScreenshotPath: "real.png", ScreenshotSHA256: shaText(imageBytes),
		TracePath: "bad.har", TraceSHA256: shaText(trace), TraceFormat: "har",
	})
	out, isErr := browserEvidenceCall(t, base, runDir, map[string]any{"receipt_path": receipt})
	if !isErr || !strings.Contains(out, "HAR") {
		t.Fatalf("malformed HAR result: is_error=%v out=%s", isErr, out)
	}
}
