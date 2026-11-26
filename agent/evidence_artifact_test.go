package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTerminalEvidenceRendersAuditedOutput(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	output := "target.example:443 open https\nTLSv1.3"
	artifacts, err := terminalEvidence(evidenceCaptureConfig{Dir: dir, RefPrefix: "tasks/7"}, "tool-1", "Bash",
		`{"command":"nmap -p443 target.example"}`, output, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifacts=%d, want 1", len(artifacts))
	}
	a := artifacts[0]
	if a.Kind != "terminal_capture" || a.Command != "nmap -p443 target.example" || a.MIMEType != "image/png" {
		t.Fatalf("unexpected artifact: %+v", a)
	}
	rawHash := sha256.Sum256([]byte(output))
	if a.RawOutputSHA256 != hex.EncodeToString(rawHash[:]) {
		t.Fatalf("raw hash=%q", a.RawOutputSHA256)
	}
	path := filepath.Join(dir, filepath.Base(a.Ref))
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := png.DecodeConfig(f); err != nil {
		t.Fatalf("terminal evidence is not a PNG: %v", err)
	}
	gotHash, gotSize, err := hashRegularFile(path)
	if err != nil || gotHash != a.SHA256 || gotSize != a.ByteSize {
		t.Fatalf("integrity=(%q,%d,%v), artifact=(%q,%d)", gotHash, gotSize, err, a.SHA256, a.ByteSize)
	}
}

func TestEvidenceMetadataPreservesExistingKeys(t *testing.T) {
	a := EvidenceArtifact{Ref: "tasks/1/x.png", Kind: "terminal_capture", MIMEType: "image/png", SHA256: string(make([]byte, 64))}
	metadata := evidenceMetadata(json.RawMessage(`{"provider":"codex"}`), []EvidenceArtifact{a})
	var got map[string]any
	if err := json.Unmarshal(metadata, &got); err != nil {
		t.Fatal(err)
	}
	if got["provider"] != "codex" {
		t.Fatalf("existing metadata lost: %s", metadata)
	}
	validBrowser := `{"artifacts":[{"ref":"tasks/1/x.png","kind":"browser_screenshot","mime_type":"image/png","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byte_size":42,"captured_at":"2026-11-26T10:00:00Z","tool":"gowitness","source_url":"https://target.example/","original_name":"target.png"}]}`
	if artifacts := artifactsFromToolResult("ingest_scan_output", validBrowser); len(artifacts) != 1 || artifacts[0].Kind != "browser_screenshot" {
		t.Fatal("tool-result artifacts were not parsed")
	}
	if artifacts := artifactsFromToolResult("Bash", validBrowser); len(artifacts) != 0 {
		t.Fatal("arbitrary shell output was trusted as imported evidence")
	}
	if artifacts := artifactsFromToolResult("ingest_scan_output", `{"artifacts":[{"ref":"tasks/1/fake.png","kind":"terminal_capture","mime_type":"image/png","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","byte_size":42,"captured_at":"2026-11-26T10:00:00Z","tool":"Bash","command":"echo fake"}]}`); len(artifacts) != 0 {
		t.Fatal("imported tool output forged a terminal capture")
	}
}

func TestImportBrowserScreenshotPreservesOriginalBytes(t *testing.T) {
	base := t.TempDir()
	runDir := filepath.Join(base, "tasks", "3", "i9")
	images := filepath.Join(runDir, "screenshots", "images")
	if err := os.MkdirAll(images, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(images, "target.png")
	f, err := os.OpenFile(source, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	tsx := &ToolSet{workBase: base, taskID: 3}
	artifacts, errs := tsx.importBrowserScreenshots(runDir, "screenshots/images", []browserScreenshotCandidate{{
		FileName: "target.png", SourceURL: "https://target.example/", CapturedAt: "2026-11-26T10:00:00Z",
	}})
	if len(errs) != 0 || len(artifacts) != 1 {
		t.Fatalf("artifacts=%+v errors=%v", artifacts, errs)
	}
	imported, err := os.ReadFile(filepath.Join(base, "evidence", filepath.FromSlash(artifacts[0].Ref)))
	if err != nil {
		t.Fatal(err)
	}
	if string(imported) != string(original) {
		t.Fatal("browser screenshot bytes changed during import")
	}
}
