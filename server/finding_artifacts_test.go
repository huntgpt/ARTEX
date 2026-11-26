package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestConfinedEvidencePath(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "tasks", "1", "capture.png")
	if err := os.MkdirAll(filepath.Dir(valid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := confinedEvidencePath(root, "tasks/1/capture.png"); err != nil || got != valid {
		t.Fatalf("valid path=(%q,%v), want %q", got, err, valid)
	}
	if _, err := confinedEvidencePath(root, "../secret"); err == nil {
		t.Fatal("path traversal accepted")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := confinedEvidencePath(root, "link/capture.png"); err == nil {
		t.Fatal("symlink path accepted")
	}
}

func TestEvidenceArtifactRequiresAuditedToolProvenance(t *testing.T) {
	output := "target.example:443 open https\nTLSv1.3"
	raw := sha256.Sum256([]byte(output))
	artifact := agent.EvidenceArtifact{
		Ref: "tasks/7/terminal-proof.png", Kind: "terminal_capture", Label: "Actual command output",
		MIMEType: "image/png", SHA256: hex.EncodeToString(make([]byte, 32)), ByteSize: 4,
		CapturedAt: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC), Tool: "Bash",
		Command: "nmap -p443 target.example", RawOutputSHA256: hex.EncodeToString(raw[:]),
	}
	activity := db.Activity{Kind: "tool_result", Tool: "Bash", ToolUseID: "tool-1", Detail: output}
	if !validEvidenceArtifact(activity, artifact) {
		t.Fatal("audited terminal artifact was rejected")
	}
	forged := artifact
	forged.RawOutputSHA256 = hex.EncodeToString(make([]byte, 32))
	if validEvidenceArtifact(activity, forged) {
		t.Fatal("terminal artifact detached from the audited output was accepted")
	}
	if validEvidenceArtifact(db.Activity{Kind: "tool_result", Tool: "Bash", Detail: output}, artifact) {
		t.Fatal("terminal artifact without a tool-use execution id was accepted")
	}
}

func TestBrowserEvidenceMustBeDeclaredByScannerIngestResult(t *testing.T) {
	artifact := agent.EvidenceArtifact{
		Ref: "tasks/7/browser-proof.png", Kind: "browser_screenshot", Label: "Actual browser screenshot",
		MIMEType: "image/png", SHA256: hex.EncodeToString(make([]byte, 32)), ByteSize: 4,
		CapturedAt: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC), Tool: "gowitness",
		SourceURL: "https://target.example/", OriginalName: "target.png",
	}
	envelope, err := json.Marshal(map[string]any{"artifacts": []agent.EvidenceArtifact{artifact}})
	if err != nil {
		t.Fatal(err)
	}
	activity := db.Activity{Kind: "tool_result", Tool: "ingest_scan_output", ToolUseID: "tool-2", Detail: string(envelope)}
	if !validEvidenceArtifact(activity, artifact) {
		t.Fatal("scanner-ingested browser artifact was rejected")
	}
	activity.Detail = `{"artifacts":[]}`
	if validEvidenceArtifact(activity, artifact) {
		t.Fatal("browser artifact absent from the audited tool result was accepted")
	}
	activity.Detail = string(envelope)
	activity.Tool = "Bash"
	if validEvidenceArtifact(activity, artifact) {
		t.Fatal("arbitrary shell output forged a browser capture")
	}
}

func TestEvidenceArtifactFileIntegrityIsVerifiedBeforeListing(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tasks", "7", "proof.png")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("real-image-bytes")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	artifact := agent.EvidenceArtifact{Ref: "tasks/7/proof.png", SHA256: hex.EncodeToString(digest[:]), ByteSize: int64(len(data))}
	if !evidenceArtifactFileValid(root, artifact) {
		t.Fatal("hash-verified evidence file was rejected")
	}
	if err := os.WriteFile(path, []byte("mock-image-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidenceArtifactFileValid(root, artifact) {
		t.Fatal("tampered evidence bytes were accepted")
	}
}
