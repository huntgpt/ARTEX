package server

import (
	"os"
	"path/filepath"
	"testing"
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
