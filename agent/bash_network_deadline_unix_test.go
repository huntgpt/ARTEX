//go:build darwin || linux

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func TestNetworkDeadlineBashKillsRequestProcessGroupWithoutBackgroundTask(t *testing.T) {
	binDir := t.TempDir()
	fakeCurl := filepath.Join(binDir, "curl")
	if err := os.WriteFile(fakeCurl, []byte("#!/bin/bash\nsleep 10\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manager, err := actool.NewManager("artex-network-deadline-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Cleanup)
	tc := &actool.ToolContext{
		WorkingDir: t.TempDir(),
		Tasks:      manager,
		Env:        []string{"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH")},
	}
	tool := boundedNetworkBash(actool.NewBash())
	started := time.Now()
	result, err := tool.Call(t.Context(), json.RawMessage(`{"command":"curl https://example.test/ && curl https://example.test/again","timeout_ms":75}`), tc)
	if err != nil || !result.IsError {
		t.Fatalf("Call() = (%q, error=%v), err=%v", result.Flatten(), result.IsError, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bounded request returned after %s, want <2s", elapsed)
	}
	if got := manager.List(); len(got) != 0 {
		t.Fatalf("request leaked background tasks: %+v", got)
	}
	for _, want := range []string{"command timed out", "blocker_type=network_environment", "not backgrounded"} {
		if !strings.Contains(result.Flatten(), want) {
			t.Fatalf("result %q missing %q", result.Flatten(), want)
		}
	}
}

func TestNetworkDeadlineBashPreservesWorkDirEnvOutputCapAndTerminalEvidence(t *testing.T) {
	binDir := t.TempDir()
	fakeCurl := filepath.Join(binDir, "curl")
	script := `#!/bin/bash
printf 'pwd=%s marker=%s\n' "$PWD" "$MARKER"
for ((i=0; i<2000; i++)); do printf x; done
printf '\n'
`
	if err := os.WriteFile(fakeCurl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	spillDir := t.TempDir()
	tc := &actool.ToolContext{
		WorkingDir:     workDir,
		MaxOutputChars: 512,
		OutputDir:      spillDir,
		Env: []string{
			"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
			"MARKER=preserved",
		},
	}
	input := json.RawMessage(`{"command":"curl https://example.test/evidence"}`)
	tool := boundedNetworkBash(actool.NewBash())
	result, err := tool.Call(t.Context(), input, tc)
	if err != nil || result.IsError {
		t.Fatalf("Call() = (%q, error=%v), err=%v", result.Flatten(), result.IsError, err)
	}
	realWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pwd=" + realWorkDir, "marker=preserved", "<persisted-output>", "Full output saved to"} {
		if !strings.Contains(result.Flatten(), want) {
			t.Fatalf("result %q missing %q", result.Flatten(), want)
		}
	}
	spillEntries, err := os.ReadDir(spillDir)
	if err != nil || len(spillEntries) != 1 {
		t.Fatalf("spill entries = %v, err=%v", spillEntries, err)
	}
	fullOutput, err := os.ReadFile(filepath.Join(spillDir, spillEntries[0].Name()))
	if err != nil || len(fullOutput) < 2000 || !strings.Contains(string(fullOutput), "marker=preserved") {
		t.Fatalf("full captured output len=%d err=%v", len(fullOutput), err)
	}

	evidenceDir := t.TempDir()
	artifacts, err := terminalEvidence(evidenceCaptureConfig{Dir: evidenceDir, RefPrefix: "tasks/2"}, "tool-use-network", tool.Name(), string(input), result.Flatten(), time.Now())
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("terminalEvidence() = %+v, err=%v", artifacts, err)
	}
	artifact := artifacts[0]
	if artifact.Kind != "terminal_capture" || artifact.Tool != "Bash" || artifact.Command != "curl https://example.test/evidence" || artifact.RawOutputSHA256 == "" || artifact.SHA256 == "" {
		t.Fatalf("terminal artifact lost audit provenance: %+v", artifact)
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, filepath.Base(artifact.Ref))); err != nil {
		t.Fatalf("terminal PNG missing: %v", err)
	}
}
