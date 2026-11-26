package agent

import (
	"slices"
	"testing"
)

func TestCodexCLIArgsUseCurrentNonInteractiveFlags(t *testing.T) {
	args := codexCLIArgs("gpt-test", "daybreak_red", "/tmp/run", "/tmp/schema", "/tmp/answer")
	if slices.Contains(args, "--ask-for-approval") {
		t.Fatal("Codex exec no longer accepts --ask-for-approval")
	}
	want := map[string]bool{
		"--json": true, "--sandbox": true, "read-only": true,
		"--ephemeral": true, "--ignore-user-config": true, "--ignore-rules": true,
		"--cyber-access-program": true, "daybreak_red": true,
	}
	for _, arg := range args {
		delete(want, arg)
	}
	if len(want) != 0 {
		t.Fatalf("Codex bridge safety flags missing: %v", want)
	}
}
