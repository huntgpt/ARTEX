//go:build !darwin && !linux

package agent

import (
	"context"
	"os/exec"
)

// Production workers run on Linux and local development is supported on
// macOS. Other platforms remain buildable with process-level cancellation.
func newBoundedCLICommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, executable, args...)
}
