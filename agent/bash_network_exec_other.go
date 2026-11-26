//go:build !darwin && !linux

package agent

import (
	"context"
	"os/exec"
)

// ARTEX deploys its execution workers on Linux and developers use macOS. Keep
// other platforms buildable with CommandContext's process-level cancellation;
// the process-group guarantee is provided on the two supported platforms.
func newBoundedShellCommand(ctx context.Context, command string) *exec.Cmd {
	return exec.CommandContext(ctx, "bash", "-c", command)
}
