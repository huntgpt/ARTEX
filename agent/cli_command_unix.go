//go:build darwin || linux

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// newBoundedCLICommand gives every local LLM invocation its own process group.
// Claude Code and Codex may spawn Node/helper descendants; killing only the
// immediate CLI can leave those descendants holding pipes open so Cmd.Wait
// never returns. ARTEX supports macOS and Linux, where a negative PID targets
// the full process group.
func newBoundedCLICommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd
}
