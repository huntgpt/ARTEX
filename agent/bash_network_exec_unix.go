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

// newBoundedShellCommand gives the request shell its own process group. When
// the context deadline fires, killing the whole group stops both bash and the
// current curl/wget child; killing only bash can leave a chained client's pipe
// open and make Cmd.Wait hang past the supposed deadline.
func newBoundedShellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
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
