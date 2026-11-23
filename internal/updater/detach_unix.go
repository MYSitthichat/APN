//go:build !windows

package updater

import (
	"os/exec"
	"syscall"
)

func detachRestartedCmd(cmd *exec.Cmd) {
	// Start the updated APN process in its own session (Setsid) so GNOME/desktop
	// scope teardown or terminal SIGHUP never kills the newly launched process!
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
