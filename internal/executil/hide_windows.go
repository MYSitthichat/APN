//go:build windows

package executil

import (
	"os/exec"
	"syscall"
)

// HideWindow prevents a spawned child process from flashing a black CMD console window on Windows.
func HideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
