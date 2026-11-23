//go:build windows

package updater

import "os/exec"

func detachRestartedCmd(_ *exec.Cmd) {}
