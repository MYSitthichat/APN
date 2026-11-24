//go:build !linux && !windows

package remote

import "os/exec"

// prepareCaptureCmd needs no extra setup on this OS (macOS).
func prepareCaptureCmd(_ *exec.Cmd) func() { return func() {} }
