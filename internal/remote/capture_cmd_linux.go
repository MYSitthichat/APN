//go:build linux

package remote

import "os/exec"

// prepareCaptureCmd configures an FFmpeg capture process. On Linux it gets the DISPLAY and
// XAUTHORITY of the X session the Go capture connection is verified to work with; a separately
// re-discovered guess once paired the user's display :1 with the GDM greeter's cookie, so
// x11grab failed with "Input/output error" and video fell back to Smart Tiles.
// The returned func must be called after cmd.Start.
func prepareCaptureCmd(cmd *exec.Cmd) func() {
	cmd.Env = captureCmdEnv()
	return func() {}
}
