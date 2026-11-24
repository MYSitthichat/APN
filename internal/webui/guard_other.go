//go:build !linux && !windows

package webui

import "net/http"

// callerAllowed: on macOS the UI is only bound to loopback; per-account checks are not
// implemented yet (macOS hosts are typically single-user and APN does not run as root there).
func callerAllowed(r *http.Request) (bool, string) {
	if _, _, _, ok := localConnPorts(r); !ok {
		return false, "not a loopback connection"
	}
	return true, ""
}
