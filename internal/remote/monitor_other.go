//go:build !windows

package remote

// captureTarget selects the monitor to capture; only Windows needs it (see monitor_windows.go).
type captureTarget struct {
	hmonitor   uintptr
	dxgiFound  bool
	dxgiAdapt  int
	dxgiOutput int
}

func primaryCaptureTarget() captureTarget { return captureTarget{} }
