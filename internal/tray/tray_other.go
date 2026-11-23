//go:build !windows

package tray

import (
	"os/exec"
	"runtime"
)

// Callbacks connects tray actions to the APN Peer Node.
type Callbacks struct {
	Tooltip       string
	DeviceIDLabel string
	OnOpen        func()
	OnCopyID      func()
	IsPaused      func() bool
	OnTogglePause func()
	OnQuit        func()
}

// HideConsoleWindow is a no-op on Unix platforms.
func HideConsoleWindow() {}

// OpenAppWindow opens APN in a standalone browser app window (or default browser).
func OpenAppWindow(url string) {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("open", url).Start()
		return
	}
	for _, bin := range []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge"} {
		if p, err := exec.LookPath(bin); err == nil {
			if err := exec.Command(p, "--app="+url, "--window-size=1200,840").Start(); err == nil {
				return
			}
		}
	}
	_ = exec.Command("xdg-open", url).Start()
}

// Start is a no-op stub on non-Windows platforms (Linux/macOS run via systemd/LaunchAgent + Web UI).
func Start(_ Callbacks) func() {
	return func() {}
}
