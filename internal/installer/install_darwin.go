//go:build !windows && !linux

package installer

import (
	"fmt"
	"os"
	"path/filepath"
)

// InstallPath returns the per-user installation path on macOS/other Unix systems.
func InstallPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", "APN", "apn")
}

// GetStatus returns installation status on macOS/other Unix systems.
func GetStatus() Status {
	dst := InstallPath()
	_, err := os.Stat(dst)
	curExe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	plist := filepath.Join(home, "Library", "LaunchAgents", "com.apn.remote.plist")
	_, pErr := os.Stat(plist)
	return Status{
		Installed:        err == nil,
		RunningInstalled: filepath.Clean(curExe) == filepath.Clean(dst),
		AutoStart:        pErr == nil,
		InstallPath:      dst,
		ConfigPath:       DefaultConfigPath(),
		Platform:         currentPlatform(),
	}
}

// Install installs APN into ~/Applications/APN/apn and registers a macOS LaunchAgent.
func Install() (Status, error) {
	curExe, err := os.Executable()
	if err != nil {
		return GetStatus(), err
	}
	dst := InstallPath()
	if filepath.Clean(curExe) != filepath.Clean(dst) {
		if err := copyFile(curExe, dst, 0o755); err != nil {
			return GetStatus(), err
		}
	}
	home, _ := os.UserHomeDir()
	laDir := filepath.Join(home, "Library", "LaunchAgents")
	_ = os.MkdirAll(laDir, 0o755)
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apn.remote</string>
  <key>ProgramArguments</key><array><string>%s</string><string>peer</string><string>-tray</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
`, dst)
	_ = os.WriteFile(filepath.Join(laDir, "com.apn.remote.plist"), []byte(plist), 0o644)
	return GetStatus(), nil
}

// Uninstall removes ~/Applications/APN/apn and the LaunchAgent plist.
func Uninstall() error {
	home, _ := os.UserHomeDir()
	_ = os.Remove(filepath.Join(home, "Library", "LaunchAgents", "com.apn.remote.plist"))
	_ = os.Remove(InstallPath())
	return nil
}
