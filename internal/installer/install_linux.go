//go:build linux

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallPath returns the standard per-user installation path for APN on Linux.
func InstallPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "apn")
}

// GetStatus checks whether APN is installed into ~/.local/bin/apn and systemd user service.
func GetStatus() Status {
	dst := InstallPath()
	_, err := os.Stat(dst)
	installed := err == nil
	curExe, _ := os.Executable()
	home, _ := os.UserHomeDir()
	svcPath := filepath.Join(home, ".config", "systemd", "user", "apn.service")
	_, svcErr := os.Stat(svcPath)

	return Status{
		Installed:        installed,
		RunningInstalled: filepath.Clean(curExe) == filepath.Clean(dst),
		AutoStart:        svcErr == nil,
		InstallPath:      dst,
		ConfigPath:       DefaultConfigPath(),
		Platform:         currentPlatform(),
	}
}

// Install copies APN to ~/.local/bin/apn, creates a .desktop launcher, and enables systemd user auto-start.
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
	desktopDir := filepath.Join(home, ".local", "share", "applications")
	_ = os.MkdirAll(desktopDir, 0o755)
	desktopEntry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=APN Remote & VPN
Comment=High-Speed P2P Remote Desktop & Encrypted L3 VPN
Exec=%s
Terminal=false
Categories=Network;RemoteAccess;
`, dst)
	_ = os.WriteFile(filepath.Join(desktopDir, "apn.desktop"), []byte(desktopEntry), 0o644)

	svcDir := filepath.Join(home, ".config", "systemd", "user")
	_ = os.MkdirAll(svcDir, 0o755)
	svc := fmt.Sprintf(`[Unit]
Description=APN Remote Desktop & VPN
After=network-online.target

[Service]
ExecStart=%s peer -tray
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`, dst)
	_ = os.WriteFile(filepath.Join(svcDir, "apn.service"), []byte(svc), 0o644)
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	_ = exec.Command("systemctl", "--user", "enable", "apn.service").Run()

	return GetStatus(), nil
}

// Uninstall removes ~/.local/bin/apn, desktop entry, and systemd user service.
func Uninstall() error {
	home, _ := os.UserHomeDir()
	_ = exec.Command("systemctl", "--user", "disable", "--now", "apn.service").Run()
	_ = os.Remove(filepath.Join(home, ".config", "systemd", "user", "apn.service"))
	_ = os.Remove(filepath.Join(home, ".local", "share", "applications", "apn.desktop"))
	dst := InstallPath()
	if !strings.HasSuffix(dst, "/") {
		_ = os.Remove(dst)
	}
	return nil
}
