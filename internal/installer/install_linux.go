//go:build linux

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"relayvpn/internal/service"
)

// InstallPath returns the standard per-user installation path for APN on Linux.
func InstallPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "apn")
}

// GetStatus checks whether APN is installed via .deb (/usr/bin/apn, /usr/lib/apn/apn)
// or per-user (~/.local/bin/apn).
func GetStatus() Status {
	dst := InstallPath()
	_, userErr := os.Stat(dst)
	_, debBinErr := os.Stat("/usr/lib/apn/apn")
	_, sysBinErr := os.Stat("/usr/bin/apn")
	debInstalled := debBinErr == nil || sysBinErr == nil
	installed := userErr == nil || debInstalled

	curExe, _ := os.Executable()
	cleanCur := filepath.Clean(curExe)
	runningInstalled := cleanCur == filepath.Clean(dst) || cleanCur == "/usr/lib/apn/apn" || cleanCur == "/usr/bin/apn"

	home, _ := os.UserHomeDir()
	svcPath := filepath.Join(home, ".config", "systemd", "user", "apn.service")
	_, svcErr := os.Stat(svcPath)
	_, xdgAutoErr := os.Stat("/etc/xdg/autostart/apn.desktop")
	_, userAutoErr := os.Stat(filepath.Join(home, ".config", "autostart", "apn.desktop"))

	effectivePath := dst
	if userErr != nil && debInstalled {
		effectivePath = "/usr/bin/apn"
	}

	svcInfo := service.GetInfo()
	if svcInfo.Installed {
		installed = true
		if svcInfo.RunningAsService {
			runningInstalled = true
			effectivePath = svcInfo.BinaryPath
		}
	}

	return Status{
		Installed:        installed,
		RunningInstalled: runningInstalled,
		AutoStart:        svcErr == nil || xdgAutoErr == nil || userAutoErr == nil || svcInfo.Installed,
		InstallPath:      effectivePath,
		ConfigPath:       DefaultConfigPath(),
		Platform:         currentPlatform(),
		Service:          svcInfo,
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
Environment=APN_SYSTEMD_SERVICE=1
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
