//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	LinuxServiceName = "apn.service"
	LinuxUnitPath    = "/etc/systemd/system/apn.service"
)

func SystemBinaryPath() string { return "/usr/local/bin/apn" }
func SystemDataDir() string    { return "/etc/apn" }
func SystemConfigPath() string { return "/etc/apn/peer.json" }
func SystemBinDir() string     { return "/var/lib/apn/bin" }


func IsElevated() bool {
	return os.Geteuid() == 0
}

func GetInfo() Info {
	info := Info{
		Supported:        true,
		RunningAsService: os.Getenv("APN_SYSTEMD_SERVICE") == "1" && os.Geteuid() == 0,
		ServiceName:      LinuxServiceName,
		BinaryPath:       SystemBinaryPath(),
		ConfigPath:       SystemConfigPath(),
	}
	if _, err := os.Stat(LinuxUnitPath); err == nil {
		info.Installed = true
	}
	if out, err := exec.Command("systemctl", "is-active", LinuxServiceName).Output(); err == nil {
		info.Running = strings.TrimSpace(string(out)) == "active"
	}
	return info
}

func InstallSystemService(migrateCfg, migrateBin string) (Info, error) {
	if !IsElevated() {
		exe, err := os.Executable()
		if err != nil {
			return GetInfo(), err
		}
		if pkexec, err := exec.LookPath("pkexec"); err == nil {
			args := []string{exe, "service", "install"}
			if migrateCfg != "" {
				args = append(args, "-migrate-cfg", migrateCfg)
			}
			if migrateBin != "" {
				args = append(args, "-migrate-bin", migrateBin)
			}
			if out, rerr := exec.Command(pkexec, args...).CombinedOutput(); rerr != nil {
				return GetInfo(), fmt.Errorf("ติดตั้ง System Service ไม่สำเร็จ (pkexec): %s", strings.TrimSpace(string(out)))
			}
			return GetInfo(), nil
		}
		return GetInfo(), errors.New("กรุณารันด้วยสิทธิ์ root: sudo apn service install")
	}

	curExe, err := os.Executable()
	if err != nil {
		return GetInfo(), err
	}
	dstExe := SystemBinaryPath()
	if filepath.Clean(curExe) != filepath.Clean(dstExe) {
		if err := copyFileAtomic(curExe, dstExe, 0o755); err != nil {
			return GetInfo(), err
		}
	}

	migrateCfg, migrateBin = resolveLinuxSudoMigratePaths(migrateCfg, migrateBin)
	migrateConfigDir(migrateCfg, SystemDataDir())
	migrateBinDir(migrateBin, SystemBinDir())

	unit := fmt.Sprintf(`[Unit]
Description=APN Remote Desktop & Built-in L3 VPN (System Service)
After=network-online.target display-manager.service
Wants=network-online.target

[Service]
Type=simple
Environment=APN_SYSTEMD_SERVICE=1
Environment=APN_SERVICE_WORKER=1
Environment=APN_BIN_DIR=%s
ExecStart=%s peer -config %s -service-worker -tray
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, SystemBinDir(), dstExe, SystemConfigPath())

	if err := os.WriteFile(LinuxUnitPath, []byte(unit), 0o644); err != nil {
		return GetInfo(), err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", LinuxServiceName).CombinedOutput(); err != nil {
		return GetInfo(), fmt.Errorf("เปิดใช้งาน apn.service ไม่สำเร็จ: %s", strings.TrimSpace(string(out)))
	}
	return GetInfo(), nil
}

func UninstallSystemService() error {
	if !IsElevated() {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if pkexec, err := exec.LookPath("pkexec"); err == nil {
			if out, rerr := exec.Command(pkexec, exe, "service", "uninstall").CombinedOutput(); rerr != nil {
				return fmt.Errorf("ถอนการติดตั้ง System Service ไม่สำเร็จ: %s", strings.TrimSpace(string(out)))
			}
			return nil
		}
		return errors.New("กรุณารันด้วยสิทธิ์ root: sudo apn service uninstall")
	}
	_ = exec.Command("systemctl", "disable", "--now", LinuxServiceName).Run()
	_ = os.Remove(LinuxUnitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func RunSystemService() error {
	return errors.New("on Linux, systemd starts 'apn peer -service-worker' directly")
}

// resolveLinuxSudoMigratePaths fixes `sudo apn service install` where $HOME=/root would miss
// the real desktop user's ~/.config/APN/peer.json (keeping their 9-digit ID & permanent password!).
func resolveLinuxSudoMigratePaths(cfgPath, binDir string) (string, string) {
	cfgMissing := cfgPath == "" || strings.HasPrefix(cfgPath, "/root/")
	if !cfgMissing {
		if _, err := os.Stat(cfgPath); err != nil {
			cfgMissing = true
		}
	}
	binMissing := binDir == "" || strings.HasPrefix(binDir, "/root/")
	if !binMissing {
		if _, err := os.Stat(binDir); err != nil {
			binMissing = true
		}
	}

	// Only the user who ran `sudo` / `pkexec` — never every /home/* directory: copying another
	// user's config or bin directory into the root service would let that user plant files.
	var homes []string
	var u *user.User
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		u, _ = user.Lookup(sudoUser)
	} else if uid := strings.TrimSpace(os.Getenv("PKEXEC_UID")); uid != "" && uid != "0" {
		u, _ = user.LookupId(uid)
	}
	if u != nil && u.HomeDir != "" {
		homes = append(homes, u.HomeDir)
	}

	for _, h := range homes {
		if cfgMissing {
			for _, sub := range []string{".config/APN/peer.json", ".config/apn/peer.json"} {
				cand := filepath.Join(h, sub)
				if _, err := os.Stat(cand); err == nil {
					cfgPath = cand
					cfgMissing = false
					break
				}
			}
		}
		if binMissing {
			for _, sub := range []string{".local/share/relayvpn/bin", ".config/APN/bin", ".local/share/APN/bin", ".config/apn/bin"} {
				cand := filepath.Join(h, sub)
				if st, err := os.Stat(cand); err == nil && st.IsDir() {
					binDir = cand
					binMissing = false
					break
				}
			}
		}
	}
	return cfgPath, binDir
}
