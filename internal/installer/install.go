package installer

import (
	"io"
	"os"
	"path/filepath"
	"runtime"

	"relayvpn/internal/service"
)

// Status describes whether APN is installed into the OS with shortcuts, auto-start, and System Service.
type Status struct {
	Installed        bool         `json:"installed"`
	RunningInstalled bool         `json:"running_installed"`
	AutoStart        bool         `json:"auto_start"`
	InstallPath      string       `json:"install_path"`
	ConfigPath       string       `json:"config_path"`
	Platform         string       `json:"platform"`
	Service          service.Info `json:"service"`
}

// DefaultConfigPath returns the persistent config path for APN
// (uses system-wide C:\ProgramData\APN\peer.json or /etc/apn/peer.json when running as System Service,
// otherwise per-user config dir with automatic migration from ./peer-config/peer.json).
func DefaultConfigPath() string {
	if os.Getenv("APN_SERVICE_WORKER") == "1" {
		if sysCfg := service.SystemConfigPath(); sysCfg != "" {
			return sysCfg
		}
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil || cfgDir == "" {
		return "./peer-config/peer.json"
	}
	apnDir := filepath.Join(cfgDir, "APN")
	apnCfg := filepath.Join(apnDir, "peer.json")
	if _, err := os.Stat(apnCfg); err == nil {
		return apnCfg
	}

	// Seamless migration: if the user already ran RelayVPN in the current folder or beside the exe,
	// copy their existing peer.json, peer.crt, and peer.key into %APPDATA%\APN so nothing is ever lost!
	candidates := []string{
		filepath.Join(".", "peer-config"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "peer-config"))
	}
	for _, oldDir := range candidates {
		oldCfg := filepath.Join(oldDir, "peer.json")
		if _, err := os.Stat(oldCfg); err == nil {
			_ = os.MkdirAll(apnDir, 0o700)
			for _, name := range []string{"peer.json", "peer.crt", "peer.key"} {
				src := filepath.Join(oldDir, name)
				dst := filepath.Join(apnDir, name)
				if _, serr := os.Stat(src); serr == nil {
					_ = copyFile(src, dst, 0o600)
				}
			}
			// Rewrite cert_file / key_file references in migrated peer.json if needed on load (handled gracefully if missing)
			return apnCfg
		}
	}
	return apnCfg
}

func copyFile(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		// On Windows, renaming over a running executable requires moving the old one aside first
		old := dst + ".old"
		_ = os.Remove(old)
		if rerr := os.Rename(dst, old); rerr == nil {
			if err2 := os.Rename(tmp, dst); err2 == nil {
				return nil
			}
		}
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func currentPlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
