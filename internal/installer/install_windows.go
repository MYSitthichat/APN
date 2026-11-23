//go:build windows

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"relayvpn/internal/version"
)

const (
	winRunRegKey       = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	winUninstallRegKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\APNRemote`
)

// InstallPath returns the standard per-user installation path for APN on Windows.
func InstallPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "AppData", "Local")
	}
	return filepath.Join(base, "Programs", "APN", "APN.exe")
}

// GetStatus inspects whether APN is installed and configured for Windows auto-start.
func GetStatus() Status {
	dst := InstallPath()
	_, err := os.Stat(dst)
	installed := err == nil

	curExe, _ := os.Executable()
	runningInstalled := strings.EqualFold(filepath.Clean(curExe), filepath.Clean(dst))

	autoStart := false
	if installed {
		cmd := exec.Command("reg", "query", winRunRegKey, "/v", "APN")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err == nil {
			autoStart = true
		}
	}

	return Status{
		Installed:        installed,
		RunningInstalled: runningInstalled,
		AutoStart:        autoStart,
		InstallPath:      dst,
		ConfigPath:       DefaultConfigPath(),
		Platform:         currentPlatform(),
	}
}

// Install copies APN into %LOCALAPPDATA%\Programs\APN\APN.exe, creates Desktop & Start Menu shortcuts
// with the embedded APN icon, enables Windows Login Auto-Start (in System Tray), and registers Add/Remove Programs.
func Install() (Status, error) {
	curExe, err := os.Executable()
	if err != nil {
		return GetStatus(), fmt.Errorf("locate current executable: %w", err)
	}
	dst := InstallPath()
	dstDir := filepath.Dir(dst)

	if !strings.EqualFold(filepath.Clean(curExe), filepath.Clean(dst)) {
		if err := copyFile(curExe, dst, 0o755); err != nil {
			return GetStatus(), fmt.Errorf("copy APN.exe to %s: %w", dst, err)
		}
	}

	// Copy wintun.dll alongside installed APN.exe if present next to current exe
	curDir := filepath.Dir(curExe)
	for _, dll := range []string{"wintun.dll", "wintun-arm64.dll"} {
		srcDLL := filepath.Join(curDir, dll)
		if _, err := os.Stat(srcDLL); err == nil {
			_ = copyFile(srcDLL, filepath.Join(dstDir, dll), 0o644)
		}
	}

	// Register Auto-Start on Windows Login (silently starts in System Tray!)
	runHidden("reg", "add", winRunRegKey, "/v", "APN", "/t", "REG_SZ", "/d", fmt.Sprintf(`"%s" peer -tray`, dst), "/f")

	// Register in Windows Settings -> Installed Apps (Add/Remove Programs)
	runHidden("reg", "add", winUninstallRegKey, "/v", "DisplayName", "/t", "REG_SZ", "/d", "APN Remote & VPN", "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "DisplayVersion", "/t", "REG_SZ", "/d", version.Version, "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "Publisher", "/t", "REG_SZ", "/d", "APN", "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "DisplayIcon", "/t", "REG_SZ", "/d", dst+",0", "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "InstallLocation", "/t", "REG_SZ", "/d", dstDir, "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "UninstallString", "/t", "REG_SZ", "/d", fmt.Sprintf(`"%s" uninstall`, dst), "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f")
	runHidden("reg", "add", winUninstallRegKey, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f")

	// Create Desktop & Start Menu shortcuts (.lnk) with embedded APN icon
	ps := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$exe = '%s'
$dir = '%s'
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'APN.lnk'
foreach ($lnkPath in @((Join-Path $desktop 'APN.lnk'), $startMenu)) {
  $s = $ws.CreateShortcut($lnkPath)
  $s.TargetPath = $exe
  $s.WorkingDirectory = $dir
  $s.IconLocation = "$exe,0"
  $s.Description = 'APN Remote Desktop & Built-in L3 VPN'
  $s.Save()
}
`, strings.ReplaceAll(dst, `'`, `''`), strings.ReplaceAll(dstDir, `'`, `''`))
	runHidden("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)

	return GetStatus(), nil
}

// Uninstall removes shortcuts, auto-start, Add/Remove Programs registration, and installed binary.
func Uninstall() error {
	runHidden("reg", "delete", winRunRegKey, "/v", "APN", "/f")
	runHidden("reg", "delete", winUninstallRegKey, "/f")

	ps := `
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'APN.lnk'
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $desktop 'APN.lnk'), $startMenu
`
	runHidden("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)

	dst := InstallPath()
	_ = os.Remove(dst + ".old")
	_ = os.Remove(dst)
	return nil
}

func runHidden(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}
