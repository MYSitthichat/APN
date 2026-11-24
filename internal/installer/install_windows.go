//go:build windows

package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"relayvpn/internal/service"
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

	svcInfo := service.GetInfo()
	if svcInfo.Installed {
		installed = true
		autoStart = true
		if svcInfo.RunningAsService {
			runningInstalled = true
			dst = svcInfo.BinaryPath
		}
	}

	return Status{
		Installed:        installed,
		RunningInstalled: runningInstalled,
		AutoStart:        autoStart,
		InstallPath:      dst,
		ConfigPath:       DefaultConfigPath(),
		Platform:         currentPlatform(),
		Service:          svcInfo,
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

	// Perform all registry updates + Desktop/Start Menu shortcut creation in ONE single fast hidden PowerShell call
	// (cuts install time from ~5 seconds down to ~0.6 seconds!).
	escDst := strings.ReplaceAll(dst, `'`, `''`)
	escDir := strings.ReplaceAll(dstDir, `'`, `''`)
	escVer := strings.ReplaceAll(version.Version, `'`, `''`)
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$exe = '%s'
$dir = '%s'
$ver = '%s'

$runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runPath -Force | Out-Null
Set-ItemProperty -Path $runPath -Name 'APN' -Value ('"' + $exe + '" peer -tray')

$uninstPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\APNRemote'
New-Item -Path $uninstPath -Force | Out-Null
Set-ItemProperty -Path $uninstPath -Name 'DisplayName' -Value 'APN Remote & VPN'
Set-ItemProperty -Path $uninstPath -Name 'DisplayVersion' -Value $ver
Set-ItemProperty -Path $uninstPath -Name 'Publisher' -Value 'APN'
Set-ItemProperty -Path $uninstPath -Name 'DisplayIcon' -Value ($exe + ',0')
Set-ItemProperty -Path $uninstPath -Name 'InstallLocation' -Value $dir
Set-ItemProperty -Path $uninstPath -Name 'UninstallString' -Value ('"' + $exe + '" uninstall')
Set-ItemProperty -Path $uninstPath -Name 'NoModify' -Value 1 -Type DWord
Set-ItemProperty -Path $uninstPath -Name 'NoRepair' -Value 1 -Type DWord

$ws = New-Object -ComObject WScript.Shell
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
`, escDst, escDir, escVer)
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
