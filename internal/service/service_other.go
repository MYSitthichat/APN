//go:build !windows && !linux

package service

import "errors"

func SystemBinaryPath() string { return "" }
func SystemDataDir() string    { return "" }
func SystemConfigPath() string { return "" }
func SystemBinDir() string     { return "" }
func IsElevated() bool         { return false }

func userConfigCandidates() []string { return nil }

func GetInfo() Info {
	return Info{Supported: false}
}

func InstallSystemService(_, _ string) (Info, error) {
	return GetInfo(), errors.New("system service installer is supported on Windows and Linux")
}

func UninstallSystemService() error {
	return errors.New("system service uninstaller is supported on Windows and Linux")
}

func RunSystemService() error {
	return errors.New("system service mode is supported on Windows and Linux")
}
