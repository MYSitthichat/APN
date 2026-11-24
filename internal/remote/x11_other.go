//go:build !linux

package remote

import (
	"image"
	"os"
	"os/exec"
)

func detectLinuxDisplayEnv() (string, string) {
	return "", ""
}

func linuxCmdEnv() []string {
	return os.Environ()
}

func applyLinuxUserCred(_ *exec.Cmd) {}

func isLinuxWayland() bool {
	return false
}

func x11ScreenSize() (int, int, bool) {
	return 0, 0, false
}

func captureX11Native() (*image.RGBA, error) {
	return nil, errUnsupportedPlatform
}

func applyX11Input(_ InputEvent) (bool, error) {
	return false, nil
}
