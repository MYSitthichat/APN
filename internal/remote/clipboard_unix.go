//go:build !windows

package remote

import (
	"bytes"
	"os/exec"
	"runtime"
	"time"
)

// ApplyClipboardPayload writes text or a PNG image into the Linux/macOS system clipboard
// and optionally triggers Ctrl+V immediately!
func ApplyClipboardPayload(kind byte, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	isImage := kind == 1 || kind == 3
	if err := setUnixClipboard(isImage, data); err != nil {
		return err
	}
	if kind == 2 || kind == 3 {
		time.Sleep(50 * time.Millisecond)
		// Send Ctrl+V on Linux (X11 XTEST / xdotool)
		_ = ApplyInputEvent(InputEvent{Type: "key_down", Code: "ControlLeft", Key: "Control", Ctrl: true})
		time.Sleep(10 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_down", Code: "KeyV", Key: "v", Ctrl: true})
		time.Sleep(20 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_up", Code: "KeyV", Key: "v", Ctrl: true})
		time.Sleep(10 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_up", Code: "ControlLeft", Key: "Control"})
	}
	return nil
}

func setUnixClipboard(isImage bool, data []byte) error {
	if runtime.GOOS == "darwin" {
		if !isImage {
			cmd := exec.Command("pbcopy")
			cmd.Stdin = bytes.NewReader(data)
			return cmd.Run()
		}
		return nil
	}

	// Linux: wl-copy (Wayland) -> xclip (X11) -> xsel (text fallback)
	if isLinuxWayland() && hasCmd("wl-copy") {
		args := []string{}
		if isImage {
			args = []string{"--type", "image/png"}
		}
		cmd := exec.Command("wl-copy", args...)
		cmd.Env = linuxCmdEnv()
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Start() // wl-copy stays resident to serve clipboard requests
	}
	if hasCmd("xclip") {
		args := []string{"-selection", "clipboard", "-i"}
		if isImage {
			args = []string{"-selection", "clipboard", "-t", "image/png", "-i"}
		}
		cmd := exec.Command("xclip", args...)
		cmd.Env = linuxCmdEnv()
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Start()
	}
	if !isImage && hasCmd("xsel") {
		cmd := exec.Command("xsel", "--clipboard", "--input")
		cmd.Env = linuxCmdEnv()
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Run()
	}
	return nil
}
