//go:build !windows

package remote

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ReadClipboard reads the current Linux/macOS system clipboard (PNG screenshot or UTF-8 text).
func ReadClipboard() (byte, []byte, error) {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("pbpaste").Output(); err == nil && len(out) > 0 {
			return 0, out, nil
		}
		return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า")
	}

	// Linux Wayland: wl-paste
	if isLinuxWayland() && hasCmd("wl-paste") {
		typesCmd := exec.Command("wl-paste", "--list-types")
		typesCmd.Env = linuxCmdEnv()
		applyLinuxUserCred(typesCmd)
		if typesOut, err := typesCmd.Output(); err == nil && strings.Contains(string(typesOut), "image/png") {
			imgCmd := exec.Command("wl-paste", "--type", "image/png")
			imgCmd.Env = linuxCmdEnv()
			applyLinuxUserCred(imgCmd)
			if out, err := imgCmd.Output(); err == nil && len(out) > 16 {
				return 1, out, nil
			}
		}
		txtCmd := exec.Command("wl-paste", "--no-newline")
		txtCmd.Env = linuxCmdEnv()
		applyLinuxUserCred(txtCmd)
		if out, err := txtCmd.Output(); err == nil && len(out) > 0 {
			return 0, out, nil
		}
	}

	// Linux X11: 100% pure-Go native X11 CLIPBOARD first (ZERO xclip/xsel dependency!)
	if kind, data, err := x11ReadClipboard(); err == nil && len(data) > 0 {
		return kind, data, nil
	}

	// Fallback: xclip
	if hasCmd("xclip") {
		tCmd := exec.Command("xclip", "-selection", "clipboard", "-t", "TARGETS", "-o")
		tCmd.Env = linuxCmdEnv()
		if tOut, err := tCmd.Output(); err == nil && strings.Contains(string(tOut), "image/png") {
			imgCmd := exec.Command("xclip", "-selection", "clipboard", "-t", "image/png", "-o")
			imgCmd.Env = linuxCmdEnv()
			if out, err := imgCmd.Output(); err == nil && len(out) > 16 {
				return 1, out, nil
			}
		}
		txtCmd := exec.Command("xclip", "-selection", "clipboard", "-o")
		txtCmd.Env = linuxCmdEnv()
		if out, err := txtCmd.Output(); err == nil && len(out) > 0 {
			return 0, out, nil
		}
	}

	// Fallback: xsel (text)
	if hasCmd("xsel") {
		txtCmd := exec.Command("xsel", "--clipboard", "--output")
		txtCmd.Env = linuxCmdEnv()
		if out, err := txtCmd.Output(); err == nil && len(out) > 0 {
			return 0, out, nil
		}
	}

	return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า หรือยังไม่ได้ติดตั้ง xclip / wl-clipboard บน Linux")
}

// ApplyClipboardPayload writes text or a PNG image into the Linux/macOS system clipboard
// and optionally triggers Ctrl+V immediately!
func ApplyClipboardPayload(kind byte, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	isImage := kind == 1 || kind == 3
	clipApplyMu.Lock()
	err := setUnixClipboard(isImage, data)
	clipApplyMu.Unlock()
	if err != nil {
		return err
	}
	if kind == 2 || kind == 3 {
		time.Sleep(55 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_down", Code: "ControlLeft", Key: "Control", Ctrl: true})
		time.Sleep(12 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_down", Code: "KeyV", Key: "v", Ctrl: true})
		time.Sleep(25 * time.Millisecond)
		_ = ApplyInputEvent(InputEvent{Type: "key_up", Code: "KeyV", Key: "v", Ctrl: true})
		time.Sleep(12 * time.Millisecond)
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

	// Linux: wl-copy (Wayland) -> pure-Go native X11 CLIPBOARD (zero deps!) -> xclip -> xsel
	if isLinuxWayland() && hasCmd("wl-copy") {
		args := []string{}
		if isImage {
			args = []string{"--type", "image/png"}
		}
		cmd := exec.Command("wl-copy", args...)
		cmd.Env = linuxCmdEnv()
		applyLinuxUserCred(cmd)
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Start()
	}
	if err := x11WriteClipboard(isImage, data); err == nil {
		return nil
	}
	if hasCmd("xclip") {
		args := []string{"-selection", "clipboard", "-i"}
		if isImage {
			args = []string{"-selection", "clipboard", "-t", "image/png", "-i"}
		}
		cmd := exec.Command("xclip", args...)
		cmd.Env = linuxCmdEnv()
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout = nil
		cmd.Stderr = nil
		return cmd.Run()
	}
	if !isImage && hasCmd("xsel") {
		cmd := exec.Command("xsel", "--clipboard", "--input")
		cmd.Env = linuxCmdEnv()
		cmd.Stdin = bytes.NewReader(data)
		return cmd.Run()
	}
	return errors.New("ไม่สามารถเขียนคลิปบอร์ดบน Linux ได้ (แนะนำติดตั้ง sudo apt install xclip)")
}
