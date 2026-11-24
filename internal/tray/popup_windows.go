//go:build windows

package tray

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSetWindowPos  = user32.NewProc("SetWindowPos")
	procFlashWindowEx = user32.NewProc("FlashWindowEx")
)

const (
	swShow          = 5
	hwndTopmost     = ^uintptr(0)     // (HWND)-1
	hwndNoTopmost   = ^uintptr(0) - 1 // (HWND)-2
	swpNoSize       = 0x0001
	swpNoMove       = 0x0002
	swpShowWindow   = 0x0040
	flashwAll       = 0x00000003
	flashwTimerNoFG = 0x0000000C
)

type flashWInfo struct {
	cbSize    uint32
	hwnd      uintptr
	dwFlags   uint32
	uCount    uint32
	dwTimeout uint32
}

// PopupAppWindow pops the APN window to the front for an incoming connection request (like
// AnyDesk): an open window is restored, raised above other windows and flashed; otherwise a new
// app window is opened. openIfMissing=false only raises an existing window.
//
// In the System Service (LocalSystem in the user's session) a new window is opened as the
// logged-on user with that user's environment, never as SYSTEM.
func PopupAppWindow(url string, openIfMissing bool) {
	if raiseAppWindow() || !openIfMissing {
		return
	}
	if os.Getenv("APN_SERVICE_WORKER") == "1" {
		launchAsSessionUser(url)
		return
	}
	OpenAppWindow(url)
}

func findAppWindow() uintptr {
	var found uintptr
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}
		var buf [256]uint16
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return 1
		}
		title := syscall.UTF16ToString(buf[:n])
		if strings.HasPrefix(title, "APN —") || strings.HasPrefix(title, "APN -") || title == "APN" {
			found = hwnd
			return 0
		}
		return 1
	})
	_, _, _ = procEnumWindows.Call(cb, 0)
	return found
}

func raiseAppWindow() bool {
	hwnd := findAppWindow()
	if hwnd == 0 {
		return false
	}
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swRestore)
	} else {
		_, _, _ = procShowWindow.Call(hwnd, swShow)
	}
	// Windows refuses SetForegroundWindow from background processes; briefly making the window
	// topmost still brings it above everything without stealing keyboard focus.
	_, _, _ = procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	_, _, _ = procSetWindowPos.Call(hwnd, hwndNoTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	_, _, _ = procSetForegroundWindow.Call(hwnd)
	fi := flashWInfo{hwnd: hwnd, dwFlags: flashwAll | flashwTimerNoFG, uCount: 5}
	fi.cbSize = uint32(unsafe.Sizeof(fi))
	_, _, _ = procFlashWindowEx.Call(uintptr(unsafe.Pointer(&fi)))
	return true
}

// appWindowArgs: a standalone app window that may play the request chime without a prior click.
func appWindowArgs(url string) []string {
	return []string{"--app=" + url, "--window-size=1280,800", "--autoplay-policy=no-user-gesture-required"}
}

func browserCandidates(env func(string) string) []string {
	return []string{
		filepath.Join(env("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(env("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(env("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(env("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(env("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
	}
}

// launchAsSessionUser opens the app window on the logged-on user's desktop from the service.
func launchAsSessionUser(url string) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sid, &tok); err != nil {
		return // nobody logged on
	}
	defer tok.Close()
	envList, err := tok.Environ(false)
	if err != nil {
		return
	}
	env := func(k string) string {
		for _, kv := range envList {
			if i := strings.IndexByte(kv, '='); i > 0 && strings.EqualFold(kv[:i], k) {
				return kv[i+1:]
			}
		}
		return ""
	}
	for _, bin := range browserCandidates(env) {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		cmd := exec.Command(bin, appWindowArgs(url)...)
		cmd.Env = envList
		cmd.Dir = env("USERPROFILE")
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok)}
		if cmd.Start() == nil {
			return
		}
	}
}
