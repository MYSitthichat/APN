//go:build windows

package remote

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"relayvpn/internal/executil"
)

var (
	procWTSQueryUserToken     = syscall.NewLazyDLL("wtsapi32.dll").NewProc("WTSQueryUserToken")
	procProcessIdToSessionId  = syscall.NewLazyDLL("kernel32.dll").NewProc("ProcessIdToSessionId")
	procGetCurrentProcessIDCC = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcessId")
)

// prepareCaptureCmd configures an FFmpeg capture process (hidden console window).
//
// In the System Service the worker runs as LocalSystem. Windows Graphics Capture (gfxcapture)
// does not work for SYSTEM: it needs the logged-on user's per-user capture service and fails with
// 0x80070424. On hybrid-GPU laptops and machines with virtual displays DXGI duplication then
// yields no frames either, leaving only GDI at ~8-11 FPS. So while the normal desktop is shown,
// FFmpeg is started with the token of the user logged on to this session, which restores WGC
// 60 FPS. On the lock screen, sign-in screen or UAC prompt it keeps running as SYSTEM, which is
// what capturing those secure desktops requires.
// The returned func must be called after cmd.Start (it closes the token handle).
func prepareCaptureCmd(cmd *exec.Cmd) func() {
	executil.HideWindow(cmd)
	if os.Getenv("APN_SERVICE_WORKER") != "1" {
		return func() {}
	}
	if !strings.EqualFold(inputDesktopName(), "Default") {
		return func() {}
	}
	tok, ok := sessionUserToken()
	if !ok {
		return func() {}
	}
	cmd.SysProcAttr.Token = tok
	return func() { _ = tok.Close() }
}

// sessionUserToken returns the primary token of the user logged on to this process's session.
// Only LocalSystem may call WTSQueryUserToken; it fails when nobody is logged on.
func sessionUserToken() (syscall.Token, bool) {
	pid, _, _ := procGetCurrentProcessIDCC.Call()
	var sid uint32
	if r, _, _ := procProcessIdToSessionId.Call(pid, uintptr(unsafe.Pointer(&sid))); r == 0 {
		return 0, false
	}
	var tok syscall.Token
	if r, _, _ := procWTSQueryUserToken.Call(uintptr(sid), uintptr(unsafe.Pointer(&tok))); r == 0 {
		return 0, false
	}
	return tok, true
}

// inputDesktopName is the name of the desktop receiving input: "Default" for the normal desktop,
// "Winlogon" for the lock/sign-in screen and UAC's secure desktop.
func inputDesktopName() string {
	const maximumAllowed = 0x02000000
	h, _, _ := procOpenInputDesktop.Call(0, 0, maximumAllowed)
	if h == 0 {
		return ""
	}
	defer procCloseDesktop.Call(h)
	return desktopName(h)
}
