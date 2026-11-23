//go:build windows

package webui

import (
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	hookUser32   = syscall.NewLazyDLL("user32.dll")
	hookKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procSetWindowsHookExW   = hookUser32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = hookUser32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = hookUser32.NewProc("CallNextHookEx")
	procGetAsyncKeyState    = hookUser32.NewProc("GetAsyncKeyState")
	procGetForegroundWindow = hookUser32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = hookUser32.NewProc("GetWindowTextW")
	procHookSendInput       = hookUser32.NewProc("SendInput")
	procHookGetMessageW     = hookUser32.NewProc("GetMessageW")
	procHookPostThreadMsgW  = hookUser32.NewProc("PostThreadMessageW")
	procGetCurrentThreadID  = hookKernel32.NewProc("GetCurrentThreadId")
)

const (
	whKeyboardLL     = 13
	wmKeyDown        = 0x0100
	wmSysKeyDown     = 0x0104
	wmQuitMsg        = 0x0012
	vkSpace          = 0x20
	vkLWin           = 0x5B
	vkRWin           = 0x5C
	vkMenuMask       = 0xE8 // Unassigned VK used to suppress Start Menu when swallowing Win+Space
	llkhfInjected    = 0x00000010
	apnHookExtraInfo = uintptr(0x41504E31)
)

type kbdLLHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type hookKbdInput struct {
	Type      uint32
	_         uint32
	Vk        uint16
	Scan      uint16
	Flags     uint32
	Time      uint32
	_         uint32
	ExtraInfo uintptr
	_pad      [8]byte
}

type hookMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

var (
	langHookMu      sync.Mutex
	langHookRef     int
	langHookTID     uint32
	langHookHandle  uintptr
	langHookTrigger func()
	langHookProc    = syscall.NewCallback(lowLevelKeyboardProc)
)

// registerRemoteLangHook installs a lightweight Windows WH_KEYBOARD_LL hook ONLY while
// a Remote Desktop viewer session is active, so pressing Win+Space while the APN window
// is focused switches the REMOTE PC's language without triggering local Windows or Start Menu!
func registerRemoteLangHook(onSwitchLang func()) func() {
	langHookMu.Lock()
	langHookTrigger = onSwitchLang
	langHookRef++
	needStart := langHookRef == 1
	langHookMu.Unlock()

	if needStart {
		ready := make(chan struct{})
		go runLangHookThread(ready)
		<-ready
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			langHookMu.Lock()
			if langHookRef > 0 {
				langHookRef--
			}
			stop := langHookRef == 0
			tid := langHookTID
			if stop {
				langHookTrigger = nil
			}
			langHookMu.Unlock()

			if stop && tid != 0 {
				_, _, _ = procHookPostThreadMsgW.Call(uintptr(tid), wmQuitMsg, 0, 0)
			}
		})
	}
}

func runLangHookThread(ready chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid, _, _ := procGetCurrentThreadID.Call()
	hhook, _, _ := procSetWindowsHookExW.Call(whKeyboardLL, langHookProc, 0, 0)

	langHookMu.Lock()
	langHookTID = uint32(tid)
	langHookHandle = hhook
	langHookMu.Unlock()

	close(ready)

	if hhook == 0 {
		return
	}

	var msg hookMsg
	for {
		r, _, _ := procHookGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
	}

	_, _, _ = procUnhookWindowsHookEx.Call(hhook)
	langHookMu.Lock()
	langHookHandle = 0
	langHookTID = 0
	langHookMu.Unlock()
}

func lowLevelKeyboardProc(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeyDown || wParam == wmSysKeyDown) && lParam != 0 {
		kb := (*kbdLLHookStruct)(unsafe.Pointer(lParam))
		if kb.VkCode == vkSpace && kb.DwExtraInfo != apnHookExtraInfo && (kb.Flags&llkhfInjected) == 0 {
			if isWinKeyHeld() && isAPNFocused() {
				langHookMu.Lock()
				fn := langHookTrigger
				langHookMu.Unlock()
				if fn != nil {
					// Send harmless unassigned VK_NONE (0xE8) so releasing Win does NOT open local Start Menu!
					suppressStartMenuMaskKey()
					go fn()
					return 1 // Swallow Space so local Windows never switches local language!
				}
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

func isWinKeyHeld() bool {
	l, _, _ := procGetAsyncKeyState.Call(vkLWin)
	if (uint16(l) & 0x8000) != 0 {
		return true
	}
	r, _, _ := procGetAsyncKeyState.Call(vkRWin)
	return (uint16(r) & 0x8000) != 0
}

func isAPNFocused() bool {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return false
	}
	var buf [256]uint16
	n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return false
	}
	title := syscall.UTF16ToString(buf[:n])
	return strings.Contains(title, "APN")
}

func suppressStartMenuMaskKey() {
	inps := [2]hookKbdInput{
		{Type: 1, Vk: vkMenuMask, Flags: 0, ExtraInfo: apnHookExtraInfo},
		{Type: 1, Vk: vkMenuMask, Flags: 2, ExtraInfo: apnHookExtraInfo},
	}
	_, _, _ = procHookSendInput.Call(2, uintptr(unsafe.Pointer(&inps[0])), unsafe.Sizeof(inps[0]))
}
