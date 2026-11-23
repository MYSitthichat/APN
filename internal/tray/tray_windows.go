//go:build windows

package tray

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetConsoleWindow    = kernel32.NewProc("GetConsoleWindow")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procSetMenuDefaultItem  = user32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procLoadIconW           = user32.NewProc("LoadIconW")
	procDestroyIcon         = user32.NewProc("DestroyIcon")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procExtractIconExW      = shell32.NewProc("ExtractIconExW")
)

const (
	swHide = 0

	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmContextMenu   = 0x007B

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	mfString    = 0x00000000
	mfSeparator = 0x00000800

	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020

	cmdOpen   = 1001
	cmdCopyID = 1002
	cmdPause  = 1003
	cmdQuit   = 1004
)

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type pointW struct {
	X int32
	Y int32
}

type msgW struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      pointW
}

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

// Callbacks connects System Tray actions to the APN Peer Node.
type Callbacks struct {
	Tooltip       string
	DeviceIDLabel string
	OnOpen        func()
	OnCopyID      func()
	IsPaused      func() bool
	OnTogglePause func()
	OnQuit        func()
}

var (
	trayMu   sync.Mutex
	trayCB   Callbacks
	trayHWND uintptr
	trayIcon uintptr
)

// HideConsoleWindow hides the Windows console window when double-clicked without CLI args.
func HideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swHide)
	}
}

// OpenAppWindow launches APN in a clean standalone desktop app window (no browser URL bar/tabs).
func OpenAppWindow(url string) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
	}
	for _, bin := range candidates {
		if bin != "" {
			if _, err := os.Stat(bin); err == nil {
				cmd := exec.Command(bin, "--app="+url, "--window-size=1280,800")
				if err := cmd.Start(); err == nil {
					return
				}
			}
		}
	}
	// Fallback to system default browser
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// Start runs a Pure-Go Windows System Tray icon (double-click to open, right-click for menu)
// and returns a stop function to cleanly remove the icon on shutdown.
func Start(cb Callbacks) func() {
	trayMu.Lock()
	trayCB = cb
	trayMu.Unlock()

	ready := make(chan struct{})
	go runTrayLoop(ready)
	<-ready

	return func() {
		trayMu.Lock()
		hwnd := trayHWND
		trayMu.Unlock()
		if hwnd != 0 {
			_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
		}
	}
}

func runTrayLoop(ready chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("APNTrayWindowClass")
	winName, _ := syscall.UTF16PtrFromString("APN Remote & VPN")

	wc := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		LpfnWndProc:   syscall.NewCallback(trayWndProc),
		HInstance:     hInst,
		LpszClassName: className,
	}
	_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(winName)),
		0, 0, 0, 0, 0,
		0, 0, hInst, 0,
	)

	var hIcon uintptr
	if exe, err := os.Executable(); err == nil {
		exePtr, _ := syscall.UTF16PtrFromString(exe)
		var smallIcon uintptr
		n, _, _ := procExtractIconExW.Call(uintptr(unsafe.Pointer(exePtr)), 0, 0, uintptr(unsafe.Pointer(&smallIcon)), 1)
		if n > 0 && smallIcon != 0 {
			hIcon = smallIcon
		}
	}
	if hIcon == 0 {
		hIcon, _, _ = procLoadIconW.Call(0, 32512) // IDI_APPLICATION
	}

	trayMu.Lock()
	trayHWND = hwnd
	trayIcon = hIcon
	tip := trayCB.Tooltip
	trayMu.Unlock()

	if hwnd != 0 {
		var nid notifyIconDataW
		nid.CbSize = uint32(unsafe.Sizeof(nid))
		nid.HWnd = hwnd
		nid.UID = 1
		nid.UFlags = nifMessage | nifIcon | nifTip
		nid.UCallbackMessage = wmTrayCallback
		nid.HIcon = hIcon
		if tip == "" {
			tip = "APN Remote & VPN"
		}
		if u16, err := syscall.UTF16FromString(tip); err == nil {
			copy(nid.SzTip[:len(nid.SzTip)-1], u16)
		}
		_, _, _ = procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	}

	close(ready)

	if hwnd == 0 {
		return
	}

	var m msgW
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	removeTrayIcon(hwnd)
	if hIcon != 0 {
		_, _, _ = procDestroyIcon.Call(hIcon)
	}
	trayMu.Lock()
	trayHWND = 0
	trayIcon = 0
	trayMu.Unlock()
}

func removeTrayIcon(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwnd
	nid.UID = 1
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func trayWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayCallback:
		switch uint32(lParam) {
		case wmLButtonDblClk:
			trayMu.Lock()
			fn := trayCB.OnOpen
			trayMu.Unlock()
			if fn != nil {
				go fn()
			}
			return 0
		case wmRButtonUp, wmContextMenu:
			showContextMenu(hwnd)
			return 0
		}
	case wmCommand:
		id := uint16(wParam & 0xFFFF)
		trayMu.Lock()
		cb := trayCB
		trayMu.Unlock()
		switch id {
		case cmdOpen:
			if cb.OnOpen != nil {
				go cb.OnOpen()
			}
		case cmdCopyID:
			if cb.OnCopyID != nil {
				go cb.OnCopyID()
			}
		case cmdPause:
			if cb.OnTogglePause != nil {
				go cb.OnTogglePause()
			}
		case cmdQuit:
			removeTrayIcon(hwnd)
			if cb.OnQuit != nil {
				go cb.OnQuit()
			}
			_, _, _ = procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmClose:
		removeTrayIcon(hwnd)
		_, _, _ = procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func showContextMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	trayMu.Lock()
	cb := trayCB
	trayMu.Unlock()

	addItem := func(id uintptr, text string) {
		ptr, _ := syscall.UTF16PtrFromString(text)
		_, _, _ = procAppendMenuW.Call(menu, mfString, id, uintptr(unsafe.Pointer(ptr)))
	}
	addSep := func() {
		_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	}

	addItem(cmdOpen, "เปิดโปรแกรม APN")
	_, _, _ = procSetMenuDefaultItem.Call(menu, cmdOpen, 0)
	if cb.DeviceIDLabel != "" {
		addItem(cmdCopyID, "คัดลอกรหัสเครื่อง ("+cb.DeviceIDLabel+")")
	}
	addSep()
	if cb.IsPaused != nil && cb.IsPaused() {
		addItem(cmdPause, "เปิดรับรีโมตอีกครั้ง")
	} else {
		addItem(cmdPause, "พักรับรีโมตชั่วคราว")
	}
	addSep()
	addItem(cmdQuit, "ออกจากโปรแกรม APN")

	var pt pointW
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(hwnd)
	_, _, _ = procTrackPopupMenu.Call(menu, tpmRightButton|tpmBottomAlign, uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	_, _, _ = procPostMessageW.Call(hwnd, 0, 0, 0)
}
