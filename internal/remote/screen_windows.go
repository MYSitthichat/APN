//go:build windows

package remote

import (
	"fmt"
	"image"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	user32 = syscall.NewLazyDLL("user32.dll")
	gdi32  = syscall.NewLazyDLL("gdi32.dll")

	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	procGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	procGetDC              = user32.NewProc("GetDC")
	procReleaseDC          = user32.NewProc("ReleaseDC")
	procSetCursorPos       = user32.NewProc("SetCursorPos")
	procMouseEvent         = user32.NewProc("mouse_event")
	procKeybdEvent         = user32.NewProc("keybd_event")
	procSendInput          = user32.NewProc("SendInput")
	procMapVirtualKey      = user32.NewProc("MapVirtualKeyW")
	procGetCursorInfo      = user32.NewProc("GetCursorInfo")
	procGetCursorPos       = user32.NewProc("GetCursorPos")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procGetIconInfo        = user32.NewProc("GetIconInfo")
	procDrawIconEx         = user32.NewProc("DrawIconEx")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procBitBlt             = gdi32.NewProc("BitBlt")
	procGdiFlush           = gdi32.NewProc("GdiFlush")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")

	dpiOnce sync.Once
)

const (
	smCXScreen = 0
	smCYScreen = 1

	srccopy       = 0x00CC0020
	biRGB         = 0
	dibRGB        = 0
	cursorShowing = 0x00000001
	diNormal      = 0x0003

	mouseEventLeftDown   = 0x0002
	mouseEventLeftUp     = 0x0004
	mouseEventRightDown  = 0x0008
	mouseEventRightUp    = 0x0010
	mouseEventMiddleDown = 0x0020
	mouseEventMiddleUp   = 0x0040
	mouseEventWheel      = 0x0800

	keyEventExtendedKey = 0x0001
	keyEventKeyUp       = 0x0002
	keyEventUnicode     = 0x0004
	keyEventScanCode    = 0x0008
	inputKeyboard       = 1
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

type pointStruct struct {
	X int32
	Y int32
}

type cursorInfoStruct struct {
	Size      uint32
	Flags     uint32
	Cursor    uintptr
	ScreenPos pointStruct
}

type iconInfoStruct struct {
	Icon     uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

// keyboardInputStruct matches Win32 INPUT (40 bytes on 64-bit Windows: amd64 & arm64).
type keyboardInputStruct struct {
	Type      uint32
	_         uint32
	Vk        uint16
	Scan      uint16
	Flags     uint32
	Time      uint32
	_         uint32
	ExtraInfo uintptr
	_unionPad [8]byte
}

func ensureDPIAware() {
	dpiOnce.Do(func() {
		_, _, _ = procSetProcessDPIAware.Call()
	})
}

// ScreenSize returns the primary display width and height in physical pixels.
func ScreenSize() (int, int) {
	ensureDPIAware()
	w, _, _ := procGetSystemMetrics.Call(smCXScreen)
	h, _, _ := procGetSystemMetrics.Call(smCYScreen)
	return int(w), int(h)
}

type captureReply struct {
	img *image.RGBA
	err error
}

// winCapturer pins ALL Win32 GDI operations onto a single dedicated OS thread (runtime.LockOSThread),
// acquires a fresh desktop DC per frame (eliminating stale-DC freezes), reuses the DIBSection & RGBA
// memory buffer (zero per-frame heap allocs), calls GdiFlush, and draws the real Windows mouse cursor!
type winCapturer struct {
	reqCh   chan chan captureReply
	closeCh chan struct{}
	once    sync.Once
}

// NewCapturer creates a thread-pinned, zero-alloc Windows screen capturer with live cursor rendering.
func NewCapturer() ScreenCapturer {
	c := &winCapturer{
		reqCh:   make(chan chan captureReply),
		closeCh: make(chan struct{}),
	}
	go c.gdiWorker()
	return c
}

func (c *winCapturer) gdiWorker() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var (
		curW, curH int
		hdcMem     uintptr
		hBitmap    uintptr
		oldObj     uintptr
		dibBits    unsafe.Pointer
		rgba       *image.RGBA
	)

	releaseMem := func() {
		if hdcMem != 0 && oldObj != 0 {
			procSelectObject.Call(hdcMem, oldObj)
			oldObj = 0
		}
		if hBitmap != 0 {
			procDeleteObject.Call(hBitmap)
			hBitmap = 0
		}
		if hdcMem != 0 {
			procDeleteDC.Call(hdcMem)
			hdcMem = 0
		}
		dibBits = nil
		curW, curH = 0, 0
	}
	defer releaseMem()

	ensureMem := func(hdcScreen uintptr, w, h int) error {
		if curW == w && curH == h && hBitmap != 0 && hdcMem != 0 && dibBits != nil {
			return nil
		}
		releaseMem()

		memDC, _, _ := procCreateCompatibleDC.Call(hdcScreen)
		if memDC == 0 {
			return fmt.Errorf("CreateCompatibleDC failed")
		}

		var bi bitmapInfo
		bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
		bi.Header.Width = int32(w)
		bi.Header.Height = -int32(h) // top-down DIB
		bi.Header.Planes = 1
		bi.Header.BitCount = 32
		bi.Header.Compression = biRGB

		var bits unsafe.Pointer
		bmp, _, err := procCreateDIBSection.Call(
			hdcScreen,
			uintptr(unsafe.Pointer(&bi)),
			dibRGB,
			uintptr(unsafe.Pointer(&bits)),
			0,
			0,
		)
		if bmp == 0 || bits == nil {
			procDeleteDC.Call(memDC)
			return fmt.Errorf("CreateDIBSection failed: %w", err)
		}

		old, _, _ := procSelectObject.Call(memDC, bmp)
		hdcMem = memDC
		hBitmap = bmp
		oldObj = old
		dibBits = bits
		curW, curH = w, h
		rgba = &image.RGBA{
			Pix:    make([]byte, w*h*4),
			Stride: w * 4,
			Rect:   image.Rect(0, 0, w, h),
		}
		return nil
	}

	for {
		select {
		case <-c.closeCh:
			return
		case replyCh := <-c.reqCh:
			w, h := ScreenSize()
			if w <= 0 || h <= 0 {
				replyCh <- captureReply{err: fmt.Errorf("invalid screen dimensions %dx%d", w, h)}
				continue
			}

			// Acquire a fresh desktop DC per frame so Windows DWM/UAC/monitor transitions never freeze it.
			hdcScreen, _, _ := procGetDC.Call(0)
			if hdcScreen == 0 {
				replyCh <- captureReply{err: fmt.Errorf("GetDC failed")}
				continue
			}

			if err := ensureMem(hdcScreen, w, h); err != nil {
				procReleaseDC.Call(0, hdcScreen)
				replyCh <- captureReply{err: err}
				continue
			}

			r, _, err := procBitBlt.Call(
				hdcMem, 0, 0, uintptr(w), uintptr(h),
				hdcScreen, 0, 0, srccopy,
			)
			procReleaseDC.Call(0, hdcScreen)

			if r == 0 {
				releaseMem()
				replyCh <- captureReply{err: fmt.Errorf("BitBlt failed: %w", err)}
				continue
			}

			// Draw the live Windows mouse cursor onto hdcMem so remote cursor movement is always visible.
			drawWindowsCursor(hdcMem)
			// Ensure GDI finishes writing pixels into dibBits before Go reads them.
			procGdiFlush.Call()

			totalBytes := w * h * 4
			src := unsafe.Slice((*byte)(dibBits), totalBytes)
			dst := rgba.Pix
			for i := 0; i < totalBytes; i += 4 {
				dst[i] = src[i+2]
				dst[i+1] = src[i+1]
				dst[i+2] = src[i]
				dst[i+3] = 255
			}
			replyCh <- captureReply{img: rgba}
		}
	}
}

func drawWindowsCursor(hdcMem uintptr) {
	var ci cursorInfoStruct
	ci.Size = uint32(unsafe.Sizeof(ci))
	ok, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci)))

	var hCursor uintptr
	var x, y int
	if ok != 0 && (ci.Flags&cursorShowing) != 0 && ci.Cursor != 0 {
		hCursor = ci.Cursor
		x = int(ci.ScreenPos.X)
		y = int(ci.ScreenPos.Y)
	} else {
		// Headless / no-physical-mouse Windows PC (where Windows hides the hardware cursor):
		// still draw the standard arrow cursor at the live pointer coordinates so it is NEVER invisible!
		var pt pointStruct
		if okPos, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt))); okPos == 0 {
			return
		}
		const idcArrow = 32512
		cur, _, _ := procLoadCursorW.Call(0, idcArrow)
		if cur == 0 {
			return
		}
		hCursor = cur
		x = int(pt.X)
		y = int(pt.Y)
	}

	var ii iconInfoStruct
	if ok2, _, _ := procGetIconInfo.Call(hCursor, uintptr(unsafe.Pointer(&ii))); ok2 != 0 {
		x -= int(ii.XHotspot)
		y -= int(ii.YHotspot)
		if ii.HbmMask != 0 {
			procDeleteObject.Call(ii.HbmMask)
		}
		if ii.HbmColor != 0 {
			procDeleteObject.Call(ii.HbmColor)
		}
	}

	_, _, _ = procDrawIconEx.Call(
		hdcMem,
		uintptr(x),
		uintptr(y),
		hCursor,
		0, 0, 0, 0,
		diNormal,
	)
}

func (c *winCapturer) Capture() (*image.RGBA, error) {
	replyCh := make(chan captureReply, 1)
	select {
	case <-c.closeCh:
		return nil, fmt.Errorf("capturer closed")
	case c.reqCh <- replyCh:
	}
	rep := <-replyCh
	return rep.img, rep.err
}

func (c *winCapturer) Close() {
	c.once.Do(func() {
		close(c.closeCh)
	})
}

// CaptureScreen performs a single desktop capture (convenience helper).
func CaptureScreen() (*image.RGBA, error) {
	cap := NewCapturer()
	defer cap.Close()
	img, err := cap.Capture()
	if err != nil {
		return nil, err
	}
	out := image.NewRGBA(img.Rect)
	copy(out.Pix, img.Pix)
	return out, nil
}

// ApplyInputEvent injects mouse and keyboard events on Windows using standard user32 APIs.
func ApplyInputEvent(ev InputEvent) error {
	w, h := ScreenSize()
	if w <= 0 || h <= 0 {
		return nil
	}

	px := clamp(int(ev.X*float64(w)), 0, w-1)
	py := clamp(int(ev.Y*float64(h)), 0, h-1)

	switch ev.Type {
	case "mouse_move":
		_, _, _ = procSetCursorPos.Call(uintptr(px), uintptr(py))

	case "mouse_down":
		_, _, _ = procSetCursorPos.Call(uintptr(px), uintptr(py))
		if flag := mouseButtonFlag(ev.Button, true); flag != 0 {
			_, _, _ = procMouseEvent.Call(uintptr(flag), 0, 0, 0, 0)
		}

	case "mouse_up":
		_, _, _ = procSetCursorPos.Call(uintptr(px), uintptr(py))
		if flag := mouseButtonFlag(ev.Button, false); flag != 0 {
			_, _, _ = procMouseEvent.Call(uintptr(flag), 0, 0, 0, 0)
		}

	case "mouse_wheel":
		_, _, _ = procSetCursorPos.Call(uintptr(px), uintptr(py))
		delta := -ev.DeltaY
		if delta > 0 {
			delta = 120
		} else if delta < 0 {
			delta = -120
		}
		_, _, _ = procMouseEvent.Call(mouseEventWheel, 0, 0, uintptr(int32(delta)), 0)

	case "key_text":
		sendUnicodeText(ev.Text)

	case "switch_lang":
		// Send Windows+Space with a 25ms hold so Windows 10/11 TSF reliably catches it 100% of the time!
		sendHardwareKey(0x5B, 0x5B, true, false)  // MetaLeft (Win) down
		time.Sleep(15 * time.Millisecond)
		sendHardwareKey(0x20, 0x39, false, false) // Space down
		time.Sleep(25 * time.Millisecond)
		sendHardwareKey(0x20, 0x39, false, true)  // Space up
		time.Sleep(15 * time.Millisecond)
		sendHardwareKey(0x5B, 0x5B, true, true)   // MetaLeft (Win) up

	case "key_down":
		handleKey(ev, false)

	case "key_up":
		handleKey(ev, true)
	}
	return nil
}

func mouseButtonFlag(btn string, down bool) uint32 {
	switch btn {
	case "right":
		if down {
			return mouseEventRightDown
		}
		return mouseEventRightUp
	case "middle":
		if down {
			return mouseEventMiddleDown
		}
		return mouseEventMiddleUp
	default:
		if down {
			return mouseEventLeftDown
		}
		return mouseEventLeftUp
	}
}

func sendHardwareKey(vk uint16, scan uint16, extended bool, up bool) {
	if scan == 0 && vk != 0 {
		sc, _, _ := procMapVirtualKey.Call(uintptr(vk), 0) // MAPVK_VK_TO_VSC
		scan = uint16(sc)
	}
	var flags uint32
	if extended {
		flags |= keyEventExtendedKey
	}
	if up {
		flags |= keyEventKeyUp
	}
	inp := keyboardInputStruct{
		Type:  inputKeyboard,
		Vk:    vk,
		Scan:  scan,
		Flags: flags,
	}
	_, _, _ = procSendInput.Call(1, uintptr(unsafe.Pointer(&inp)), unsafe.Sizeof(inp))
}

func handleKey(ev InputEvent, up bool) {
	// 1) Preferred: Physical KeyboardEvent.code -> real Windows VK + Hardware ScanCode!
	// This guarantees 100% full keyboard fidelity: Grave Accent (`~) & Alt+Shift language switching,
	// Thai/English typing on remote layout, and Ctrl+C/V shortcuts even when local keyboard is Thai!
	if ev.Code != "" {
		if vk, scan, ext, ok := mapCodeToWinKey(ev.Code); ok {
			sendHardwareKey(vk, scan, ext, up)
			return
		}
	}

	// 2) Fallback for virtual/mobile keyboards or quick buttons without ev.Code
	if vk := mapKeyToVK(ev.Key); vk != 0 {
		sendHardwareKey(uint16(vk), 0, isExtendedVK(vk), up)
		return
	}

	runes := []rune(ev.Key)
	if len(runes) == 1 && !ev.Ctrl && !ev.Alt {
		if !up {
			sendUnicodeText(ev.Key)
		}
	}
}

func isExtendedVK(vk byte) bool {
	switch vk {
	case 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5C, 0x5D, 0xA3, 0xA5, 0x6F:
		return true
	}
	return false
}

// mapCodeToWinKey maps W3C KeyboardEvent.code to Windows Virtual-Key + AT Set-1 Hardware ScanCode.
func mapCodeToWinKey(code string) (vk uint16, scan uint16, extended bool, ok bool) {
	// Letters KeyA..KeyZ
	if len(code) == 4 && strings.HasPrefix(code, "Key") {
		c := code[3]
		if c >= 'A' && c <= 'Z' {
			return uint16(c), 0, false, true
		}
	}
	// Top-row digits Digit0..Digit9
	if len(code) == 6 && strings.HasPrefix(code, "Digit") {
		c := code[5]
		if c >= '0' && c <= '9' {
			return uint16(c), 0, false, true
		}
	}
	// Numpad0..Numpad9
	if len(code) == 7 && strings.HasPrefix(code, "Numpad") {
		c := code[6]
		if c >= '0' && c <= '9' {
			return uint16(0x60 + (c - '0')), 0, false, true
		}
	}
	switch code {
	// Language toggle / punctuation / OEM keys (with exact hardware scan codes)
	case "Backquote":
		return 0xC0, 0x29, false, true // ` ~ (Thai/Eng toggle!)
	case "Minus":
		return 0xBD, 0x0C, false, true
	case "Equal":
		return 0xBB, 0x0D, false, true
	case "BracketLeft":
		return 0xDB, 0x1A, false, true
	case "BracketRight":
		return 0xDD, 0x1B, false, true
	case "Backslash":
		return 0xDC, 0x2B, false, true
	case "IntlBackslash":
		return 0xE2, 0x56, false, true
	case "Semicolon":
		return 0xBA, 0x27, false, true
	case "Quote":
		return 0xDE, 0x28, false, true
	case "Comma":
		return 0xBC, 0x33, false, true
	case "Period":
		return 0xBE, 0x34, false, true
	case "Slash":
		return 0xBF, 0x35, false, true

	// Modifiers (distinct Left/Right for Alt+Shift / Win+Space language switching!)
	case "ShiftLeft":
		return 0xA0, 0x2A, false, true
	case "ShiftRight":
		return 0xA1, 0x36, false, true
	case "ControlLeft":
		return 0xA2, 0x1D, false, true
	case "ControlRight":
		return 0xA3, 0x1D, true, true
	case "AltLeft":
		return 0xA4, 0x38, false, true
	case "AltRight":
		return 0xA5, 0x38, true, true
	case "MetaLeft", "OSLeft":
		return 0x5B, 0x5B, true, true
	case "MetaRight", "OSRight":
		return 0x5C, 0x5C, true, true
	case "ContextMenu":
		return 0x5D, 0x5D, true, true

	// Core editing & locks
	case "Backspace":
		return 0x08, 0x0E, false, true
	case "Tab":
		return 0x09, 0x0F, false, true
	case "Enter":
		return 0x0D, 0x1C, false, true
	case "NumpadEnter":
		return 0x0D, 0x1C, true, true
	case "Space":
		return 0x20, 0x39, false, true
	case "Escape":
		return 0x1B, 0x01, false, true
	case "CapsLock":
		return 0x14, 0x3A, false, true
	case "NumLock":
		return 0x90, 0x45, true, true
	case "ScrollLock":
		return 0x91, 0x46, false, true
	case "PrintScreen":
		return 0x2C, 0x37, true, true
	case "Pause":
		return 0x13, 0x45, false, true

	// Navigation & Arrows (extended scan codes!)
	case "Insert":
		return 0x2D, 0x52, true, true
	case "Delete":
		return 0x2E, 0x53, true, true
	case "Home":
		return 0x24, 0x47, true, true
	case "End":
		return 0x23, 0x4F, true, true
	case "PageUp":
		return 0x21, 0x49, true, true
	case "PageDown":
		return 0x22, 0x51, true, true
	case "ArrowUp":
		return 0x26, 0x48, true, true
	case "ArrowDown":
		return 0x28, 0x50, true, true
	case "ArrowLeft":
		return 0x25, 0x4B, true, true
	case "ArrowRight":
		return 0x27, 0x4D, true, true

	// Numpad operators
	case "NumpadMultiply":
		return 0x6A, 0x37, false, true
	case "NumpadAdd":
		return 0x6B, 0x4E, false, true
	case "NumpadSubtract":
		return 0x6D, 0x4A, false, true
	case "NumpadDecimal":
		return 0x6E, 0x53, false, true
	case "NumpadDivide":
		return 0x6F, 0x35, true, true

	// Function keys F1-F12
	case "F1":
		return 0x70, 0x3B, false, true
	case "F2":
		return 0x71, 0x3C, false, true
	case "F3":
		return 0x72, 0x3D, false, true
	case "F4":
		return 0x73, 0x3E, false, true
	case "F5":
		return 0x74, 0x3F, false, true
	case "F6":
		return 0x75, 0x40, false, true
	case "F7":
		return 0x76, 0x41, false, true
	case "F8":
		return 0x77, 0x42, false, true
	case "F9":
		return 0x78, 0x43, false, true
	case "F10":
		return 0x79, 0x44, false, true
	case "F11":
		return 0x7A, 0x57, false, true
	case "F12":
		return 0x7B, 0x58, false, true
	}
	return 0, 0, false, false
}

func sendUnicodeText(s string) {
	if s == "" {
		return
	}
	u16 := utf16.Encode([]rune(s))
	inputs := make([]keyboardInputStruct, 0, len(u16)*2)
	for _, codeUnit := range u16 {
		inputs = append(inputs,
			keyboardInputStruct{
				Type:  inputKeyboard,
				Scan:  codeUnit,
				Flags: keyEventUnicode,
			},
			keyboardInputStruct{
				Type:  inputKeyboard,
				Scan:  codeUnit,
				Flags: keyEventUnicode | keyEventKeyUp,
			},
		)
	}
	if len(inputs) > 0 {
		_, _, _ = procSendInput.Call(
			uintptr(len(inputs)),
			uintptr(unsafe.Pointer(&inputs[0])),
			unsafe.Sizeof(inputs[0]),
		)
	}
}

func mapKeyToVK(key string) byte {
	if len(key) == 1 {
		c := strings.ToUpper(key)[0]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return c
		}
	}
	switch key {
	case "Backspace":
		return 0x08
	case "Tab":
		return 0x09
	case "Enter":
		return 0x0D
	case "Shift":
		return 0x10
	case "Control":
		return 0x11
	case "Alt":
		return 0x12
	case "Escape":
		return 0x1B
	case " ", "Space":
		return 0x20
	case "PageUp":
		return 0x21
	case "PageDown":
		return 0x22
	case "End":
		return 0x23
	case "Home":
		return 0x24
	case "ArrowLeft":
		return 0x25
	case "ArrowUp":
		return 0x26
	case "ArrowRight":
		return 0x27
	case "ArrowDown":
		return 0x28
	case "Insert":
		return 0x2D
	case "Delete":
		return 0x2E
	case "Meta":
		return 0x5B
	case "F1":
		return 0x70
	case "F2":
		return 0x71
	case "F3":
		return 0x72
	case "F4":
		return 0x73
	case "F5":
		return 0x74
	case "F6":
		return 0x75
	case "F7":
		return 0x76
	case "F8":
		return 0x77
	case "F9":
		return 0x78
	case "F10":
		return 0x79
	case "F11":
		return 0x7A
	case "F12":
		return 0x7B
	}
	return 0
}
