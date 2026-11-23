//go:build windows

package remote

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	clipKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGlobalAlloc      = clipKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = clipKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = clipKernel32.NewProc("GlobalUnlock")
	procGlobalFree       = clipKernel32.NewProc("GlobalFree")
)

const (
	cfDIB         = 8
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// ApplyClipboardPayload writes UTF-8 text or a PNG/JPEG screenshot directly into the Windows
// system clipboard (CF_UNICODETEXT or CF_DIB) and optionally triggers Ctrl+V immediately!
func ApplyClipboardPayload(kind byte, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var err error
	switch kind {
	case 0, 2: // text, text+paste
		err = setWinClipboardText(string(data))
	case 1, 3: // image, image+paste
		err = setWinClipboardImage(data)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if kind == 2 || kind == 3 {
		// Give the foreground app ~45ms to observe the clipboard update, then paste with Ctrl+V!
		time.Sleep(45 * time.Millisecond)
		sendHardwareKey(0xA2, 0x1D, false, false) // ControlLeft down
		time.Sleep(10 * time.Millisecond)
		sendHardwareKey('V', 0x2F, false, false) // V down
		time.Sleep(20 * time.Millisecond)
		sendHardwareKey('V', 0x2F, false, true)  // V up
		time.Sleep(10 * time.Millisecond)
		sendHardwareKey(0xA2, 0x1D, false, true) // ControlLeft up
	}
	return nil
}

func setWinClipboardBytes(format uintptr, raw []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Retry briefly in case another app temporarily holds the clipboard lock
	opened := false
	for i := 0; i < 6; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			opened = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !opened {
		return errors.New("OpenClipboard failed")
	}
	defer procCloseClipboard.Call()

	_, _, _ = procEmptyClipboard.Call()

	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(len(raw)))
	if hMem == 0 {
		return errors.New("GlobalAlloc failed")
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return errors.New("GlobalLock failed")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(raw))
	copy(dst, raw)
	_, _, _ = procGlobalUnlock.Call(hMem)

	if r, _, _ := procSetClipboardData.Call(format, hMem); r == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return errors.New("SetClipboardData failed")
	}
	return nil
}

func setWinClipboardText(text string) error {
	u16 := utf16.Encode([]rune(text))
	u16 = append(u16, 0)
	raw := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(raw[i*2:i*2+2], v)
	}
	return setWinClipboardBytes(cfUnicodeText, raw)
}

func setWinClipboardImage(encoded []byte) error {
	img, _, err := image.Decode(bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return errors.New("empty image")
	}
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(rgba, rgba.Bounds(), img, b.Min, draw.Src)

	// Build standard Windows CF_DIB: 40-byte BITMAPINFOHEADER + bottom-up 32-bit BGRA pixels.
	// Works universally in LINE, Teams, Discord, Chrome, Word, Paint, Slack, Messenger, etc.!
	const hdrSize = 40
	pixSize := w * h * 4
	dib := make([]byte, hdrSize+pixSize)
	binary.LittleEndian.PutUint32(dib[0:4], hdrSize)
	binary.LittleEndian.PutUint32(dib[4:8], uint32(int32(w)))
	binary.LittleEndian.PutUint32(dib[8:12], uint32(int32(h))) // positive = bottom-up DIB
	binary.LittleEndian.PutUint16(dib[12:14], 1)               // planes
	binary.LittleEndian.PutUint16(dib[14:16], 32)              // 32-bit BGRA
	binary.LittleEndian.PutUint32(dib[16:20], 0)               // BI_RGB
	binary.LittleEndian.PutUint32(dib[20:24], uint32(pixSize))

	src := rgba.Pix
	rowBytes := w * 4
	for y := 0; y < h; y++ {
		srcRow := (h - 1 - y) * rgba.Stride
		dstRow := hdrSize + y*rowBytes
		for x := 0; x < w; x++ {
			si := srcRow + x*4
			di := dstRow + x*4
			dib[di] = src[si+2]   // B
			dib[di+1] = src[si+1] // G
			dib[di+2] = src[si]   // R
			dib[di+3] = src[si+3] // A
		}
	}
	return setWinClipboardBytes(cfDIB, dib)
}
