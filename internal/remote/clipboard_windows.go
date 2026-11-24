//go:build windows

package remote

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/draw"
	_ "image/jpeg"
	"image/png"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	clipKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc                = clipKernel32.NewProc("GlobalAlloc")
	procGlobalLock                 = clipKernel32.NewProc("GlobalLock")
	procGlobalUnlock               = clipKernel32.NewProc("GlobalUnlock")
	procGlobalFree                 = clipKernel32.NewProc("GlobalFree")
	procGlobalSize                 = clipKernel32.NewProc("GlobalSize")
)

const (
	cfDIB         = 8
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func pngClipboardFormat() uintptr {
	name, _ := syscall.UTF16PtrFromString("PNG")
	r, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(name)))
	return r
}

func openClipboardWithRetry() bool {
	for i := 0; i < 8; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

// ReadClipboard reads the current Windows system clipboard natively (PNG/CF_DIB screenshot or UTF-8 text)
// with ZERO browser permission prompts! Returns kind (0=text, 1=png) and raw bytes.
func ReadClipboard() (byte, []byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !openClipboardWithRetry() {
		return 0, nil, errors.New("เปิดคลิปบอร์ด Windows ไม่สำเร็จ")
	}
	defer procCloseClipboard.Call()

	// 1) Prefer native PNG clipboard format (if present — preserves exact PNG bytes!)
	if cfPNG := pngClipboardFormat(); cfPNG != 0 {
		if avail, _, _ := procIsClipboardFormatAvailable.Call(cfPNG); avail != 0 {
			if raw, ok := readClipboardGlobalBytes(cfPNG); ok && len(raw) > 16 {
				return 1, raw, nil
			}
		}
	}

	// 2) Standard Windows CF_DIB (Win+Shift+S, Snipping Tool, PrintScreen, LINE, Chrome, Paint!)
	if avail, _, _ := procIsClipboardFormatAvailable.Call(cfDIB); avail != 0 {
		if raw, ok := readClipboardGlobalBytes(cfDIB); ok && len(raw) >= 40 {
			pngBytes, err := dibToPNG(raw)
			if err == nil && len(pngBytes) > 0 {
				return 1, pngBytes, nil
			}
		}
	}

	// 3) Unicode Text (CF_UNICODETEXT)
	if avail, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText); avail != 0 {
		if raw, ok := readClipboardGlobalBytes(cfUnicodeText); ok && len(raw) >= 2 {
			n := len(raw) / 2
			u16 := make([]uint16, 0, n)
			for i := 0; i+1 < len(raw); i += 2 {
				v := binary.LittleEndian.Uint16(raw[i : i+2])
				if v == 0 {
					break
				}
				u16 = append(u16, v)
			}
			if len(u16) > 0 {
				return 0, []byte(string(utf16.Decode(u16))), nil
			}
		}
	}

	return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า (ยังไม่มีรูปหรือข้อความ)")
}

func readClipboardGlobalBytes(format uintptr) ([]byte, bool) {
	hMem, _, _ := procGetClipboardData.Call(format)
	if hMem == 0 {
		return nil, false
	}
	sz, _, _ := procGlobalSize.Call(hMem)
	if sz == 0 || sz > 32*1024*1024 {
		return nil, false
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return nil, false
	}
	defer procGlobalUnlock.Call(hMem)
	out := make([]byte, sz)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), sz))
	return out, true
}

// ApplyClipboardPayload writes UTF-8 text or a PNG/JPEG screenshot directly into the Windows
// system clipboard (BOTH CF_DIB and registered "PNG" format for 100% app compatibility!)
// and optionally triggers Ctrl+V immediately!
func ApplyClipboardPayload(kind byte, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var err error
	clipApplyMu.Lock()
	switch kind {
	case 0, 2: // text, text+paste
		err = setWinClipboardText(string(data))
	case 1, 3: // image, image+paste
		err = setWinClipboardImage(data)
	default:
		clipApplyMu.Unlock()
		return nil
	}
	// Remember the sequence number of our own write so WatchClipboardChanges does not
	// report it back to the viewer.
	ownClipSeq = ClipboardSeq()
	clipApplyMu.Unlock()
	if err != nil {
		return err
	}
	if kind == 2 || kind == 3 {
		// Give the foreground app ~50ms to observe the clipboard update, then paste with Ctrl+V!
		time.Sleep(50 * time.Millisecond)
		sendHardwareKey(0xA2, 0x1D, false, false) // ControlLeft down
		time.Sleep(12 * time.Millisecond)
		sendHardwareKey('V', 0x2F, false, false) // V down
		time.Sleep(25 * time.Millisecond)
		sendHardwareKey('V', 0x2F, false, true)  // V up
		time.Sleep(12 * time.Millisecond)
		sendHardwareKey(0xA2, 0x1D, false, true) // ControlLeft up
	}
	return nil
}

func putGlobalClipboardFormat(format uintptr, raw []byte) error {
	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(len(raw)))
	if hMem == 0 {
		return errors.New("GlobalAlloc failed")
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return errors.New("GlobalLock failed")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(raw)), raw)
	_, _, _ = procGlobalUnlock.Call(hMem)

	if r, _, _ := procSetClipboardData.Call(format, hMem); r == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return errors.New("SetClipboardData failed")
	}
	return nil
}

func setWinClipboardText(text string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !openClipboardWithRetry() {
		return errors.New("OpenClipboard failed")
	}
	defer procCloseClipboard.Call()

	_, _, _ = procEmptyClipboard.Call()
	u16 := utf16.Encode([]rune(text))
	u16 = append(u16, 0)
	raw := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(raw[i*2:i*2+2], v)
	}
	return putGlobalClipboardFormat(cfUnicodeText, raw)
}

func setWinClipboardImage(encoded []byte) error {
	img, _, err := image.Decode(bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	dib, err := imageToDIB(img)
	if err != nil {
		return err
	}
	var pngBuf bytes.Buffer
	if bytes.HasPrefix(encoded, []byte{0x89, 'P', 'N', 'G'}) {
		pngBuf.Write(encoded)
	} else {
		_ = png.Encode(&pngBuf, img)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !openClipboardWithRetry() {
		return errors.New("OpenClipboard failed")
	}
	defer procCloseClipboard.Call()

	_, _, _ = procEmptyClipboard.Call()

	// Set BOTH CF_DIB (for Win32 apps: Paint, Word, LINE Desktop) AND registered "PNG" (for Electron/Web: Discord, Teams, Chrome)!
	if err := putGlobalClipboardFormat(cfDIB, dib); err != nil {
		return err
	}
	if pngBuf.Len() > 0 {
		if cfPNG := pngClipboardFormat(); cfPNG != 0 {
			_ = putGlobalClipboardFormat(cfPNG, pngBuf.Bytes())
		}
	}
	return nil
}

func imageToDIB(img image.Image) ([]byte, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return nil, errors.New("empty image")
	}
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(rgba, rgba.Bounds(), img, b.Min, draw.Src)

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
	return dib, nil
}

func dibToPNG(dib []byte) ([]byte, error) {
	if len(dib) < 40 {
		return nil, errors.New("invalid DIB header")
	}
	hdrSize := int(binary.LittleEndian.Uint32(dib[0:4]))
	w := int(int32(binary.LittleEndian.Uint32(dib[4:8])))
	rawH := int(int32(binary.LittleEndian.Uint32(dib[8:12])))
	bpp := int(binary.LittleEndian.Uint16(dib[14:16]))
	comp := binary.LittleEndian.Uint32(dib[16:20])
	clrUsed := int(binary.LittleEndian.Uint32(dib[32:36]))

	topDown := rawH < 0
	h := rawH
	if h < 0 {
		h = -h
	}
	if w <= 0 || h <= 0 || w > 16384 || h > 16384 || hdrSize < 40 {
		return nil, errors.New("unsupported DIB geometry")
	}
	if bpp != 24 && bpp != 32 {
		return nil, errors.New("unsupported DIB bit depth")
	}

	pixOff := hdrSize
	if comp == 3 && hdrSize == 40 { // BI_BITFIELDS appends 3 uint32 color masks
		pixOff += 12
	}
	if clrUsed > 0 {
		pixOff += clrUsed * 4
	}
	bytesPerPx := bpp / 8
	rowStride := ((w * bytesPerPx) + 3) &^ 3
	if pixOff+rowStride*h > len(dib) {
		return nil, errors.New("truncated DIB pixel data")
	}

	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		srcY := y
		if !topDown {
			srcY = h - 1 - y
		}
		srcRow := pixOff + srcY*rowStride
		dstRow := y * rgba.Stride
		for x := 0; x < w; x++ {
			si := srcRow + x*bytesPerPx
			di := dstRow + x*4
			rgba.Pix[di] = dib[si+2]   // R
			rgba.Pix[di+1] = dib[si+1] // G
			rgba.Pix[di+2] = dib[si]   // B
			rgba.Pix[di+3] = 255       // Opaque alpha (Windows GDI often leaves alpha byte 0!)
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, rgba); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
