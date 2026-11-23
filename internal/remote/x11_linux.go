//go:build linux

package remote

import (
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// detectLinuxDisplayEnv ensures DISPLAY and XAUTHORITY are populated even when APN
// was started from an autostart desktop entry or background service.
func detectLinuxDisplayEnv() (display, xauth string) {
	display = strings.TrimSpace(os.Getenv("DISPLAY"))
	if display == "" {
		if matches, err := filepath.Glob("/tmp/.X11-unix/X*"); err == nil && len(matches) > 0 {
			sort.Strings(matches)
			base := filepath.Base(matches[0])
			if strings.HasPrefix(base, "X") && len(base) > 1 {
				display = ":" + base[1:]
			}
		}
		if display == "" {
			display = ":0"
		}
	}

	xauth = strings.TrimSpace(os.Getenv("XAUTHORITY"))
	if xauth == "" {
		uid := os.Getuid()
		candidates := []string{}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			candidates = append(candidates, filepath.Join(home, ".Xauthority"))
		}
		candidates = append(candidates, fmt.Sprintf("/run/user/%d/gdm/Xauthority", uid))
		if mutter, err := filepath.Glob(fmt.Sprintf("/run/user/%d/.mutter-Xwaylandauth.*", uid)); err == nil {
			candidates = append(candidates, mutter...)
		}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Size() > 0 {
				xauth = c
				break
			}
		}
	}
	return display, xauth
}

func linuxCmdEnv() []string {
	display, xauth := detectLinuxDisplayEnv()
	env := append([]string(nil), os.Environ()...)
	if os.Getenv("DISPLAY") == "" && display != "" {
		env = append(env, "DISPLAY="+display)
	}
	if os.Getenv("XAUTHORITY") == "" && xauth != "" {
		env = append(env, "XAUTHORITY="+xauth)
	}
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		uid := os.Getuid()
		if matches, err := filepath.Glob(fmt.Sprintf("/run/user/%d/wayland-*", uid)); err == nil {
			for _, m := range matches {
				if !strings.HasSuffix(m, ".lock") {
					env = append(env, "WAYLAND_DISPLAY="+filepath.Base(m))
					break
				}
			}
		}
	}
	return env
}

func isLinuxWayland() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("XDG_SESSION_TYPE")), "wayland") {
		return true
	}
	return strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
}

// x11State holds a reusable pure-Go X11 connection.
// Capture and Input use TWO separate connections so mouse_move NEVER blocks waiting on GetImage!
type x11State struct {
	mu      sync.Mutex
	conn    *xgb.Conn
	root    xproto.Window
	w, h    int
	depth   byte
	hasTest bool
	buf     *image.RGBA
}

var (
	linuxX11Cap x11State
	linuxX11Inp x11State
)

func (x *x11State) ensureLocked() error {
	if x.conn != nil {
		return nil
	}
	display, xauth := detectLinuxDisplayEnv()
	if os.Getenv("XAUTHORITY") == "" && xauth != "" {
		_ = os.Setenv("XAUTHORITY", xauth)
	}
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return err
	}
	setup := xproto.Setup(conn)
	if setup == nil || len(setup.Roots) == 0 {
		conn.Close()
		return errors.New("X11 server has no screens")
	}
	screen := setup.DefaultScreen(conn)
	x.conn = conn
	x.root = screen.Root
	x.w = int(screen.WidthInPixels)
	x.h = int(screen.HeightInPixels)
	x.depth = screen.RootDepth
	x.hasTest = xtest.Init(conn) == nil
	return nil
}

func (x *x11State) resetLocked() {
	if x.conn != nil {
		x.conn.Close()
		x.conn = nil
	}
	x.hasTest = false
}

func x11ScreenSize() (int, int, bool) {
	linuxX11Cap.mu.Lock()
	defer linuxX11Cap.mu.Unlock()
	if err := linuxX11Cap.ensureLocked(); err != nil {
		return 0, 0, false
	}
	geom, err := xproto.GetGeometry(linuxX11Cap.conn, xproto.Drawable(linuxX11Cap.root)).Reply()
	if err == nil && geom.Width > 0 && geom.Height > 0 {
		linuxX11Cap.w = int(geom.Width)
		linuxX11Cap.h = int(geom.Height)
	}
	if linuxX11Cap.w > 0 && linuxX11Cap.h > 0 {
		return linuxX11Cap.w, linuxX11Cap.h, true
	}
	return 0, 0, false
}

// captureX11Native captures the entire root desktop in 100% pure Go (zero CGO, zero external tools).
func captureX11Native() (*image.RGBA, error) {
	linuxX11Cap.mu.Lock()
	defer linuxX11Cap.mu.Unlock()

	if err := linuxX11Cap.ensureLocked(); err != nil {
		return nil, err
	}

	geom, err := xproto.GetGeometry(linuxX11Cap.conn, xproto.Drawable(linuxX11Cap.root)).Reply()
	if err != nil {
		linuxX11Cap.resetLocked()
		return nil, err
	}
	w, h := int(geom.Width), int(geom.Height)
	if w <= 0 || h <= 0 {
		return nil, errors.New("invalid X11 root screen geometry")
	}
	linuxX11Cap.w, linuxX11Cap.h = w, h

	reply, err := xproto.GetImage(
		linuxX11Cap.conn,
		xproto.ImageFormatZPixmap,
		xproto.Drawable(linuxX11Cap.root),
		0, 0,
		uint16(w), uint16(h),
		0xffffffff,
	).Reply()
	if err != nil {
		linuxX11Cap.resetLocked()
		return nil, err
	}

	data := reply.Data
	if len(data) < w*h*4 {
		return nil, fmt.Errorf("unexpected X11 ZPixmap size: got %d want %d", len(data), w*h*4)
	}

	if linuxX11Cap.buf == nil || linuxX11Cap.buf.Bounds().Dx() != w || linuxX11Cap.buf.Bounds().Dy() != h {
		linuxX11Cap.buf = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	pix := linuxX11Cap.buf.Pix
	total := w * h * 4
	// X11 ZPixmap 24/32-bit on little-endian Linux is BGRX -> convert in-place to RGBA.
	for i := 0; i < total; i += 4 {
		pix[i] = data[i+2]
		pix[i+1] = data[i+1]
		pix[i+2] = data[i]
		pix[i+3] = 255
	}

	sizeMu.Lock()
	lastW, lastH = w, h
	sizeMu.Unlock()
	return linuxX11Cap.buf, nil
}

// applyX11Input injects mouse/wheel/keyboard events directly into X11 via a DEDICATED X11 connection
// (~0.1ms, zero contention with screen capture, zero xdotool spawn overhead!).
func applyX11Input(ev InputEvent) (bool, error) {
	linuxX11Inp.mu.Lock()
	defer linuxX11Inp.mu.Unlock()

	if err := linuxX11Inp.ensureLocked(); err != nil {
		return false, nil
	}
	// Use live tracked screen size so mouse mapping stays accurate even after resolution changes.
	sizeMu.RLock()
	w, h := lastW, lastH
	sizeMu.RUnlock()
	if w <= 0 || h <= 0 {
		w, h = linuxX11Inp.w, linuxX11Inp.h
	}
	if w <= 0 || h <= 0 {
		w, h = 1920, 1080
	}
	px := int16(clamp(int(ev.X*float64(w)), 0, w-1))
	py := int16(clamp(int(ev.Y*float64(h)), 0, h-1))

	if !linuxX11Inp.hasTest {
		if ev.Type == "mouse_move" {
			xproto.WarpPointer(linuxX11Inp.conn, xproto.WindowNone, linuxX11Inp.root, 0, 0, 0, 0, px, py)
			return true, nil
		}
		return false, nil
	}

	switch ev.Type {
	case "mouse_move":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		return true, nil
	case "mouse_down":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonPress, x11MouseBtn(ev.Button), 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "mouse_up":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonRelease, x11MouseBtn(ev.Button), 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "mouse_wheel":
		btn := byte(5) // scroll down
		if ev.DeltaY < 0 {
			btn = 4 // scroll up
		}
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonPress, btn, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonRelease, btn, 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "switch_lang":
		// Super_L (133) + Space (65) — standard GNOME / Ubuntu input source switch
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, 133, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, 65, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, 65, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, 133, 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "key_down":
		if kc := codeToX11Keycode(ev.Code, ev.Key); kc != 0 {
			xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, kc, 0, linuxX11Inp.root, 0, 0, 0)
			return true, nil
		}
		return false, nil
	case "key_up":
		if kc := codeToX11Keycode(ev.Code, ev.Key); kc != 0 {
			xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, kc, 0, linuxX11Inp.root, 0, 0, 0)
			return true, nil
		}
		return false, nil
	}
	return false, nil
}

func x11MouseBtn(b string) byte {
	switch b {
	case "right":
		return 3
	case "middle":
		return 2
	default:
		return 1
	}
}

// codeToX11Keycode maps W3C KeyboardEvent.code (physical key) to standard Linux Xorg evdev+8 keycodes.
// Physical keycodes work seamlessly for both English and Thai layouts as well as all shortcuts (Ctrl+C/V, Alt+Tab, Super+Space).
func codeToX11Keycode(code, key string) byte {
	if kc, ok := w3cCodeToEvdevX11[code]; ok {
		return kc
	}
	switch key {
	case "Enter":
		return 36
	case "Escape":
		return 9
	case "Backspace":
		return 22
	case "Tab":
		return 23
	case " ":
		return 65
	case "Meta", "Super", "OS":
		return 133
	case "ArrowUp":
		return 111
	case "ArrowDown":
		return 116
	case "ArrowLeft":
		return 113
	case "ArrowRight":
		return 114
	case "Delete":
		return 119
	case "Home":
		return 110
	case "End":
		return 115
	case "PageUp":
		return 112
	case "PageDown":
		return 117
	}
	return 0
}

// Standard Linux evdev keycode + 8 = X11 keycode.
var w3cCodeToEvdevX11 = map[string]byte{
	"Escape":       9,
	"Digit1":       10,
	"Digit2":       11,
	"Digit3":       12,
	"Digit4":       13,
	"Digit5":       14,
	"Digit6":       15,
	"Digit7":       16,
	"Digit8":       17,
	"Digit9":       18,
	"Digit0":       19,
	"Minus":        20,
	"Equal":        21,
	"Backspace":    22,
	"Tab":          23,
	"KeyQ":         24,
	"KeyW":         25,
	"KeyE":         26,
	"KeyR":         27,
	"KeyT":         28,
	"KeyY":         29,
	"KeyU":         30,
	"KeyI":         31,
	"KeyO":         32,
	"KeyP":         33,
	"BracketLeft":  34,
	"BracketRight": 35,
	"Enter":        36,
	"ControlLeft":  37,
	"KeyA":         38,
	"KeyS":         39,
	"KeyD":         40,
	"KeyF":         41,
	"KeyG":         42,
	"KeyH":         43,
	"KeyJ":         44,
	"KeyK":         45,
	"KeyL":         46,
	"Semicolon":    47,
	"Quote":        48,
	"Backquote":    49,
	"ShiftLeft":    50,
	"Backslash":    51,
	"KeyZ":         52,
	"KeyX":         53,
	"KeyC":         54,
	"KeyV":         55,
	"KeyB":         56,
	"KeyN":         57,
	"KeyM":         58,
	"Comma":        59,
	"Period":       60,
	"Slash":        61,
	"ShiftRight":   62,
	"NumpadMultiply": 63,
	"AltLeft":      64,
	"Space":        65,
	"CapsLock":     66,
	"F1":           67,
	"F2":           68,
	"F3":           69,
	"F4":           70,
	"F5":           71,
	"F6":           72,
	"F7":           73,
	"F8":           74,
	"F9":           75,
	"F10":          76,
	"NumLock":      77,
	"ScrollLock":   78,
	"Numpad7":      79,
	"Numpad8":      80,
	"Numpad9":      81,
	"NumpadSubtract": 82,
	"Numpad4":      83,
	"Numpad5":      84,
	"Numpad6":      85,
	"NumpadAdd":    86,
	"Numpad1":      87,
	"Numpad2":      88,
	"Numpad3":      89,
	"Numpad0":      90,
	"NumpadDecimal": 91,
	"F11":          95,
	"F12":          96,
	"NumpadEnter":  104,
	"ControlRight": 105,
	"NumpadDivide": 106,
	"PrintScreen":  107,
	"AltRight":     108,
	"Home":         110,
	"ArrowUp":      111,
	"PageUp":       112,
	"ArrowLeft":    113,
	"ArrowRight":   114,
	"End":          115,
	"ArrowDown":    116,
	"PageDown":     117,
	"Insert":       118,
	"Delete":       119,
	"Pause":        127,
	"MetaLeft":     133,
	"MetaRight":    134,
	"ContextMenu":  135,
}
