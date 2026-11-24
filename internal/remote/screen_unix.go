//go:build !windows

package remote

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"relayvpn/internal/bootstrap"
)

var (
	sizeMu          sync.RWMutex
	lastW           = 1920
	lastH           = 1080
	lastSizeKnown   bool
	lastSizeProbeAt time.Time
)

type unixCapturer struct {
	workingBackend string
}

// NewCapturer creates a cross-platform Unix screen capturer.
func NewCapturer() ScreenCapturer {
	return &unixCapturer{}
}

func (u *unixCapturer) Capture() (*image.RGBA, error) {
	if runtime.GOOS == "darwin" {
		return captureMacOS()
	}
	return u.captureLinux()
}

func (u *unixCapturer) Close() {}

// ScreenSize returns the real display dimensions on Linux/macOS (auto-probed via X11/xrandr).
func ScreenSize() (int, int) {
	sizeMu.RLock()
	w, h, known, probed := lastW, lastH, lastSizeKnown, lastSizeProbeAt
	sizeMu.RUnlock()

	probeTTL := 10 * time.Second
	if !known {
		probeTTL = 1 * time.Second
	}
	if runtime.GOOS == "linux" && time.Since(probed) > probeTTL {
		if nw, nh, ok := probeLinuxScreenSize(); ok {
			sizeMu.Lock()
			lastW, lastH = nw, nh
			lastSizeKnown = true
			lastSizeProbeAt = time.Now()
			sizeMu.Unlock()
			return nw, nh
		}
		sizeMu.Lock()
		lastSizeProbeAt = time.Now()
		sizeMu.Unlock()
	}
	return w, h
}

// markScreenSizeStale forces the next ScreenSize call to probe the display again
// (used when capture moves to another X display, e.g. login screen -> user desktop).
func markScreenSizeStale() {
	sizeMu.Lock()
	lastSizeKnown = false
	lastSizeProbeAt = time.Time{}
	sizeMu.Unlock()
}

var reXrandrCurrent =regexp.MustCompile(`current\s+(\d+)\s*x\s*(\d+)`)

func probeLinuxScreenSize() (int, int, bool) {
	if w, h, ok := x11ScreenSize(); ok {
		return w, h, true
	}
	if hasCmd("xrandr") {
		cmd := exec.Command("xrandr", "--current")
		cmd.Env = linuxCmdEnv()
		if out, err := cmd.Output(); err == nil {
			if m := reXrandrCurrent.FindSubmatch(out); len(m) == 3 {
				w, _ := strconv.Atoi(string(m[1]))
				h, _ := strconv.Atoi(string(m[2]))
				if w > 0 && h > 0 {
					return w, h, true
				}
			}
		}
	}
	return 0, 0, false
}

// CaptureScreen captures a single desktop frame on macOS/Linux.
func CaptureScreen() (*image.RGBA, error) {
	var c unixCapturer
	return c.Capture()
}

func captureMacOS() (*image.RGBA, error) {
	cmd := exec.Command("screencapture", "-x", "-t", "jpg", "-")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("capture command failed: %w", err)
	}
	return decodeAndTrackRGBA(out)
}

func (u *unixCapturer) captureLinux() (*image.RGBA, error) {
	// Order backends dynamically:
	//  - On X11/Xorg: pure-Go X11 GetImage first (zero deps, ~5-12ms!), then ffmpeg/scrot/maim/import/gnome-screenshot
	//  - On Wayland: grim / spectacle / gnome-screenshot first, then Xwayland pure-Go X11 / ffmpeg / scrot / import
	var order []string
	if isLinuxWayland() {
		order = []string{"grim", "spectacle", "gnome-screenshot", "x11", "ffmpeg", "scrot", "maim", "import"}
	} else {
		order = []string{"x11", "ffmpeg", "scrot", "maim", "import", "gnome-screenshot", "grim"}
	}
	if u.workingBackend != "" {
		reordered := make([]string, 0, len(order))
		reordered = append(reordered, u.workingBackend)
		for _, b := range order {
			if b != u.workingBackend {
				reordered = append(reordered, b)
			}
		}
		order = reordered
	}

	var errParts []string
	for _, backend := range order {
		img, err := runLinuxCaptureBackend(backend)
		if err == nil && img != nil {
			u.workingBackend = backend
			return img, nil
		}
		if err != nil {
			errParts = append(errParts, backend+": "+err.Error())
		}
	}

	detail := strings.Join(errParts, "; ")
	if len(detail) > 220 {
		detail = detail[:220] + "..."
	}
	disp, xauth := detectLinuxDisplayEnv()
	if isLinuxWayland() {
		return nil, fmt.Errorf("Linux เครื่องนี้ใช้โหมด Wayland ซึ่งบล็อกการจับภาพหน้าจอ (แนะนำเลือก 'Ubuntu on Xorg' ตอน Login หรือรัน sudo sed -i 's/^#WaylandEnable=false/WaylandEnable=false/' /etc/gdm3/custom.conf แล้วรีสตาร์ท) — [%s] %s", disp, detail)
	}
	return nil, fmt.Errorf("ไม่สามารถจับภาพหน้าจอ Linux ได้ (DISPLAY=%s XAUTH=%v — แนะนำติดตั้ง sudo apt install ffmpeg xdotool) — %s", disp, xauth != "", detail)
}

func runLinuxCaptureBackend(backend string) (*image.RGBA, error) {
	switch backend {
	case "x11":
		return captureX11Native()
	case "grim":
		if !hasCmd("grim") {
			return nil, nil
		}
		cmd := exec.Command("grim", "-t", "jpeg", "-")
		cmd.Env = linuxCmdEnv()
		applyLinuxUserCred(cmd)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, summarizeCmdErr(stderr.String(), err)
		}
		return decodeAndTrackRGBA(out)
	case "ffmpeg":
		ffPath, ok := bootstrap.FindFFmpeg()
		if !ok {
			return nil, nil
		}
		disp, _ := detectLinuxDisplayEnv()
		args := []string{"-loglevel", "error", "-f", "x11grab"}
		if w, h, ok := probeLinuxScreenSize(); ok && w > 0 && h > 0 {
			args = append(args, "-video_size", fmt.Sprintf("%dx%d", w, h))
		}
		args = append(args, "-i", disp, "-vframes", "1", "-f", "image2pipe", "-vcodec", "mjpeg", "-")
		cmd := exec.Command(ffPath, args...)
		cmd.Env = linuxCmdEnv()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil || len(out) < 128 {
			if err == nil {
				err = fmt.Errorf("ffmpeg returned empty frame")
			}
			return nil, summarizeCmdErr(stderr.String(), err)
		}
		return decodeAndTrackRGBA(out)
	case "scrot":
		if !hasCmd("scrot") {
			return nil, nil
		}
		return captureViaTempFile("scrot", false, func(tmp string) []string {
			return []string{"-z", "-o", tmp}
		})
	case "maim":
		if !hasCmd("maim") {
			return nil, nil
		}
		cmd := exec.Command("maim", "-f", "jpg")
		cmd.Env = linuxCmdEnv()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, summarizeCmdErr(stderr.String(), err)
		}
		return decodeAndTrackRGBA(out)
	case "import":
		if !hasCmd("import") {
			return nil, nil
		}
		cmd := exec.Command("import", "-window", "root", "jpg:-")
		cmd.Env = linuxCmdEnv()
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, summarizeCmdErr(stderr.String(), err)
		}
		return decodeAndTrackRGBA(out)
	case "gnome-screenshot":
		if !hasCmd("gnome-screenshot") {
			return nil, nil
		}
		return captureViaTempFile("gnome-screenshot", true, func(tmp string) []string {
			return []string{"-f", tmp}
		})
	case "spectacle":
		if !hasCmd("spectacle") {
			return nil, nil
		}
		return captureViaTempFile("spectacle", true, func(tmp string) []string {
			return []string{"-b", "-n", "-f", "-o", tmp}
		})
	}
	return nil, nil
}

func summarizeCmdErr(stderr string, err error) error {
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 100 {
				line = line[:100] + "..."
			}
			return fmt.Errorf("%s", line)
		}
	}
	return err
}

func captureViaTempFile(bin string, asDesktopUser bool, argsFn func(tmp string) []string) (*image.RGBA, error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("apn-cap-%d-%d.png", os.Getpid(), time.Now().UnixNano()))
	defer os.Remove(tmp)
	cmd := exec.Command(bin, argsFn(tmp)...)
	cmd.Env = linuxCmdEnv()
	if asDesktopUser {
		applyLinuxUserCred(cmd)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, summarizeCmdErr(stderr.String(), err)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return nil, err
	}
	return decodeAndTrackRGBA(data)
}

func decodeAndTrackRGBA(encoded []byte) (*image.RGBA, error) {
	img, _, err := image.Decode(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode captured image: %w", err)
	}
	b := img.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(rgba, rgba.Bounds(), img, b.Min, draw.Src)

	sizeMu.Lock()
	lastW, lastH = b.Dx(), b.Dy()
	sizeMu.Unlock()
	return rgba, nil
}

// ApplyInputEvent uses pure-Go X11 XTEST first (instant ~0.1ms, zero deps!), falling back to xdotool.
func ApplyInputEvent(ev InputEvent) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	// Try native pure-Go X11 XTEST first (mouse, wheel, physical keys, Super+Space)
	if handled, err := applyX11Input(ev); handled {
		return err
	}
	if !hasCmd("xdotool") {
		return nil
	}
	w, h := ScreenSize()
	px := strconv.Itoa(clamp(int(ev.X*float64(w)), 0, w-1))
	py := strconv.Itoa(clamp(int(ev.Y*float64(h)), 0, h-1))

	runXdo := func(args ...string) error {
		cmd := exec.Command("xdotool", args...)
		cmd.Env = linuxCmdEnv()
		return cmd.Run()
	}

	switch ev.Type {
	case "mouse_move":
		return runXdo("mousemove", px, py)
	case "mouse_down":
		return runXdo("mousemove", px, py, "mousedown", xdoMouseBtn(ev.Button))
	case "mouse_up":
		return runXdo("mousemove", px, py, "mouseup", xdoMouseBtn(ev.Button))
	case "mouse_wheel":
		n := wheelNotches(ev.DeltaY)
		if n == 0 {
			return nil
		}
		btn := "5"
		if ev.DeltaY < 0 {
			btn = "4"
		}
		return runXdo("mousemove", px, py, "click", "--repeat", strconv.Itoa(n), "--delay", "1", btn)
	case "switch_lang":
		return runXdo("key", "super+space")
	case "key_text":
		if ev.Text != "" {
			return runXdo("type", "--clearmodifiers", ev.Text)
		}
	case "key_down":
		if len([]rune(ev.Key)) == 1 && !ev.Ctrl && !ev.Alt {
			return runXdo("type", "--clearmodifiers", ev.Key)
		}
		if k := mapUnixKey(ev.Key); k != "" {
			if ev.Ctrl {
				k = "ctrl+" + k
			}
			if ev.Alt {
				k = "alt+" + k
			}
			if ev.Shift {
				k = "shift+" + k
			}
			return runXdo("key", k)
		}
	}
	return nil
}

func xdoMouseBtn(b string) string {
	switch b {
	case "right":
		return "3"
	case "middle":
		return "2"
	default:
		return "1"
	}
}

func mapUnixKey(key string) string {
	switch key {
	case "Enter":
		return "Return"
	case "Backspace":
		return "BackSpace"
	case "Tab":
		return "Tab"
	case "Escape":
		return "Escape"
	case " ":
		return "space"
	case "Meta", "Super", "OS":
		return "Super_L"
	case "ArrowUp":
		return "Up"
	case "ArrowDown":
		return "Down"
	case "ArrowLeft":
		return "Left"
	case "ArrowRight":
		return "Right"
	case "Delete":
		return "Delete"
	case "Home":
		return "Home"
	case "End":
		return "End"
	case "PageUp":
		return "Page_Up"
	case "PageDown":
		return "Page_Down"
	case "Insert":
		return "Insert"
	}
	if len(key) == 1 {
		return strings.ToLower(key)
	}
	if strings.HasPrefix(key, "F") && len(key) <= 3 {
		return key
	}
	return ""
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
