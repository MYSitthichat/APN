//go:build !windows

package remote

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
)

var (
	sizeMu    sync.RWMutex
	lastW     = 1280
	lastH     = 720
)

type unixCapturer struct{}

// NewCapturer creates a cross-platform Unix screen capturer.
func NewCapturer() ScreenCapturer {
	return &unixCapturer{}
}

func (u *unixCapturer) Capture() (*image.RGBA, error) {
	return CaptureScreen()
}

func (u *unixCapturer) Close() {}

// ScreenSize returns the last captured screen dimensions on Unix platforms.
func ScreenSize() (int, int) {
	sizeMu.RLock()
	defer sizeMu.RUnlock()
	return lastW, lastH
}

// CaptureScreen uses native OS capture utilities on macOS/Linux so zero-CGO cross-builds work seamlessly.
func CaptureScreen() (*image.RGBA, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// Built into macOS: capture primary screen as JPEG to stdout
		cmd = exec.Command("screencapture", "-x", "-t", "jpg", "-")
	} else {
		// Linux: try grim (Wayland), import (ImageMagick), or scrot (X11)
		switch {
		case hasCmd("grim"):
			cmd = exec.Command("grim", "-t", "jpeg", "-")
		case hasCmd("import"):
			cmd = exec.Command("import", "-window", "root", "jpg:-")
		default:
			return nil, fmt.Errorf("%w (install grim or imagemagick on Linux)", errUnsupportedPlatform)
		}
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("capture command failed: %w", err)
	}
	img, _, err := image.Decode(bytes.NewReader(out))
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

// ApplyInputEvent uses xdotool on Linux when installed (macOS requires Accessibility helper).
func ApplyInputEvent(ev InputEvent) error {
	if runtime.GOOS != "linux" || !hasCmd("xdotool") {
		return nil
	}
	w, h := ScreenSize()
	px := strconv.Itoa(clamp(int(ev.X*float64(w)), 0, w-1))
	py := strconv.Itoa(clamp(int(ev.Y*float64(h)), 0, h-1))

	switch ev.Type {
	case "mouse_move":
		return exec.Command("xdotool", "mousemove", px, py).Run()
	case "mouse_down":
		btn := "1"
		if ev.Button == "right" {
			btn = "3"
		} else if ev.Button == "middle" {
			btn = "2"
		}
		return exec.Command("xdotool", "mousemove", px, py, "mousedown", btn).Run()
	case "mouse_up":
		btn := "1"
		if ev.Button == "right" {
			btn = "3"
		} else if ev.Button == "middle" {
			btn = "2"
		}
		return exec.Command("xdotool", "mousemove", px, py, "mouseup", btn).Run()
	case "key_text":
		if ev.Text != "" {
			return exec.Command("xdotool", "type", "--clearmodifiers", ev.Text).Run()
		}
	case "key_down":
		if len([]rune(ev.Key)) == 1 && !ev.Ctrl && !ev.Alt {
			return exec.Command("xdotool", "type", "--clearmodifiers", ev.Key).Run()
		}
		if k := mapUnixKey(ev.Key); k != "" {
			return exec.Command("xdotool", "key", k).Run()
		}
	}
	return nil
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
	}
	return ""
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
