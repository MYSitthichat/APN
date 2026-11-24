//go:build linux && x11integration

// Integration test for the pure-Go X11 clipboard against a real X server and xclip.
// Needs Xvfb and xclip; run with:  DISPLAY=:99 go test -tags x11integration -run X11Clipboard ./internal/remote/
package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"testing"
	"time"
)

func xclipOut(t *testing.T, target string) []byte {
	t.Helper()
	out, err := exec.Command("xclip", "-selection", "clipboard", "-t", target, "-o").Output()
	if err != nil {
		t.Fatalf("xclip -o -t %s: %v", target, err)
	}
	return out
}

func xclipIn(t *testing.T, target string, data []byte) {
	t.Helper()
	cmd := exec.Command("xclip", "-selection", "clipboard", "-t", target, "-i")
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil { // xclip forks and keeps serving the selection
		t.Fatalf("xclip -i -t %s: %v", target, err)
	}
	time.Sleep(300 * time.Millisecond) // let APN see SelectionClear
}

// TestX11ClipboardWatch checks the host-side change watcher: a copy by another application
// (right-click -> Copy, here xclip) is reported; APN's own write (viewer -> host sync) is not,
// so the two machines never ping-pong the same clipboard.
func TestX11ClipboardWatch(t *testing.T) {
	if os.Getenv("DISPLAY") == "" {
		t.Skip("DISPLAY not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := WatchClipboardChanges(ctx)
	time.Sleep(500 * time.Millisecond) // watcher connects and subscribes

	expect := func(want bool, what string) {
		t.Helper()
		select {
		case <-changes:
			if !want {
				t.Fatalf("%s: unexpected change event", what)
			}
		case <-time.After(1500 * time.Millisecond):
			if want {
				t.Fatalf("%s: no change event", what)
			}
		}
		t.Logf("%s: OK (event=%v)", what, want)
	}

	xclipIn(t, "UTF8_STRING", []byte("copied on the Linux side"))
	expect(true, "copy by another app")

	if err := ApplyClipboardPayload(0, []byte("pushed from the viewer")); err != nil {
		t.Fatal(err)
	}
	expect(false, "APN's own write")
	if got := xclipOut(t, "UTF8_STRING"); string(got) != "pushed from the viewer" {
		t.Fatalf("APN write not visible to apps: %q", got)
	}

	xclipIn(t, "UTF8_STRING", []byte("second copy"))
	expect(true, "another copy after APN's write")
}

func TestX11ClipboardIntegration(t *testing.T) {
	if os.Getenv("DISPLAY") == "" {
		t.Skip("DISPLAY not set")
	}
	bigImg := make([]byte, 2_000_000) // far above one X request (256 KiB): needs INCR
	_, _ = rand.Read(bigImg)
	copy(bigImg, []byte("\x89PNG\r\n\x1a\n"))
	bigTxt := bytes.Repeat([]byte("สวัสดี APN clipboard 0123456789\n"), 9000) // ~400 KB UTF-8
	smallTxt := []byte("hello จาก APN")

	// APN owns the clipboard, another app (xclip) pastes.
	for _, c := range []struct {
		name    string
		isImage bool
		data    []byte
		target  string
	}{
		{"2MB image via INCR", true, bigImg, "image/png"},
		{"400KB text via INCR", false, bigTxt, "UTF8_STRING"},
		{"small text inline", false, smallTxt, "UTF8_STRING"},
	} {
		if err := x11WriteClipboard(c.isImage, c.data); err != nil {
			t.Fatalf("APN->xclip %s: write: %v", c.name, err)
		}
		got := xclipOut(t, c.target)
		if !bytes.Equal(got, c.data) {
			t.Fatalf("APN->xclip %s: got %d bytes, want %d (equal=%v)", c.name, len(got), len(c.data), bytes.Equal(got, c.data))
		}
		t.Logf("APN->xclip %s: OK (%d bytes)", c.name, len(got))
	}

	// Another app (xclip) owns the clipboard, APN reads it.
	for _, c := range []struct {
		name     string
		target   string
		data     []byte
		wantKind byte
	}{
		{"2MB image via INCR", "image/png", bigImg, 1},
		{"400KB text via INCR", "UTF8_STRING", bigTxt, 0},
		{"small text inline", "UTF8_STRING", smallTxt, 0},
	} {
		xclipIn(t, c.target, c.data)
		kind, got, err := x11ReadClipboard()
		if err != nil {
			t.Fatalf("xclip->APN %s: read: %v", c.name, err)
		}
		if kind != c.wantKind || !bytes.Equal(got, c.data) {
			t.Fatalf("xclip->APN %s: kind %d, %d bytes; want kind %d, %d bytes", c.name, kind, len(got), c.wantKind, len(c.data))
		}
		t.Logf("xclip->APN %s: OK (%d bytes)", c.name, len(got))
	}
}
