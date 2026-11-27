//go:build linux && capturediag

package remote

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// TestWaylandCaptureDiag runs APN's real capture path on the machine it runs on: session
// discovery, the Mutter helper, the GStreamer source and the encoder candidates. Run as root on a
// GNOME Wayland desktop (or the headless Mutter test container):
//
//	go test -tags capturediag -run TestWaylandCaptureDiag ./internal/remote/
//
// APN_DIAG_DUMP names a file that receives a few seconds of the first working candidate's FLV
// stream. APN_DIAG_MOVE=1 also moves the pointer to 25% / 30% of the screen through ApplyInputEvent.
// APN_DIAG_HELPER is the APN binary used for "wayland-cast" (default /usr/local/bin/apn).
func TestWaylandCaptureDiag(t *testing.T) {
	ff, err := findFFmpeg()
	if err != nil {
		t.Fatal(err)
	}
	// The helper is "apn wayland-cast"; a test binary does not have that subcommand.
	waylandHelperExe = os.Getenv("APN_DIAG_HELPER")
	if waylandHelperExe == "" {
		waylandHelperExe = "/usr/local/bin/apn"
	}
	s, isWayland := waylandSession()
	t.Logf("session: wayland=%v uid=%d display=%q wayland_display=%q type=%q runtime=%q dbus=%q",
		isWayland, s.UID, s.Display, s.WaylandDisplay, s.SessionType, s.RuntimeDir, s.DBusAddr)
	w, h := ScreenSize()
	t.Logf("screen %dx%d", w, h)
	cands := videoEncoderCandidates("h264", 30, w, h, w&^1, h&^1, 82, true)
	t.Logf("helper active=%v err=%q", waylandCaptureActive(), waylandCaptureError())
	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	dump := os.Getenv("APN_DIAG_DUMP")
	for _, c := range cands {
		if dump == "" && os.Getenv("APN_DIAG_DUMP") != "" {
			break // dumped the first working candidate
		}
		ok, timedOut, stderr := probeCandidateDetail(context.Background(), ff, c, 6*time.Second)
		t.Logf("candidate %q tier=%s wayland=%v ok=%v timedOut=%v err=%.300s", c.name, c.tier, c.source != nil, ok, timedOut, stderr)
		if ok && dump != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			var errb bytes.Buffer
			cmd, stdout, cleanup, err := startCandidate(ctx, ff, c, &errb)
			if err == nil {
				var buf bytes.Buffer
				_, _ = buf.ReadFrom(stdout)
				_ = cmd.Wait()
				cleanup()
				_ = os.WriteFile(dump, buf.Bytes(), 0o644)
				t.Logf("dumped %d bytes of %q to %s", buf.Len(), c.name, dump)
			}
			cancel()
			dump = ""
		}
	}
	if os.Getenv("APN_DIAG_MOVE") == "1" {
		err := ApplyInputEvent(InputEvent{Type: "mouse_move", X: 0.25, Y: 0.30})
		time.Sleep(300 * time.Millisecond)
		t.Logf("pointer move through ApplyInputEvent: err=%v", err)
	}
}

// TestWaylandWarmupDiag checks that the startup encoder warmup leaves a Wayland desktop alone
// (it would otherwise start Mutter's screen cast and GNOME's "screen is being shared" icon).
func TestWaylandWarmupDiag(t *testing.T) {
	waylandHelperExe = "/usr/local/bin/apn"
	t.Logf("wayland desktop: %v", waylandDesktop())
	WarmupH264Encoder()
	time.Sleep(4 * time.Second)
	t.Logf("helper active after warmup: %v", waylandCaptureActive())
}

// TestWaylandHintsDiag prints the screen hints the viewer would get, and whether a capture
// attempt started the helper.
func TestWaylandHintsDiag(t *testing.T) {
	waylandHelperExe = "/usr/local/bin/apn"
	w, h := ScreenSize()
	cands := videoEncoderCandidates("h264", 30, w, h, w&^1, h&^1, 82, true)
	t.Logf("first candidate %q, helper active %v, hints %v", cands[0].name, waylandCaptureActive(), hostScreenHints())
}
