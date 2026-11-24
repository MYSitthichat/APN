//go:build linux && x11diag

// On-machine diagnostic for X session selection (not part of normal test runs). Build with
// `go test -c -tags x11diag ./internal/remote` and run as root on the host with
// `-test.run TestX11SessionDiag -test.v`. It changes nothing on the machine.
package remote

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"relayvpn/internal/bootstrap"
)

func TestX11SessionDiag(t *testing.T) {
	t.Logf("active VT: %d", readActiveVT())
	for i, s := range discoverLinuxSessions() {
		if i >= 8 {
			break
		}
		t.Logf("#%d prio=%-4d display=%-4s uid=%-5d xauth=%s type=%s runtime=%s",
			i, s.Priority, s.Display, s.UID, s.XAuthority, s.SessionType, s.RuntimeDir)
	}
	s, ok := verifiedCaptureSession()
	t.Logf("verified capture session: ok=%v display=%s xauth=%s", ok, s.Display, s.XAuthority)
	disp := captureDisplay()
	w, h := ScreenSize()
	ff, okFF := bootstrap.FindFFmpeg()
	if !okFF {
		t.Fatalf("ffmpeg not found")
	}
	cmd := exec.Command(ff, "-nostdin", "-hide_banner", "-loglevel", "error", "-f", "x11grab",
		"-video_size", fmt.Sprintf("%dx%d", w, h), "-i", disp, "-vframes", "1", "-f", "null", "-")
	release := prepareCaptureCmd(cmd)
	out, err := cmd.CombinedOutput()
	release()
	var xa string
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "XAUTHORITY=") || strings.HasPrefix(kv, "DISPLAY=") {
			xa += kv + " "
		}
	}
	t.Logf("ffmpeg env: %s", xa)
	if err != nil {
		t.Fatalf("ffmpeg x11grab %s (%dx%d) FAILED: %v %s", disp, w, h, err, strings.TrimSpace(string(out)))
	}
	t.Logf("ffmpeg x11grab %s (%dx%d): OK", disp, w, h)
}
