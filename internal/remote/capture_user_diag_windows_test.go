//go:build windows && capturediag

// On-machine diagnostic for the System Service capture path (not part of normal test runs).
// Build with `go test -c -tags capturediag ./internal/remote` and run it as SYSTEM in the user's
// session (e.g. through APN's remote shell on a machine with the service installed). It starts
// FFmpeg the way the service worker does and grabs a few frames. It changes nothing.
package remote

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/bootstrap"
)

func TestCaptureAsSessionUserDiag(t *testing.T) {
	_ = os.Setenv("APN_SERVICE_WORKER", "1")
	if dir := os.Getenv("APN_BIN_DIR"); dir == "" {
		_ = os.Setenv("APN_BIN_DIR", `C:\ProgramData\APN\bin`)
	}
	t.Logf("input desktop: %q", inputDesktopName())
	_, hasTok := sessionUserToken()
	t.Logf("session user token available: %v", hasTok)
	ff, ok := bootstrap.FindFFmpeg()
	if !ok {
		t.Fatal("ffmpeg not found")
	}
	run := func(label string, asUser bool, args ...string) {
		cmd := exec.Command(ff, append([]string{"-nostdin", "-hide_banner", "-loglevel", "error"}, args...)...)
		release := func() {}
		if asUser {
			release = prepareCaptureCmd(cmd)
		} else {
			_ = os.Setenv("APN_SERVICE_WORKER", "0")
			release = prepareCaptureCmd(cmd)
			_ = os.Setenv("APN_SERVICE_WORKER", "1")
		}
		var out strings.Builder
		cmd.Stdout = &out
		cmd.Stderr = &out
		start := time.Now()
		err := cmd.Start()
		release()
		if err != nil {
			t.Logf("%s: start failed: %v", label, err)
			return
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err = <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			err = <-done
			t.Logf("%s: TIMEOUT after 10s", label)
			return
		}
		msg := strings.TrimSpace(out.String())
		if len(msg) > 160 {
			msg = msg[:160]
		}
		if err != nil {
			t.Logf("%s: FAIL (%v) %s", label, err, msg)
			return
		}
		t.Logf("%s: OK in %s", label, time.Since(start).Round(time.Millisecond))
	}
	wgc := []string{"-f", "lavfi", "-i", "gfxcapture=monitor_idx=0:max_framerate=60", "-frames:v", "1", "-f", "null", "-"}
	run("WGC as SYSTEM (before)", false, wgc...)
	run("WGC as session user (after)", true, wgc...)
}
