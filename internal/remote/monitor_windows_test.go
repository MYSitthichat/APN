//go:build windows

package remote

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestPrimaryCaptureTarget finds the primary monitor and its DXGI output on this machine, and
// checks that WGC and DXGI capture it through the selectors used in the encoder candidates.
func TestPrimaryCaptureTarget(t *testing.T) {
	tgt := primaryCaptureTarget()
	if tgt.hmonitor == 0 {
		t.Fatal("no primary monitor handle")
	}
	t.Logf("primary hmonitor=%#x dxgi found=%v adapter=%d output=%d", tgt.hmonitor, tgt.dxgiFound, tgt.dxgiAdapt, tgt.dxgiOutput)
	ff, err := findFFmpeg()
	if err != nil {
		t.Skip("ffmpeg not installed")
	}
	w, h := ScreenSize()
	for _, c := range videoEncoderCandidates("h264", 30, w, h, w&^1, h&^1, 82, false) {
		if c.name != "WGC + x264 ZeroLatency" && c.name != "DXGI + x264 ZeroLatency" {
			continue
		}
		joined := strings.Join(c.args, " ")
		if c.tier == "WGC" && !strings.Contains(joined, "hmonitor=") {
			t.Errorf("WGC candidate does not select the primary monitor: %s", joined)
		}
		start := time.Now()
		ok := probeCandidate(context.Background(), ff, c, 6*time.Second)
		t.Logf("%s: first frame ok=%v in %v", c.name, ok, time.Since(start).Round(time.Millisecond))
		if !ok && c.tier == "WGC" {
			t.Errorf("%s produced no frame", c.name)
		}
	}
}
