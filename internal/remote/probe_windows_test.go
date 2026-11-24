//go:build windows

package remote

import (
	"context"
	"testing"
	"time"
)

// TestProbeCandidateWGC checks the background WGC re-probe on this machine's real FFmpeg: a working
// WGC candidate delivers a frame, and a broken command line does not.
func TestProbeCandidateWGC(t *testing.T) {
	ff, err := findFFmpeg()
	if err != nil {
		t.Skip("ffmpeg not installed")
	}
	ctx := context.Background()
	var wgc *encoderCandidate
	for _, c := range videoEncoderCandidates("h264", 60, 1920, 1080, 1280, 720, 82, false) {
		if c.tier == "WGC" && (c.name == "WGC + x264 ZeroLatency") {
			c := c
			wgc = &c
		}
	}
	if wgc == nil {
		t.Fatal("no WGC x264 candidate")
	}
	start := time.Now()
	if !probeCandidate(ctx, ff, *wgc, 5*time.Second) {
		t.Skip("WGC capture not available in this session")
	}
	t.Logf("WGC probe ok in %v", time.Since(start).Round(time.Millisecond))

	broken := *wgc
	broken.args = []string{"-f", "lavfi", "-i", "nosuchfilter_apn", "-f", "flv", "pipe:1"}
	if probeCandidate(ctx, ff, broken, 3*time.Second) {
		t.Fatal("a broken command must not pass the probe")
	}
}
