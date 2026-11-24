package remote

import (
	"context"
	"strings"
	"sync/atomic"
	"time"
)

// captureCheckResult is one capture+encoder combination tried by the in-app capture check.
type captureCheckResult struct {
	Codec  string `json:"codec"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Ms     int    `json:"ms"`
	Reason string `json:"reason,omitempty"`
}

var captureCheckRunning atomic.Bool

// runCaptureCheck tries every capture method and encoder this host offers, the way a session
// starts them, and reports each result through send as it arrives (done=true at the end). It is
// the in-app version of the capturediag tool: it shows on the viewer why a host is not on its
// fastest path, without remote shell access. Only one check runs at a time per host.
func runCaptureCheck(ctx context.Context, send func(done bool, results []captureCheckResult)) {
	if !captureCheckRunning.CompareAndSwap(false, true) {
		return
	}
	defer captureCheckRunning.Store(false)

	ff, err := findFFmpeg()
	if err != nil {
		send(true, []captureCheckResult{{Name: "FFmpeg", Reason: err.Error()}})
		return
	}
	w, h := ScreenSize()
	if w <= 0 || h <= 0 {
		w, h = 1920, 1080
	}
	var results []captureCheckResult
	seenGDI := map[string]bool{}
	for _, codec := range []string{"hevc", "h264"} {
		for _, c := range videoEncoderCandidates(codec, 60, w, h, w&^1, h&^1, 82, false) {
			if ctx.Err() != nil {
				return
			}
			if c.tier == "GDI" { // one GDI line per codec is enough as a baseline
				if seenGDI[codec] {
					continue
				}
				seenGDI[codec] = true
			}
			start := time.Now()
			ok, timedOut, stderr := probeCandidateDetail(ctx, ff, c, 5*time.Second)
			r := captureCheckResult{Codec: codec, Name: c.name, OK: ok, Ms: int(time.Since(start).Milliseconds())}
			if !ok {
				switch {
				case timedOut:
					r.Reason = "ไม่ได้ภาพแรกภายใน 5 วินาที"
				default:
					r.Reason, _ = explainVideoFailure(c.tier, stderr, nil)
				}
				r.Reason = strings.TrimSpace(r.Reason)
				noteCaptureStderr(stderr)
			}
			results = append(results, r)
			send(false, results)
		}
	}
	send(true, results)
}
