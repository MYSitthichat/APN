package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/protocol"
)

var (
	cachedEncMu      sync.RWMutex
	cachedEncByCodec = map[string]string{}
	warmupOnce       sync.Mutex
	warmupRunning    bool
	warmupCancel     context.CancelFunc
)

// keyframeRestartCooldown limits how often a keyframe request may restart the encoder.
const keyframeRestartCooldown = 1500 * time.Millisecond

// keyframeInterval is how often every encoder emits a keyframe, in real time. It is forced by
// timestamp (not by frame count, -g): WGC passes frames through only when the screen changes,
// so a frame-count GOP could go tens of seconds without a keyframe.
const keyframeInterval = 2 * time.Second

// keyframeWaitGrace is how long a keyframe request (viewer decoder reset, dropped frames) waits
// for the next periodic keyframe before the encoder is restarted to force one. Restarting FFmpeg
// freezes the picture and, on some PCs, makes WGC stall; the periodic keyframe arrives within
// keyframeInterval whenever the screen is changing. A still screen sends no frames at all, so
// there the restart after the grace period is invisible.
const keyframeWaitGrace = keyframeInterval + 300*time.Millisecond

// videoStreamEndedError reports that a working encoder delivered frames and then FFmpeg stopped
// on its own (resolution change, display sleep, lock screen, GPU reset). The caller restarts
// video instead of treating the encoder as unsupported.
type videoStreamEndedError struct {
	encoder  string
	ran      time.Duration
	cause    error
	upgraded bool // stopped on purpose because a faster capture path (WGC) works again
}

func (e *videoStreamEndedError) Error() string {
	return fmt.Sprintf("%s stopped after %s: %v", e.encoder, e.ran.Round(time.Second), e.cause)
}

func (e *videoStreamEndedError) Unwrap() error { return e.cause }

// cancelWarmup stops any in-flight background encoder probe so it never contends
// for GPU/WGC/DXGI capture when a real Remote Desktop session opens.
func cancelWarmup() {
	warmupOnce.Lock()
	cancel := warmupCancel
	warmupOnce.Unlock()
	if cancel != nil {
		cancel()
	}
}

// WarmupH264Encoder silently probes & caches the fastest working GPU H.265/H.264 encoder
// in the background at startup (and right after FFmpeg finishes auto-installing),
// so the VERY FIRST remote desktop session starts at 60 FPS GPU video in ~0.2s!
func WarmupH264Encoder() {
	cachedEncMu.RLock()
	alreadyHEVC := cachedEncByCodec["hevc"] != ""
	alreadyH264 := cachedEncByCodec["h264"] != ""
	cachedEncMu.RUnlock()
	if alreadyHEVC && alreadyH264 {
		return
	}
	ffmpegPath, err := findFFmpeg()
	if err != nil {
		return
	}

	warmupOnce.Lock()
	if warmupRunning {
		warmupOnce.Unlock()
		return
	}
	wCtx, wCancel := context.WithCancel(context.Background())
	warmupRunning = true
	warmupCancel = wCancel
	warmupOnce.Unlock()

	go func() {
		defer func() {
			wCancel()
			warmupOnce.Lock()
			warmupRunning = false
			warmupCancel = nil
			warmupOnce.Unlock()
		}()

		w, h := ScreenSize()
		if w <= 0 || h <= 0 {
			w, h = 1920, 1080
		}
		outW, outH := w&^1, h&^1

		for _, codec := range []string{"hevc", "h264"} {
			if wCtx.Err() != nil {
				return
			}
			cachedEncMu.RLock()
			done := cachedEncByCodec[codec] != ""
			cachedEncMu.RUnlock()
			if done {
				continue
			}
			candidates := videoEncoderCandidates(codec, 60, w, h, outW, outH, 82, true)
			skipTier := map[string]bool{}
			for _, cand := range candidates {
				if wCtx.Err() != nil {
					return
				}
				// Never waste startup warmup caching slow GDI capture (screen may simply be locked at boot!).
				if cand.tier == "GDI" {
					continue
				}
				if cand.tier != "" && skipTier[cand.tier] {
					continue
				}
				probeCtx, cancel := context.WithTimeout(wCtx, 2400*time.Millisecond)
				var stderrBuf bytes.Buffer
				cmd, stdout, srcCleanup, err := startCandidate(probeCtx, ffmpegPath, cand, &stderrBuf)
				if err != nil {
					cancel()
					continue
				}
				scanner := newFLVH264Reader(stdout)
				au, _, rerr := scanner.NextAccessUnit()
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				srcCleanup()
				timedOut := probeCtx.Err() == context.DeadlineExceeded
				cancel()
				if rerr == nil && len(au) > 0 {
					cachedEncMu.Lock()
					cachedEncByCodec[codec] = cand.name
					cachedEncMu.Unlock()
					break
				}
				noteCaptureStderr(stderrBuf.String())
				if cand.tier != "" && (timedOut || isCaptureTierFailure(cand.tier, stderrBuf.String())) {
					skipTier[cand.tier] = true
				}
			}
		}
	}()
}

func isCaptureTierFailure(tier, stderr string) bool {
	s := strings.ToLower(stderr)
	switch tier {
	case "WGC":
		// Only skip WGC tier if gfxcapture itself failed (NOT if an encoder like hevc_nvenc/d3d12va failed!)
		return (strings.Contains(s, "gfxcapture") && (strings.Contains(s, "no such filter") ||
			strings.Contains(s, "failed to configure") ||
			strings.Contains(s, "error") ||
			strings.Contains(s, "not supported"))) ||
			strings.Contains(s, "no such filter: 'gfxcapture'")
	case "DXGI", "DXGI1":
		return isDDACaptureFailure(stderr)
	default:
		return false
	}
}

func isDDACaptureFailure(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "desktop duplication") ||
		strings.Contains(s, "failed to duplicate") ||
		strings.Contains(s, "failed to enumerate dxgi output") ||
		strings.Contains(s, "failed to create d3d11") ||
		(strings.Contains(s, "ddagrab") && (strings.Contains(s, "access denied") ||
			strings.Contains(s, "operation not permitted") ||
			strings.Contains(s, "failed to configure") ||
			strings.Contains(s, "unsupported") ||
			strings.Contains(s, "invalid argument") ||
			strings.Contains(s, "no such filter")))
}

// wgcRetryInterval is how often a stream on a slower capture path re-tries WGC in the background.
var wgcRetryInterval = 20 * time.Second

// probeCandidate starts one capture+encoder command line and reports whether it delivers an
// encoded frame within timeout. Used to check in the background that WGC works again.
func probeCandidate(ctx context.Context, ffmpegPath string, cand encoderCandidate, timeout time.Duration) bool {
	ok, _, _ := probeCandidateDetail(ctx, ffmpegPath, cand, timeout)
	return ok
}

// probeCandidateDetail is probeCandidate that also reports FFmpeg's error output.
func probeCandidateDetail(ctx context.Context, ffmpegPath string, cand encoderCandidate, timeout time.Duration) (ok, timedOut bool, stderr string) {
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var errBuf bytes.Buffer
	cmd, stdout, srcCleanup, err := startCandidate(pctx, ffmpegPath, cand, &errBuf)
	if err != nil {
		return false, false, err.Error()
	}
	au, _, rerr := newFLVH264Reader(stdout).NextAccessUnit()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	srcCleanup()
	timedOut = pctx.Err() != nil
	return rerr == nil && len(au) > 0 && !timedOut, timedOut, errBuf.String()
}

// noteCaptureStderr starts an FFmpeg upgrade when the installed build lacks Windows Graphics
// Capture, which otherwise leaves Windows hosts on DXGI or ~11 FPS GDI capture for good.
func noteCaptureStderr(stderr string) {
	if strings.Contains(strings.ToLower(stderr), "no such filter: 'gfxcapture'") {
		bootstrap.RequestFFmpegWGCUpgrade()
	}
}

// explainVideoFailure turns an encoder probe failure into a short reason for the stats panel.
// capture=true means the capture method itself failed (not just one encoder).
func explainVideoFailure(tier, stderr string, err error) (reason string, capture bool) {
	if strings.Contains(strings.ToLower(stderr), "no such filter: 'gfxcapture'") {
		return "FFmpeg รุ่นนี้ไม่มีตัวจับภาพ WGC (gfxcapture)", true
	}
	if hint := driverHint(stderr); hint != "" {
		return hint, false
	}
	raw := summarizeFFmpegErr(stderr, err).Error()
	if tier != "" && isCaptureTierFailure(tier, stderr) {
		return "จับภาพไม่ได้: " + raw, true
	}
	return raw, false
}

var nvencDriverRe = regexp.MustCompile(`(?i)minimum required nvidia driver for nvenc is ([0-9.]+)`)

// driverHint turns "driver too old" encoder errors into the action that fixes them.
func driverHint(stderr string) string {
	if m := nvencDriverRe.FindStringSubmatch(stderr); len(m) == 2 {
		return "ต้องอัปเดต driver NVIDIA เป็น " + strings.TrimSuffix(m[1], ".00") + " ขึ้นไปจึงจะใช้ NVENC ได้"
	}
	if strings.Contains(strings.ToLower(stderr), "driver does not support the required nvenc api version") {
		return "driver NVIDIA เก่าเกินไปสำหรับ NVENC — อัปเดต driver แล้วจะใช้ NVENC ได้"
	}
	return ""
}

type videoFailure struct {
	tier, name, reason string
	capture            bool
}

var tierLabels = map[string]string{
	"WGC":   "WGC (Windows Graphics Capture)",
	"DXGI":  "DXGI Desktop Duplication",
	"DXGI1": "DXGI Desktop Duplication (GPU ตัวที่ 2)",
	"GDI":   "GDI",
}

// fallbackReasons explains, one line per capture method, why the methods tried before the chosen
// encoder were unusable, and why a GPU encoder was not used when the choice is software x264.
func fallbackReasons(fails []videoFailure, chosen encoderCandidate) []string {
	var out []string
	seen := map[string]int{}
	for _, f := range fails {
		if f.tier == chosen.tier {
			continue
		}
		label := tierLabels[f.tier]
		if label == "" {
			label = f.name
		}
		line := label + ": " + f.reason
		if i, ok := seen[f.tier]; ok {
			if f.capture && !strings.Contains(out[i], "จับภาพ") && !strings.Contains(out[i], "เริ่มไม่ทัน") {
				out[i] = line
			}
			continue
		}
		seen[f.tier] = len(out)
		out = append(out, line)
	}
	// A driver update is an action the user can take even when another encoder is working.
	for _, f := range fails {
		if strings.Contains(f.reason, "driver NVIDIA") {
			out = append(out, "NVENC: "+f.reason)
			break
		}
	}
	if strings.Contains(chosen.name, "x264") {
		for _, f := range fails {
			if f.tier == chosen.tier && !f.capture {
				out = append(out, "GPU encoder ("+f.name+"): "+f.reason)
				break
			}
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func summarizeFFmpegErr(stderr string, fallback error) error {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "nothing was written") || strings.Contains(low, "terminating thread") {
			continue
		}
		if len(line) > 140 {
			line = line[:140] + "..."
		}
		return errors.New(line)
	}
	if fallback != nil {
		return fallback
	}
	return errors.New("encoder failed")
}

// findFFmpeg looks for ffmpeg in RelayVPN's persistent bin dir, beside the exe, or on PATH.
func findFFmpeg() (string, error) {
	if p, ok := bootstrap.FindFFmpeg(); ok {
		return p, nil
	}
	return "", errors.New("ffmpeg not found")
}

// streamH264FFmpeg streams H.264 video (backward-compatible wrapper around streamVideoFFmpeg).
func streamH264FFmpeg(
	ctx context.Context,
	fps, maxWidth, quality int,
	seqCounter *atomic.Uint32,
	keyframeReqCh <-chan struct{},
	sendFrame func(byte, []byte) error,
	sendInfo func(codec, encoder, notice string),
) (string, error) {
	return streamVideoFFmpeg(ctx, "h264", fps, maxWidth, quality, seqCounter, keyframeReqCh, sendFrame, sendInfo, true, nil)
}

// streamVideoFFmpeg captures the desktop with hardware GPU acceleration (H.265/HEVC or H.264):
//   - Windows: WGC (gfxcapture) + Direct3D 12 Zero-Delay GPU (hevc_d3d12va / h264_d3d12va -async_depth 1),
//     NVENC, AMD AMF, Intel QSV, Media Foundation MFT, and x264 ZeroLatency; with DXGI/DXGI-GPU1/GDI fallbacks.
//   - macOS: AVFoundation + VideoToolbox HEVC/H.264 GPU.
//   - Linux: x11grab + NVENC / VAAPI HEVC/H.264 GPU / x264.
func streamVideoFFmpeg(
	ctx context.Context,
	codec string,
	fps, maxWidth, quality int,
	seqCounter *atomic.Uint32,
	keyframeReqCh <-chan struct{},
	sendFrame func(byte, []byte) error,
	sendInfo func(codec, encoder, notice string),
	drawCursor bool,
	stats *streamStats,
) (string, error) {
	if codec != "hevc" {
		codec = "h264"
	}
	frameType := protocol.FrameTypeH264
	if codec == "hevc" {
		frameType = protocol.FrameTypeHEVC
	}

	ffmpegPath, err := findFFmpeg()
	if err != nil {
		return "ffmpeg", errors.New("ไม่พบ ffmpeg (กำลังติดตั้งให้อัตโนมัติ)")
	}
	// Ensure any startup background warmup probe yields GPU/WGC/DXGI immediately to this live session.
	cancelWarmup()

	w, h := ScreenSize()
	if w <= 0 || h <= 0 {
		w, h = 1920, 1080
	}
	outW, outH := w, h
	if maxWidth > 0 && w > maxWidth {
		outW = maxWidth &^ 1
		outH = (h * outW / w) &^ 1
	} else {
		outW &= ^1
		outH &= ^1
	}
	if fps <= 0 {
		fps = 60
	}

	candidates := videoEncoderCandidates(codec, fps, w, h, outW, outH, quality, drawCursor)
	// Move last known working GPU encoder for this codec to the front so opening Remote Desktop starts in <0.2s!
	cachedEncMu.RLock()
	fav := cachedEncByCodec[codec]
	cachedEncMu.RUnlock()
	if fav != "" {
		for i := range candidates {
			if candidates[i].name == fav && i > 0 {
				preferred := candidates[i]
				copy(candidates[1:i+1], candidates[0:i])
				candidates[0] = preferred
				break
			}
		}
	}
	var lastErr error
	var lastEnc string
	skipTier := map[string]bool{}
	restarting := false
	var fails []videoFailure
	// wgcRetry is the WGC candidate that only timed out (no error). WGC can stall briefly (seen on
	// a hybrid-GPU workstation right after a settings change) and then work normally, so while a
	// slower capture runs it is retried in the background and the stream moves back when it works.
	var wgcRetry *encoderCandidate

	for i := 0; i < len(candidates); i++ {
		cand := candidates[i]
		if cand.tier != "" && skipTier[cand.tier] {
			continue
		}
		lastEnc = cand.name
		var stderrBuf bytes.Buffer
		cmd, stdout, srcCleanup, err := startCandidate(ctx, ffmpegPath, cand, &stderrBuf)
		if err != nil {
			lastErr = err
			fails = append(fails, videoFailure{tier: cand.tier, name: cand.name, reason: err.Error()})
			continue
		}

		scanner := newFLVH264Reader(stdout)
		// Allow 2.6s for cold GPU wake-up (e.g. Optimus RTX A1000 waking from D3 sleep);
		// broken/missing filters or unsupported encoders still fail in <100ms!
		type probeRes struct {
			au    []byte
			isKey bool
			err   error
		}
		probeCh := make(chan probeRes, 1)
		go func() {
			au, isKey, err := scanner.NextAccessUnit()
			probeCh <- probeRes{au: au, isKey: isKey, err: err}
		}()

		var firstAU []byte
		var firstIsKey bool
		probeTimer := time.NewTimer(2600 * time.Millisecond)
		select {
		case <-ctx.Done():
			probeTimer.Stop()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			srcCleanup()
			return cand.name, nil
		case <-probeTimer.C:
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			srcCleanup()
			lastErr = errors.New("encoder startup timed out")
			if cand.tier != "" && cand.tier != "GDI" {
				skipTier[cand.tier] = true
			}
			if cand.tier == "WGC" && wgcRetry == nil && strings.TrimSpace(stderrBuf.String()) == "" {
				c := cand
				wgcRetry = &c
			}
			fails = append(fails, videoFailure{tier: cand.tier, name: cand.name, capture: cand.tier != "GDI",
				reason: "เริ่มไม่ทันใน 2.6 วินาที (GPU หรือการจับภาพไม่ตอบสนอง)"})
			continue
		case pr := <-probeCh:
			probeTimer.Stop()
			if pr.err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				srcCleanup()
				lastErr = summarizeFFmpegErr(stderrBuf.String(), pr.err)
				noteCaptureStderr(stderrBuf.String())
				if cand.tier != "" && isCaptureTierFailure(cand.tier, stderrBuf.String()) {
					skipTier[cand.tier] = true
				}
				reason, capture := explainVideoFailure(cand.tier, stderrBuf.String(), pr.err)
				fails = append(fails, videoFailure{tier: cand.tier, name: cand.name, reason: reason, capture: capture})
				continue
			}
			firstAU = pr.au
			firstIsKey = pr.isKey
		}

		// Cache fast hardware-capture encoders so reconnects start in <0.2s;
		// never permanently pin slow GDI if a transient lock/sleep caused WGC/DXGI to miss once.
		if cand.tier != "GDI" {
			cachedEncMu.Lock()
			cachedEncByCodec[codec] = cand.name
			cachedEncMu.Unlock()
		}

		stats.setFallback(fallbackReasons(fails, cand))
		if codec == "hevc" {
			stats.setHEVCFailure("")
		}

		if !restarting {
			codecTitle := "H.264"
			if codec == "hevc" {
				codecTitle = "H.265/HEVC"
			}
			sendInfo(codec, cand.name, fmt.Sprintf("สตรีมวิดีโอ GPU %s (%s · %dx%d @ %d FPS)", codecTitle, cand.name, outW, outH, fps))
		}
		restarting = false

		// Tight 12-frame shock absorber (200ms max) eliminates bufferbloat while absorbing brief Wi-Fi/WAN jitter.
		type auPacket struct {
			data  []byte
			isKey bool
		}
		// Half a second of frames: a keyframe burst or a short network stall is absorbed and caught
		// up. Overflowing drops every frame until the next keyframe (up to keyframeInterval of frozen
		// picture), so that must be left to real congestion, not to one large frame.
		frameCh := make(chan auPacket, sendQueueDepth(fps))
		// needKeyCh tells the sender loop that frames were dropped and the viewer now waits for a keyframe.
		needKeyCh := make(chan struct{}, 1)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			defer close(frameCh)
			droppingUntilKey := false
			pushAU := func(au []byte, isKey bool) bool {
				if !isKey {
					if codec == "hevc" {
						isKey = isHEVCKeyframe(au)
					} else {
						isKey = isH264Keyframe(au)
					}
				}
				stats.addEncoded()
				if droppingUntilKey {
					if !isKey {
						stats.addDropped(1)
						return true
					}
					droppingUntilKey = false
				}
				select {
				case frameCh <- auPacket{data: au, isKey: isKey}:
					return true
				default:
					if isKey {
						for {
							select {
							case <-frameCh:
								stats.addDropped(1)
							default:
								goto drained
							}
						}
					drained:
						select {
						case frameCh <- auPacket{data: au, isKey: true}:
						case <-ctx.Done():
							return false
						}
					} else {
						droppingUntilKey = true
						stats.addDropped(1)
						select {
						case needKeyCh <- struct{}{}:
						default:
						}
					}
					return true
				}
			}

			if !pushAU(firstAU, firstIsKey) {
				return
			}
			for ctx.Err() == nil {
				au, isKey, err := scanner.NextAccessUnit()
				if err != nil {
					return
				}
				if !pushAU(au, isKey) {
					return
				}
			}
		}()

		// A keyframe request is met by the next periodic keyframe (keyframeInterval); only when none
		// comes within keyframeWaitGrace is the same encoder restarted, which opens with an IDR.
		// Replaying an old stored keyframe would jump the picture back in time and smear later
		// delta frames.
		launchedAt := time.Now()
		var (
			sendErr      error
			restart      bool
			ended        bool
			restartTimer *time.Timer
			restartC     <-chan time.Time
		)
		requestRestart := func() {
			if restartC != nil {
				return // already waiting for a keyframe
			}
			wait := keyframeWaitGrace
			if c := keyframeRestartCooldown - time.Since(launchedAt); c > wait {
				wait = c
			}
			restartTimer = time.NewTimer(wait)
			restartC = restartTimer.C
		}
		// The freshly launched encoder always opens with a keyframe, so requests queued while it started are already met.
		select {
		case <-keyframeReqCh:
		default:
		}
		// Linux: x11grab is bound to one X display. When the active session changes (login screen ->
		// user desktop after login, or back after logout) the stream must move with it, otherwise the
		// picture freezes on the old display while input already goes to the new one.
		var displayTick <-chan time.Time
		var displayTicker *time.Ticker
		startDisplay := captureDisplayKey()
		if startDisplay != "" {
			displayTicker = time.NewTicker(2 * time.Second)
			displayTick = displayTicker.C
		}
		var upgradeTick <-chan time.Time
		var upgradeTicker *time.Ticker
		upgradeRes := make(chan bool, 1)
		upgradeProbing := false
		upgraded := false
		if wgcRetry != nil && cand.tier != "WGC" {
			upgradeTicker = time.NewTicker(wgcRetryInterval)
			upgradeTick = upgradeTicker.C
		}
	streamLoop:
		for !restart {
			select {
			case <-ctx.Done():
				break streamLoop
			case <-upgradeTick:
				if !upgradeProbing {
					upgradeProbing = true
					retry := *wgcRetry
					go func() { upgradeRes <- probeCandidate(ctx, ffmpegPath, retry, 4*time.Second) }()
				}
			case ok := <-upgradeRes:
				upgradeProbing = false
				if ok {
					// WGC works again: remember it and restart video so the candidate loop starts with it.
					cachedEncMu.Lock()
					cachedEncByCodec[codec] = wgcRetry.name
					cachedEncMu.Unlock()
					ended, upgraded = true, true
					break streamLoop
				}
			case <-displayTick:
				if cur := captureDisplayKey(); cur != "" && cur != startDisplay {
					// The new display may have another resolution; re-probe before restarting.
					markScreenSizeStale()
					ended = true
					break streamLoop
				}
			case <-keyframeReqCh:
				requestRestart()
			case <-needKeyCh:
				requestRestart()
			case <-restartC:
				restartC = nil
				restart = true
			case pkt, ok := <-frameCh:
				if !ok {
					ended = true
					break streamLoop
				}
				stats.noteQueue(len(frameCh) + 1)
				if pkt.isKey && restartC != nil {
					// A natural keyframe already satisfies the pending request.
					restartTimer.Stop()
					restartC = nil
				}
				if err := emitVideoFrame(frameType, pkt.data, pkt.isKey, outW, outH, seqCounter, sendFrame); err != nil {
					sendErr = err
					break streamLoop
				}
			}
		}
		if restartTimer != nil {
			restartTimer.Stop()
		}
		if displayTicker != nil {
			displayTicker.Stop()
		}
		if upgradeTicker != nil {
			upgradeTicker.Stop()
		}

		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		srcCleanup()
		<-readDone

		if sendErr != nil || ctx.Err() != nil {
			return cand.name, sendErr
		}
		if restart {
			// Relaunch the same encoder; if it fails to start, the loop moves on to the next candidates.
			stats.addRestart()
			restarting = true
			i--
			continue
		}
		if ended {
			return cand.name, &videoStreamEndedError{
				encoder:  cand.name,
				ran:      time.Since(launchedAt),
				cause:    summarizeFFmpegErr(stderrBuf.String(), io.EOF),
				upgraded: upgraded,
			}
		}
		return cand.name, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no working %s encoder found", strings.ToUpper(codec))
	}
	return lastEnc, lastErr
}

type encoderCandidate struct {
	name string
	tier string // Capture tier on Windows: "WGC", "DXGI", "DXGI1", "GDI"
	args []string
	// source, when set, feeds FFmpeg's stdin (Linux Wayland: raw frames from Mutter's PipeWire stream).
	source *candidateSource
}

// candidateSource produces the input an FFmpeg candidate reads on stdin. start returns the read
// end FFmpeg gets as its stdin and a cleanup that stops the producer.
type candidateSource struct {
	name  string
	start func(ctx context.Context) (*os.File, func(), error)
}

// startCandidate launches one candidate's FFmpeg with stdout piped and stderr to errOut. Call
// cleanup after cmd.Wait: it stops the candidate's input source, if any.
func startCandidate(ctx context.Context, ffmpegPath string, cand encoderCandidate, errOut io.Writer) (*exec.Cmd, io.ReadCloser, func(), error) {
	noop := func() {}
	cmd := exec.CommandContext(ctx, ffmpegPath, cand.args...)
	release := prepareCaptureCmd(cmd)
	cmd.Stderr = errOut
	srcCleanup := noop
	var stdinFile *os.File
	if cand.source != nil {
		f, c, err := cand.source.start(ctx)
		if err != nil {
			release()
			return nil, nil, noop, fmt.Errorf("%s capture: %w", cand.source.name, err)
		}
		stdinFile, srcCleanup = f, c
		cmd.Stdin = f
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		release()
		if stdinFile != nil {
			stdinFile.Close()
		}
		srcCleanup()
		return nil, nil, noop, err
	}
	err = cmd.Start()
	release()
	if stdinFile != nil {
		stdinFile.Close() // FFmpeg has its own copy; ours would keep the producer alive after FFmpeg exits
	}
	if err != nil {
		srcCleanup()
		return nil, nil, noop, err
	}
	return cmd, stdout, srcCleanup, nil
}

// sendQueueDepth is how many encoded frames may wait for the network before frames are dropped.
func sendQueueDepth(fps int) int {
	if d := fps / 2; d > 12 {
		return d
	}
	return 12
}

func h264EncoderCandidates(fps, srcW, srcH, outW, outH, quality int) []encoderCandidate {
	return videoEncoderCandidates("h264", fps, srcW, srcH, outW, outH, quality, true)
}

// videoEncoderCandidates lists capture+encoder command lines to try in order. drawCursor=false
// leaves the mouse cursor out of the picture, for viewers that draw it locally.
func videoEncoderCandidates(codec string, fps, srcW, srcH, outW, outH, quality int, drawCursor bool) []encoderCandidate {
	fpsStr := strconv.Itoa(fps)
	cur := "1"
	if !drawCursor {
		cur = "0"
	}
	// 2-second GOP (e.g. 120 frames @ 60 FPS): balances low bandwidth with rapid packet-loss recovery!
	gopStr := strconv.Itoa(fps * 2)

	// Map UI quality selector to crisp, generous VBV bitrate targets.
	// NOTE: H.265 (HEVC) achieves equal/superior sharpness at ~60% of H.264's bitrate!
	cqStr := "20"
	targetBitrate := "5M"
	maxRate := "7M"
	hevcBitrate := "3500k"
	hevcMaxRate := "5M"
	if quality > 0 && quality <= 68 {
		cqStr = "25"
		targetBitrate = "2500k"
		maxRate = "3500k"
		hevcBitrate = "1800k"
		hevcMaxRate = "2600k"
	} else if quality >= 93 {
		cqStr = "16"
		targetBitrate = "14M"
		maxRate = "18M"
		hevcBitrate = "9M"
		hevcMaxRate = "12M"
	} else if quality >= 88 {
		cqStr = "18"
		targetBitrate = "8M"
		maxRate = "11M"
		hevcBitrate = "5500k"
		hevcMaxRate = "7500k"
	}

	// Rate-control buffer (VBV): about one second of the maximum bitrate, and it has to stay that
	// large. A clean 1080p keyframe takes 110-280 KB. With a 150 ms buffer (v1.3.31-v1.3.32)
	// keyframes were capped near 65 KB, and NVENC/QSV ran out of bits partway down the picture:
	// the lower part of every keyframe, i.e. every keyframeInterval, was unreadable until later
	// frames repaired it. Keyframe bursts have to be reduced by sending fewer keyframes instead.
	// For x264 a small buffer crushes 1080p keyframes into a macroblock mosaic the same way.
	bufSize := "7M"
	switch maxRate {
	case "3500k":
		bufSize = "4M"
	case "18M":
		bufSize = "16M"
	case "11M":
		bufSize = "10M"
	}
	hevcBufSize := hevcMaxRate

	needScale := outW != (srcW&^1) || outH != (srcH&^1)
	nv12Filter := "format=nv12"
	yuvFilter := "format=yuv420p"
	if needScale {
		nv12Filter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12", outW, outH)
		yuvFilter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=yuv420p", outW, outH)
	}

	// Zero-latency length-prefixed FLV / Enhanced-FLV output (supports both H.264 AVC & H.265 HEVC!)
	outFlags := []string{
		"-force_key_frames", fmt.Sprintf("expr:gte(t,n_forced*%g)", keyframeInterval.Seconds()),
		"-flush_packets", "1", "-f", "flv", "pipe:1",
	}
	filterThreads := runtime.NumCPU()
	if filterThreads > 4 {
		filterThreads = 4
	}
	if filterThreads < 2 {
		filterThreads = 2
	}
	inLowLatency := []string{"-loglevel", "error", "-filter_threads", strconv.Itoa(filterThreads), "-fflags", "+nobuffer+flush_packets", "-flags", "+low_delay"}

	var list []encoderCandidate

	if runtime.GOOS == "windows" {
		// Capture exactly the primary monitor (where mouse input goes), never a virtual display
		// that happens to be enumerated first: see primaryCaptureTarget.
		tgt := primaryCaptureTarget()
		wgcSel := "monitor_idx=0"
		if tgt.hmonitor != 0 {
			wgcSel = fmt.Sprintf("hmonitor=%d", uint64(tgt.hmonitor))
		}
		ddaAdapter, ddaOut := -1, 0
		if tgt.dxgiFound {
			ddaAdapter, ddaOut = tgt.dxgiAdapt, tgt.dxgiOutput
		}
		wgcSrc := fmt.Sprintf("gfxcapture=%s:capture_cursor=%s:max_framerate=%s", wgcSel, cur, fpsStr)
		if needScale {
			wgcSrc += fmt.Sprintf(":width=%d:height=%d:resize_mode=scale:scale_mode=bilinear", outW, outH)
		}
		wgcLavfi := wgcSrc + ",hwdownload,format=bgra"
		wgcNV12 := wgcSrc + ",hwdownload,format=bgra,format=nv12"
		wgcYUV := wgcSrc + ",hwdownload,format=bgra,format=yuv420p"

		ddaLavfi := fmt.Sprintf("ddagrab=output_idx=%d:framerate=%s:draw_mouse=%s:allow_fallback=1,hwdownload,format=bgra", ddaOut, fpsStr, cur)
		ddaNV12 := fmt.Sprintf("ddagrab=output_idx=%d:framerate=%s:draw_mouse=%s:allow_fallback=1,hwdownload,format=bgra,%s", ddaOut, fpsStr, cur, nv12Filter)
		ddaYUV := fmt.Sprintf("ddagrab=output_idx=%d:framerate=%s:draw_mouse=%s:allow_fallback=1,hwdownload,format=bgra,%s", ddaOut, fpsStr, cur, yuvFilter)
		// The D3D12 DXGI candidates let ddagrab open its own device on the default adapter (0).
		ddaD12OK := ddaAdapter <= 0

		// D3D12VA pipeline helper: uses `-f lavfi -i <src>` + `-init_hw_device d3d12va=d12 -filter_hw_device d12 -vf format=nv12,hwupload`
		// so gfxcapture/ddagrab owns its own internal D3D11 device while D3D12VA encodes on GPU at 250-340 FPS with ~6ms latency!
		makeWGCD12 := func(encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-init_hw_device", "d3d12va=d12", "-filter_hw_device", "d12",
				"-f", "lavfi", "-i", wgcLavfi,
				"-vf", "format=nv12,hwupload", "-fps_mode", "passthrough")
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		makeDDAD12 := func(encArgs []string) []string {
			vf := "format=nv12,hwupload"
			if needScale {
				vf = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12,hwupload", outW, outH)
			}
			args := append([]string{}, inLowLatency...)
			args = append(args, "-init_hw_device", "d3d12va=d12", "-filter_hw_device", "d12",
				"-f", "lavfi", "-i", ddaLavfi,
				"-vf", vf)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		makeWGC := func(filter string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-filter_complex", filter, "-fps_mode", "passthrough")
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		// ownEncoderDevice is for encoders that accept a D3D11 device (NVENC, AMF). FFmpeg hands a
		// lone hardware device to any such encoder, so with the primary monitor on another vendor's
		// adapter (hybrid Intel + NVIDIA/AMD) the encoder was opened on the capture adapter and
		// failed with "Invalid argument". A second device of the same type makes the choice
		// ambiguous: FFmpeg then attaches none and the encoder opens its own GPU.
		makeDDA := func(adapterIdx int, ownEncoderDevice bool, filter string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			if adapterIdx >= 0 {
				args = append(args, "-init_hw_device", fmt.Sprintf("d3d11va=dda:%d", adapterIdx))
				if ownEncoderDevice {
					args = append(args, "-init_hw_device", fmt.Sprintf("d3d11va=dda2:%d", adapterIdx))
				}
				args = append(args, "-filter_hw_device", "dda")
			}
			args = append(args, "-filter_complex", filter)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		makeGDI := func(vf string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-f", "gdigrab", "-framerate", fpsStr, "-draw_mouse", cur, "-i", "desktop", "-vf", vf)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}

		if codec == "hevc" {
			// Direct3D 12 Hardware H.265/HEVC GPU Encoder (-async_depth 1 = zero pipeline lag, verified 255 FPS @ 1080p!)
			// Works universally on NVIDIA RTX A1000/T1000/RTX, Intel UHD/Iris, AMD Radeon — zero NVENC SDK restriction!
			hevcD12Args := []string{
				"-c:v", "hevc_d3d12va", "-async_depth", "1", "-rc_mode", "VBR",
				"-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcNVENCArgs := []string{
				"-c:v", "hevc_nvenc", "-preset", "p1", "-tune", "ull",
				"-zerolatency", "1", "-rc-lookahead", "0", "-delay", "0", "-forced-idr", "1",
				"-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcBufSize, "-g", gopStr, "-bf", "0",
			}
			hevcAMFArgs := []string{
				"-c:v", "hevc_amf", "-usage", "ultralowlatency", "-quality", "speed",
				"-preanalysis", "0", "-vbaq", "0",
				"-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcBufSize, "-g", gopStr, "-bf", "0",
			}
			hevcQSVArgs := []string{
				"-c:v", "hevc_qsv", "-preset", "veryfast", "-async_depth", "1", "-look_ahead", "0",
				"-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcBufSize, "-g", gopStr, "-bf", "0",
			}
			hevcMFArgs := []string{
				"-c:v", "hevc_mf", "-hw_encoding", "1", "-scenario", "display_remoting", "-rate_control", "ld_vbr",
				"-quality", "65", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcMFSafeArgs := []string{
				"-c:v", "hevc_mf", "-hw_encoding", "1", "-scenario", "display_remoting",
				"-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}

			// Hardware H.265 GPU candidates ONLY (if none supported, ServeScreenSession cleanly falls back to 60 FPS H.264!).
			// Prefer native vendor encoders (NVENC / AMF / Intel QSV) ahead of D3D12VA for consistent
			// VPS/SPS/PPS IDR headers and lowest startup latency on modern NVIDIA/AMD/Intel drivers.
			list = append(list,
				encoderCandidate{name: "WGC + H.265 NVENC GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcNVENCArgs)},
				encoderCandidate{name: "WGC + H.265 AMD AMF GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcAMFArgs)},
				encoderCandidate{name: "WGC + H.265 Intel QSV GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcQSVArgs)},
				encoderCandidate{name: "WGC + H.265 D3D12 GPU", tier: "WGC", args: makeWGCD12(hevcD12Args)},
				encoderCandidate{name: "WGC + H.265 Hardware GPU (MF)", tier: "WGC", args: makeWGC(wgcNV12, hevcMFArgs)},
				encoderCandidate{name: "WGC + H.265 Hardware GPU (MF Safe)", tier: "WGC", args: makeWGC(wgcNV12, hevcMFSafeArgs)},
			)
			if ddaD12OK {
				list = append(list, encoderCandidate{name: "DXGI + H.265 D3D12 GPU", tier: "DXGI", args: makeDDAD12(hevcD12Args)})
			}
			list = append(list,
				encoderCandidate{name: "DXGI + H.265 Hardware GPU (MF)", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaNV12, hevcMFArgs)},
				encoderCandidate{name: "DXGI + H.265 Intel QSV GPU", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaNV12, hevcQSVArgs)},
			)
			return list
		}

		// H.264 GPU + ZeroLatency candidates:
		h264D12Args := []string{
			"-c:v", "h264_d3d12va", "-async_depth", "1", "-rc_mode", "VBR",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		mfArgs := []string{
			"-c:v", "h264_mf", "-hw_encoding", "1", "-scenario", "display_remoting", "-rate_control", "ld_vbr",
			"-quality", "65", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		mfSafeArgs := []string{
			"-c:v", "h264_mf", "-hw_encoding", "1", "-scenario", "display_remoting",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		qsvArgs := []string{
			"-c:v", "h264_qsv", "-preset", "veryfast", "-profile:v", "baseline",
			"-async_depth", "1", "-look_ahead", "0", "-rdo", "0", "-forced_idr", "1",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		amfArgs := []string{
			// h264_amf has no "baseline" profile name (FFmpeg rejects the option before trying the GPU).
			"-c:v", "h264_amf", "-usage", "ultralowlatency", "-quality", "speed", "-profile:v", "constrained_baseline",
			"-preanalysis", "0", "-vbaq", "0",
			"-rc", "cbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		nvencArgs := []string{
			"-c:v", "h264_nvenc", "-preset", "p1", "-tune", "ull", "-profile:v", "baseline",
			"-zerolatency", "1", "-rc-lookahead", "0", "-delay", "0", "-forced-idr", "1",
			"-rc", "cbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		x264Args := []string{
			"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline",
			"-x264-params", "repeat-headers=1:sliced-threads=1:rc-lookahead=0:sync-lookahead=0",
			"-crf", cqStr, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}

		// Tier 1: WGC (gfxcapture) + native vendor GPU encoders (NVENC / AMF / Intel QSV) first because
		// h264_d3d12va can emit corrupted NV12 chroma/stride frames on some Intel/hybrid iGPU drivers,
		// then H.264 D3D12VA -> crisp x264 -> MF.
		list = append(list,
			encoderCandidate{name: "WGC + NVENC GPU", tier: "WGC", args: makeWGC(wgcNV12, nvencArgs)},
			encoderCandidate{name: "WGC + AMD AMF GPU", tier: "WGC", args: makeWGC(wgcNV12, amfArgs)},
			encoderCandidate{name: "WGC + Intel QSV GPU", tier: "WGC", args: makeWGC(wgcNV12, qsvArgs)},
			encoderCandidate{name: "WGC + H.264 D3D12 GPU", tier: "WGC", args: makeWGCD12(h264D12Args)},
			encoderCandidate{name: "WGC + x264 ZeroLatency", tier: "WGC", args: makeWGC(wgcYUV, x264Args)},
			encoderCandidate{name: "WGC + Hardware GPU (MF LD-VBR)", tier: "WGC", args: makeWGC(wgcNV12, mfArgs)},
			encoderCandidate{name: "WGC + Hardware GPU (MF)", tier: "WGC", args: makeWGC(wgcNV12, mfSafeArgs)},
		)

		// Tier 2: DXGI Desktop Duplication on the primary monitor's adapter/output (allow_fallback=1)
		if ddaD12OK {
			list = append(list, encoderCandidate{name: "DXGI + H.264 D3D12 GPU", tier: "DXGI", args: makeDDAD12(h264D12Args)})
		}
		list = append(list,
			encoderCandidate{name: "DXGI + Hardware GPU (MF LD-VBR)", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI + Hardware GPU (MF)", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaNV12, mfSafeArgs)},
			encoderCandidate{name: "DXGI + Intel QSV GPU", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaNV12, qsvArgs)},
			encoderCandidate{name: "DXGI + AMD AMF GPU", tier: "DXGI", args: makeDDA(ddaAdapter, true, ddaNV12, amfArgs)},
			encoderCandidate{name: "DXGI + NVENC GPU", tier: "DXGI", args: makeDDA(ddaAdapter, true, ddaNV12, nvencArgs)},
			encoderCandidate{name: "DXGI + x264 ZeroLatency", tier: "DXGI", args: makeDDA(ddaAdapter, false, ddaYUV, x264Args)},
		)

		// Tier 3: DXGI Adapter 1 (Hybrid Optimus laptops with older FFmpeg lacking gfxcapture). Only
		// a guess when the primary monitor's adapter could not be found; otherwise Tier 2 already
		// uses the right adapter and output.
		if !tgt.dxgiFound {
			list = append(list,
				encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF LD-VBR)", tier: "DXGI1", args: makeDDA(1, false, ddaNV12, mfArgs)},
				encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF)", tier: "DXGI1", args: makeDDA(1, false, ddaNV12, mfSafeArgs)},
				encoderCandidate{name: "DXGI-GPU1 + x264 ZeroLatency", tier: "DXGI1", args: makeDDA(1, false, ddaYUV, x264Args)},
			)
		}

		// Tier 4: Last-resort fallback: gdigrab (NOTE: Never pass `-probesize 32` to gdigrab — BMP header is 54 bytes!)
		list = append(list,
			encoderCandidate{name: "GDI + Hardware GPU (MF LD-VBR)", tier: "GDI", args: makeGDI(nv12Filter, mfArgs)},
			encoderCandidate{name: "GDI + Hardware GPU (MF)", tier: "GDI", args: makeGDI(nv12Filter, mfSafeArgs)},
			encoderCandidate{name: "GDI + Intel QSV GPU", tier: "GDI", args: makeGDI(nv12Filter, qsvArgs)},
			encoderCandidate{name: "GDI + AMD AMF GPU", tier: "GDI", args: makeGDI(nv12Filter, amfArgs)},
			encoderCandidate{name: "GDI + NVENC GPU", tier: "GDI", args: makeGDI(nv12Filter, nvencArgs)},
			encoderCandidate{name: "GDI + x264 ZeroLatency", tier: "GDI", args: makeGDI(yuvFilter, x264Args)},
		)
		return list
	}

	var inputArgs []string
	// wlSource: GNOME on Wayland, where x11grab sees only an empty Xwayland root. Frames come
	// from Mutter's screen cast as raw BGRx on stdin instead (see wayland_mutter_linux.go).
	var wlSource *candidateSource
	if runtime.GOOS == "darwin" {
		inputArgs = []string{"-probesize", "32", "-analyzeduration", "0", "-f", "avfoundation", "-framerate", fpsStr, "-capture_cursor", cur, "-i", "1:none"}
	} else if src, args, ok := waylandCaptureSource(srcW, srcH, fps); ok {
		inputArgs, wlSource = args, src
	} else {
		disp := captureDisplay()
		inputArgs = []string{"-probesize", "32", "-analyzeduration", "0", "-f", "x11grab", "-framerate", fpsStr, "-draw_mouse", cur, "-video_size", fmt.Sprintf("%dx%d", srcW, srcH), "-i", disp}
	}
	withSource := func(l []encoderCandidate) []encoderCandidate {
		if wlSource == nil {
			return l
		}
		for i := range l {
			// No tier: a timed-out GPU encoder must not skip the remaining candidates (x264), which
			// a shared tier would do in streamVideoFFmpeg.
			l[i].source = wlSource
			l[i].name = "Wayland + " + strings.TrimPrefix(l[i].name, "X11 + ")
		}
		return l
	}
	makeUnix := func(vf string, encArgs []string) []string {
		args := append([]string{}, inLowLatency...)
		args = append(args, inputArgs...)
		args = append(args, "-vf", vf)
		args = append(args, encArgs...)
		args = append(args, outFlags...)
		return args
	}

	if codec == "hevc" {
		if runtime.GOOS == "darwin" {
			list = append(list, encoderCandidate{
				name: "VideoToolbox H.265 GPU",
				args: makeUnix(nv12Filter, []string{"-c:v", "hevc_videotoolbox", "-realtime", "true", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0"}),
			})
		} else {
			nvenc := []string{"-c:v", "hevc_nvenc", "-preset", "p1", "-tune", "ull", "-zerolatency", "1", "-forced-idr", "1", "-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcBufSize, "-g", gopStr, "-bf", "0"}
			vaapi := []string{"-c:v", "hevc_vaapi", "-rc_mode", "VBR", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0"}
			list = append(list, linuxGPUCandidates("H.265 ", makeUnix, inLowLatency, inputArgs, outFlags, nv12Filter, needScale, outW, outH, nvenc, vaapi)...)
		}
		return withSource(list)
	}

	if runtime.GOOS == "darwin" {
		list = append(list, encoderCandidate{
			name: "VideoToolbox GPU",
			args: makeUnix(nv12Filter, []string{"-c:v", "h264_videotoolbox", "-realtime", "true", "-profile:v", "baseline", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0"}),
		})
	} else {
		nvenc := []string{"-c:v", "h264_nvenc", "-preset", "p1", "-tune", "ull", "-profile:v", "baseline", "-zerolatency", "1", "-forced-idr", "1", "-rc", "cbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0"}
		vaapi := []string{"-c:v", "h264_vaapi", "-profile:v", "constrained_baseline", "-rc_mode", "CBR", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0"}
		list = append(list, linuxGPUCandidates("", makeUnix, inLowLatency, inputArgs, outFlags, nv12Filter, needScale, outW, outH, nvenc, vaapi)...)
	}
	list = append(list, encoderCandidate{
		name: "x264 ZeroLatency",
		args: makeUnix(yuvFilter, []string{"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-x264-params", "repeat-headers=1:sliced-threads=1:rc-lookahead=0:sync-lookahead=0", "-crf", cqStr, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0"}),
	})
	return withSource(list)
}

// linuxGPUCandidates builds the Linux X11 GPU encoder candidates for NVENC and VAAPI.
//
// The first candidate of each family converts colour on the GPU: NVENC takes x11grab's BGRX
// frames directly, and VAAPI uploads BGRX and converts/scales with scale_vaapi. That removes
// the CPU BGRX->NV12 pass (about 3-8ms per 1080p frame), which made 60 FPS uneven on weaker CPUs.
// The previous CPU-conversion candidates stay as fallbacks for drivers that reject RGB input.
// Every VAAPI render node is tried, since on hybrid laptops renderD128 is not always the encoder.
func linuxGPUCandidates(
	label string,
	makeUnix func(vf string, encArgs []string) []string,
	inLowLatency, inputArgs, outFlags []string,
	nv12Filter string,
	needScale bool,
	outW, outH int,
	nvencArgs, vaapiArgs []string,
) []encoderCandidate {
	var list []encoderCandidate
	if !needScale {
		list = append(list, encoderCandidate{
			name: "X11 + " + label + "NVENC GPU (GPU color)",
			args: makeUnix("format=bgr0", nvencArgs),
		})
	}
	list = append(list, encoderCandidate{
		name: "X11 + " + label + "NVENC GPU",
		args: makeUnix(nv12Filter, nvencArgs),
	})

	makeVAAPI := func(device, vf string) []string {
		args := append([]string{}, inLowLatency...)
		args = append(args, "-vaapi_device", device)
		args = append(args, inputArgs...)
		args = append(args, "-vf", vf)
		args = append(args, vaapiArgs...)
		args = append(args, outFlags...)
		return args
	}
	gpuVF := "format=bgr0,hwupload,scale_vaapi=format=nv12"
	cpuVF := "format=nv12,hwupload"
	if needScale {
		gpuVF = fmt.Sprintf("format=bgr0,hwupload,scale_vaapi=w=%d:h=%d:format=nv12", outW, outH)
		cpuVF = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12,hwupload", outW, outH)
	}
	for i, dev := range vaapiRenderNodes() {
		suffix := ""
		if i > 0 {
			suffix = " #" + strings.TrimPrefix(filepath.Base(dev), "renderD")
		}
		list = append(list,
			encoderCandidate{name: "X11 + " + label + "VAAPI GPU (GPU color)" + suffix, args: makeVAAPI(dev, gpuVF)},
			encoderCandidate{name: "X11 + " + label + "VAAPI GPU" + suffix, args: makeVAAPI(dev, cpuVF)},
		)
	}
	return list
}

// vaapiRenderNodes lists DRM render nodes (/dev/dri/renderD128, ...), renderD128 first.
func vaapiRenderNodes() []string {
	nodes, _ := filepath.Glob("/dev/dri/renderD*")
	sort.Strings(nodes)
	if len(nodes) == 0 {
		return []string{"/dev/dri/renderD128"}
	}
	if len(nodes) > 3 {
		nodes = nodes[:3]
	}
	return nodes
}

func emitVideoFrame(frameType byte, au []byte, isKey bool, w, h int, seqCounter *atomic.Uint32, sendFrame func(byte, []byte) error) error {
	seq := seqCounter.Add(1)
	var flags byte
	if isKey {
		flags = 1
	}
	pkt := make([]byte, 9+len(au))
	binary.BigEndian.PutUint32(pkt[0:4], seq)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(w))
	binary.BigEndian.PutUint16(pkt[6:8], uint16(h))
	pkt[8] = flags
	copy(pkt[9:], au)
	return sendFrame(frameType, pkt)
}

func isH264Keyframe(au []byte) bool {
	for i := 0; i+4 < len(au); i++ {
		if au[i] == 0 && au[i+1] == 0 {
			var nal byte
			if au[i+2] == 1 {
				nal = au[i+3] & 0x1F
			} else if au[i+2] == 0 && au[i+3] == 1 && i+4 < len(au) {
				nal = au[i+4] & 0x1F
			}
			if nal == 5 || nal == 7 {
				return true
			}
		}
	}
	return false
}

func isHEVCKeyframe(au []byte) bool {
	for i := 0; i+4 < len(au); i++ {
		if au[i] == 0 && au[i+1] == 0 {
			var nal byte
			if au[i+2] == 1 {
				nal = (au[i+3] >> 1) & 0x3F
			} else if au[i+2] == 0 && au[i+3] == 1 && i+4 < len(au) {
				nal = (au[i+4] >> 1) & 0x3F
			}
			// HEVC IRAP (BLA/IDR/CRA: 16..21) or VPS/SPS (32, 33)
			if (nal >= 16 && nal <= 21) || nal == 32 || nal == 33 {
				return true
			}
		}
	}
	return false
}

// flvH264Reader reads exact length-prefixed video frames from an FFmpeg `-f flv` stream
// (supporting BOTH standard FLV H.264/AVC and Enhanced FLV H.265/HEVC `hvc1`!)
// with ZERO 1-frame lookahead latency and converts AVCC/HVCC NAL units into Annex-B
// with automatic SPS/PPS (or VPS/SPS/PPS) prepending on keyframes.
type flvH264Reader struct {
	r           io.Reader
	headerDone  bool
	nalLenSize  int
	spsPPSAnnex []byte
	tagHdr      [11]byte
	prevSize    [4]byte
	payloadBuf  []byte
	outBuf      bytes.Buffer
}

func newFLVH264Reader(r io.Reader) *flvH264Reader {
	return &flvH264Reader{
		r:          r,
		nalLenSize: 4,
	}
}

func (f *flvH264Reader) NextAccessUnit() ([]byte, bool, error) {
	if !f.headerDone {
		var flvHdr [13]byte // 9-byte FLV header + 4-byte PreviousTagSize0
		if _, err := io.ReadFull(f.r, flvHdr[:]); err != nil {
			return nil, false, err
		}
		if flvHdr[0] != 'F' || flvHdr[1] != 'L' || flvHdr[2] != 'V' {
			return nil, false, errors.New("invalid FLV stream header")
		}
		f.headerDone = true
	}

	sc := []byte{0, 0, 0, 1}
	for {
		if _, err := io.ReadFull(f.r, f.tagHdr[:]); err != nil {
			return nil, false, err
		}
		tagType := f.tagHdr[0] & 0x1F
		dataSize := int(f.tagHdr[1])<<16 | int(f.tagHdr[2])<<8 | int(f.tagHdr[3])
		if dataSize > 16*1024*1024 {
			return nil, false, io.ErrShortBuffer
		}
		if cap(f.payloadBuf) < dataSize {
			f.payloadBuf = make([]byte, dataSize)
		}
		payload := f.payloadBuf[:dataSize]
		if dataSize > 0 {
			if _, err := io.ReadFull(f.r, payload); err != nil {
				return nil, false, err
			}
		}
		if _, err := io.ReadFull(f.r, f.prevSize[:]); err != nil {
			return nil, false, err
		}

		// Only process Video tags (type 9)
		if tagType != 9 || dataSize < 5 {
			continue
		}

		// Enhanced FLV (RTMP ExVideoTagHeader): bit 7 == 1, FourCC in payload[1:5] (e.g. "hvc1" for H.265/HEVC)
		if (payload[0] & 0x80) != 0 {
			pktType := payload[0] & 0x0F
			frameType := (payload[0] >> 4) & 0x07
			fourcc := string(payload[1:5])
			if fourcc != "hvc1" {
				continue
			}
			if pktType == 0 {
				f.parseHEVCConfig(payload[5:])
				continue
			}
			if pktType != 1 && pktType != 3 {
				continue
			}
			body := payload[5:]
			if pktType == 1 {
				if len(body) < 3 {
					continue
				}
				body = body[3:] // skip 24-bit composition time offset
			}
			au, isKey := f.convertLengthPrefixedToAnnexB(body, frameType == 1, true, sc)
			if len(au) == 0 {
				continue
			}
			return au, isKey, nil
		}

		// Standard FLV Video tag: H.264/AVC (codecID 7)
		frameType := payload[0] >> 4
		codecID := payload[0] & 0x0F
		if codecID != 7 {
			continue
		}
		avcPacketType := payload[1]

		if avcPacketType == 0 {
			f.parseAVCConfig(payload[5:])
			continue
		}
		if avcPacketType != 1 {
			continue
		}

		au, isKey := f.convertLengthPrefixedToAnnexB(payload[5:], frameType == 1, false, sc)
		if len(au) == 0 {
			continue
		}
		return au, isKey, nil
	}
}

func (f *flvH264Reader) convertLengthPrefixedToAnnexB(body []byte, isKey, isHEVC bool, sc []byte) ([]byte, bool) {
	f.outBuf.Reset()
	hasParamSets := false

	off := 0
	nLen := f.nalLenSize
	if nLen < 1 || nLen > 4 {
		nLen = 4
	}
	var nals [][]byte
	var inlineParams bytes.Buffer
	for off+nLen <= len(body) {
		nalSize := 0
		for i := 0; i < nLen; i++ {
			nalSize = (nalSize << 8) | int(body[off+i])
		}
		off += nLen
		if nalSize <= 0 || off+nalSize > len(body) {
			break
		}
		nal := body[off : off+nalSize]
		off += nalSize
		if isHEVC {
			nalType := (nal[0] >> 1) & 0x3F
			if nalType == 32 || nalType == 33 || nalType == 34 {
				if nalType == 33 {
					hasParamSets = true
				}
				inlineParams.Write(sc)
				inlineParams.Write(nal)
			}
			if nalType >= 16 && nalType <= 21 {
				isKey = true
			}
		} else {
			nalType := nal[0] & 0x1F
			if nalType == 7 {
				hasParamSets = true
				inlineParams.Write(sc)
				inlineParams.Write(nal)
			} else if nalType == 8 {
				inlineParams.Write(sc)
				inlineParams.Write(nal)
			}
			if nalType == 5 {
				isKey = true
			}
		}
		nals = append(nals, nal)
	}
	if inlineParams.Len() > 0 {
		f.spsPPSAnnex = append([]byte(nil), inlineParams.Bytes()...)
	}
	if len(nals) == 0 {
		return nil, false
	}
	if isKey && !hasParamSets && len(f.spsPPSAnnex) > 0 {
		f.outBuf.Write(f.spsPPSAnnex)
	}
	for _, nal := range nals {
		f.outBuf.Write(sc)
		f.outBuf.Write(nal)
	}
	au := make([]byte, f.outBuf.Len())
	copy(au, f.outBuf.Bytes())
	return au, isKey
}

func (f *flvH264Reader) parseAVCConfig(cfg []byte) {
	if len(cfg) < 7 {
		return
	}
	f.nalLenSize = int(cfg[4]&0x03) + 1
	sc := []byte{0, 0, 0, 1}
	var buf bytes.Buffer

	numSPS := int(cfg[5] & 0x1F)
	off := 6
	for i := 0; i < numSPS && off+2 <= len(cfg); i++ {
		l := int(binary.BigEndian.Uint16(cfg[off : off+2]))
		off += 2
		if l <= 0 || off+l > len(cfg) {
			return
		}
		buf.Write(sc)
		buf.Write(cfg[off : off+l])
		off += l
	}
	if off < len(cfg) {
		numPPS := int(cfg[off])
		off++
		for i := 0; i < numPPS && off+2 <= len(cfg); i++ {
			l := int(binary.BigEndian.Uint16(cfg[off : off+2]))
			off += 2
			if l <= 0 || off+l > len(cfg) {
				break
			}
			buf.Write(sc)
			buf.Write(cfg[off : off+l])
			off += l
		}
	}
	if buf.Len() > 0 {
		f.spsPPSAnnex = append([]byte(nil), buf.Bytes()...)
	}
}

func (f *flvH264Reader) parseHEVCConfig(cfg []byte) {
	// ISO/IEC 14496-15 HEVCDecoderConfigurationRecord:
	// [21] lengthSizeMinusOne (low 2 bits), [22] numOfArrays, followed by VPS/SPS/PPS arrays.
	if len(cfg) < 23 {
		return
	}
	f.nalLenSize = int(cfg[21]&0x03) + 1
	numArrays := int(cfg[22])
	sc := []byte{0, 0, 0, 1}
	var buf bytes.Buffer
	off := 23
	for a := 0; a < numArrays && off+3 <= len(cfg); a++ {
		numNalus := int(binary.BigEndian.Uint16(cfg[off+1 : off+3]))
		off += 3
		for i := 0; i < numNalus && off+2 <= len(cfg); i++ {
			l := int(binary.BigEndian.Uint16(cfg[off : off+2]))
			off += 2
			if l <= 0 || off+l > len(cfg) {
				return
			}
			buf.Write(sc)
			buf.Write(cfg[off : off+l])
			off += l
		}
	}
	if buf.Len() > 0 {
		f.spsPPSAnnex = append([]byte(nil), buf.Bytes()...)
	}
}
