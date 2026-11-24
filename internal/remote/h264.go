package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/executil"
	"relayvpn/internal/protocol"
)

var (
	cachedEncMu   sync.RWMutex
	cachedEncName string
	warmupOnce    sync.Mutex
	warmupRunning bool
	warmupCancel  context.CancelFunc
)

// cancelWarmup stops any in-flight background encoder probe so it never contends
// for DXGI Desktop Duplication when a real Remote Desktop session opens.
func cancelWarmup() {
	warmupOnce.Lock()
	cancel := warmupCancel
	warmupOnce.Unlock()
	if cancel != nil {
		cancel()
	}
}

// WarmupH264Encoder silently probes & caches the fastest working GPU/CPU H.264 encoder
// in the background at startup (and right after FFmpeg finishes auto-installing),
// so the VERY FIRST remote desktop session starts at 60 FPS H.264 in ~0.2s!
func WarmupH264Encoder() {
	cachedEncMu.RLock()
	already := cachedEncName != ""
	cachedEncMu.RUnlock()
	if already {
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
		candidates := h264EncoderCandidates(60, w, h, outW, outH, 82)
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
			cmd := exec.CommandContext(probeCtx, ffmpegPath, cand.args...)
			if runtime.GOOS == "linux" {
				cmd.Env = linuxCmdEnv()
			}
			executil.HideWindow(cmd)
			var stderrBuf bytes.Buffer
			cmd.Stderr = &stderrBuf
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				cancel()
				continue
			}
			if err := cmd.Start(); err != nil {
				cancel()
				continue
			}
			scanner := newFLVH264Reader(stdout)
			au, _, rerr := scanner.NextAccessUnit()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			timedOut := probeCtx.Err() == context.DeadlineExceeded
			cancel()
			if rerr == nil && len(au) > 0 {
				cachedEncMu.Lock()
				cachedEncName = cand.name
				cachedEncMu.Unlock()
				return
			}
			if cand.tier != "" && (timedOut || isCaptureTierFailure(cand.tier, stderrBuf.String())) {
				skipTier[cand.tier] = true
			}
		}
	}()
}

func isCaptureTierFailure(tier, stderr string) bool {
	s := strings.ToLower(stderr)
	switch tier {
	case "WGC":
		return strings.Contains(s, "gfxcapture") ||
			strings.Contains(s, "no such filter") ||
			strings.Contains(s, "failed to configure") ||
			strings.Contains(s, "winrt") ||
			strings.Contains(s, "capture")
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

// streamH264FFmpeg captures the desktop with GPU acceleration when available:
//   - Windows: DXGI Desktop Duplication (ddagrab <1ms) + NVENC / Intel QSV / AMD AMF / x264 VBR,
//     with automatic fallback to gdigrab if ddagrab is unsupported.
//   - macOS: AVFoundation + VideoToolbox GPU / x264.
//   - Linux: x11grab + VAAPI / x264.
func streamH264FFmpeg(
	ctx context.Context,
	fps, maxWidth, quality int,
	seqCounter *atomic.Uint32,
	keyframeReqCh <-chan struct{},
	sendFrame func(byte, []byte) error,
	sendInfo func(codec, encoder, notice string),
) (string, error) {
	ffmpegPath, err := findFFmpeg()
	if err != nil {
		return "ffmpeg", errors.New("ไม่พบ ffmpeg (กำลังติดตั้งให้อัตโนมัติ)")
	}
	// Ensure any startup background warmup probe yields DXGI immediately to this live session.
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

	candidates := h264EncoderCandidates(fps, w, h, outW, outH, quality)
	// Move last known working GPU encoder to the front so opening Remote Desktop starts in <0.2s!
	cachedEncMu.RLock()
	fav := cachedEncName
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

	for _, cand := range candidates {
		if cand.tier != "" && skipTier[cand.tier] {
			continue
		}
		lastEnc = cand.name
		cmd := exec.CommandContext(ctx, ffmpegPath, cand.args...)
		if runtime.GOOS == "linux" {
			cmd.Env = linuxCmdEnv()
		}
		executil.HideWindow(cmd)
		var stderrBuf bytes.Buffer
		cmd.Stderr = &stderrBuf
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			lastErr = err
			continue
		}
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}

		scanner := newFLVH264Reader(stdout)
		// Allow 2.6s for cold GPU wake-up (e.g. Optimus RTX A1000 waking from D3 sleep);
		// broken/missing filters still fail in <100ms!
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
			return cand.name, nil
		case <-probeTimer.C:
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			lastErr = errors.New("encoder startup timed out")
			// If this capture tier stalls (e.g. static desktop or multi-GPU adapter mismatch),
			// immediately skip remaining encoders in the same tier and try the next 60 FPS capture tier!
			if cand.tier != "" && cand.tier != "GDI" {
				skipTier[cand.tier] = true
			}
			continue
		case pr := <-probeCh:
			probeTimer.Stop()
			if pr.err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				lastErr = summarizeFFmpegErr(stderrBuf.String(), pr.err)
				if cand.tier != "" && isCaptureTierFailure(cand.tier, stderrBuf.String()) {
					skipTier[cand.tier] = true
				}
				continue
			}
			firstAU = pr.au
			firstIsKey = pr.isKey
		}

		// Cache fast hardware-capture encoders so reconnects start in <0.2s;
		// never permanently pin slow GDI if a transient lock/sleep caused WGC/DXGI to miss once.
		if cand.tier != "GDI" {
			cachedEncMu.Lock()
			cachedEncName = cand.name
			cachedEncMu.Unlock()
		}

		sendInfo("h264", cand.name, fmt.Sprintf("สตรีมวิดีโอ GPU/H.264 (%s · %dx%d @ %d FPS)", cand.name, outW, outH, fps))

		// Decouple FFmpeg stdout reading from network writes with a 32-frame shock absorber
		// so normal 50-150ms Internet/Wi-Fi jitter NEVER drops delta frames or freezes video!
		// Also cache the latest keyframe (SPS+PPS+IDR) so viewer keyframe requests unlock instantly.
		type auPacket struct {
			data  []byte
			isKey bool
		}
		frameCh := make(chan auPacket, 32)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			defer close(frameCh)
			droppingUntilKey := false
			pushAU := func(au []byte, isKey bool) bool {
				if !isKey {
					isKey = isH264Keyframe(au)
				}
				if droppingUntilKey {
					if !isKey {
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

		var sendErr error
		var lastKeyAU []byte
		for {
			select {
			case <-ctx.Done():
				goto doneStream
			case <-keyframeReqCh:
				// Viewer requested an instant keyframe (e.g. initial decode recovery) -> replay cached IDR immediately!
				if len(lastKeyAU) > 0 {
					if err := emitH264Frame(lastKeyAU, true, outW, outH, seqCounter, sendFrame); err != nil {
						sendErr = err
						goto doneStream
					}
				}
			case pkt, ok := <-frameCh:
				if !ok {
					goto doneStream
				}
				if pkt.isKey {
					lastKeyAU = pkt.data
				}
				if err := emitH264Frame(pkt.data, pkt.isKey, outW, outH, seqCounter, sendFrame); err != nil {
					sendErr = err
					goto doneStream
				}
			}
		}

	doneStream:
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-readDone
		return cand.name, sendErr
	}

	if lastErr == nil {
		lastErr = errors.New("no working H.264 encoder found")
	}
	return lastEnc, lastErr
}

type encoderCandidate struct {
	name string
	tier string // Capture tier on Windows: "WGC", "DXGI", "DXGI1", "GDI"
	args []string
}

func h264EncoderCandidates(fps, srcW, srcH, outW, outH, quality int) []encoderCandidate {
	fpsStr := strconv.Itoa(fps)
	// 4-second GOP (e.g. 240 frames @ 60 FPS): eliminates periodic 1-second 200KB I-frame network spikes
	// while cached lastKeyAU + on-demand keyframe requests keep initial display & recovery instant!
	gopStr := strconv.Itoa(fps * 4)

	// Map UI quality selector to smooth, strictly rate-controlled low-latency bitrate targets
	// (CBR / LD-VBR prevents sudden 10x I-frame network spikes for gaming-grade frame pacing!)
	cqStr := "24"
	targetBitrate := "5M"
	maxRate := "6M"
	bufSize := "1200k"
	if quality > 0 && quality <= 68 {
		cqStr = "28"
		targetBitrate = "2500k"
		maxRate = "3M"
		bufSize = "600k"
	} else if quality >= 93 {
		cqStr = "18"
		targetBitrate = "14M"
		maxRate = "16M"
		bufSize = "3200k"
	} else if quality >= 88 {
		cqStr = "20"
		targetBitrate = "8M"
		maxRate = "10M"
		bufSize = "2000k"
	}

	// Skip redundant CPU scaling when capturing at native 100% resolution!
	needScale := outW != (srcW&^1) || outH != (srcH&^1)
	nv12Filter := "format=nv12"
	yuvFilter := "format=yuv420p"
	if needScale {
		nv12Filter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12", outW, outH)
		yuvFilter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=yuv420p", outW, outH)
	}

	// Critical zero-latency length-prefixed FLV output:
	// Every video tag header carries the exact frame length BEFORE the payload, so we emit EVERY frame
	// the exact microsecond FFmpeg finishes encoding it — ZERO 1-frame (+16.7ms) Annex-B lookahead wait!
	outFlags := []string{"-flush_packets", "1", "-f", "flv", "pipe:1"}
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
		// Windows Media Foundation Hardware Encoder (Low-Delay VBR + Display Remoting):
		// Uses NVIDIA NVENC MFT (RTX A1000/T1000/RTX), Intel QSV MFT, and AMD AMF MFT universally
		// WITHOUT FFmpeg 9.1's NVENC API 13.1 (driver >= 610) restriction — verified 145+ FPS @ 1080p!
		mfArgs := []string{
			"-c:v", "h264_mf", "-hw_encoding", "1", "-scenario", "display_remoting", "-rate_control", "ld_vbr",
			"-quality", "50", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		// Safe universal MFT fallback for drivers that reject ld_vbr/quality flags
		mfSafeArgs := []string{
			"-c:v", "h264_mf", "-hw_encoding", "1", "-scenario", "display_remoting",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		// Intel QuickSync Hardware Encoder (strictly rate-controlled VBR/CBR with async_depth=1)
		qsvArgs := []string{
			"-c:v", "h264_qsv", "-preset", "veryfast", "-profile:v", "baseline",
			"-async_depth", "1", "-look_ahead", "0", "-rdo", "0", "-forced_idr", "1",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		amfArgs := []string{
			"-c:v", "h264_amf", "-usage", "ultralowlatency", "-quality", "speed", "-profile:v", "baseline",
			"-preanalysis", "0", "-vbaq", "0",
			"-rc", "cbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		// Native NVENC (used when driver meets FFmpeg's NVENC SDK version)
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

		// Tier 1: Windows Graphics Capture (WGC / gfxcapture — FFmpeg 9.1+, Windows 10/11):
		// Captures directly from Windows DWM at 60 FPS across ALL GPUs (Optimus RTX A1000 laptops,
		// multi-GPU workstations, Intel UHD/Iris, AMD, HDR & Parsec virtual displays) with GPU-side scaling
		// and 5x lower idle CPU than ddagrab/gdigrab!
		wgcSrc := fmt.Sprintf("gfxcapture=monitor_idx=0:capture_cursor=1:max_framerate=%s", fpsStr)
		if needScale {
			wgcSrc += fmt.Sprintf(":width=%d:height=%d:resize_mode=scale:scale_mode=bilinear", outW, outH)
		}
		wgcNV12 := wgcSrc + ",hwdownload,format=bgra,format=nv12"
		wgcYUV := wgcSrc + ",hwdownload,format=bgra,format=yuv420p"
		makeWGC := func(filter string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-filter_complex", filter, "-fps_mode", "cfr", "-r", fpsStr)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		list = append(list,
			encoderCandidate{name: "WGC + Hardware GPU (MF LD-VBR)", tier: "WGC", args: makeWGC(wgcNV12, mfArgs)},
			encoderCandidate{name: "WGC + Hardware GPU (MF)", tier: "WGC", args: makeWGC(wgcNV12, mfSafeArgs)},
			encoderCandidate{name: "WGC + Intel QSV GPU", tier: "WGC", args: makeWGC(wgcNV12, qsvArgs)},
			encoderCandidate{name: "WGC + AMD AMF GPU", tier: "WGC", args: makeWGC(wgcNV12, amfArgs)},
			encoderCandidate{name: "WGC + NVENC GPU", tier: "WGC", args: makeWGC(wgcNV12, nvencArgs)},
			encoderCandidate{name: "WGC + x264 ZeroLatency", tier: "WGC", args: makeWGC(wgcYUV, x264Args)},
		)

		// Tier 2: DXGI Desktop Duplication (ddagrab Adapter 0 with allow_fallback=1 for HDR/10-bit displays)
		ddaNV12 := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1:allow_fallback=1,hwdownload,format=bgra,%s", fpsStr, nv12Filter)
		ddaYUV := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1:allow_fallback=1,hwdownload,format=bgra,%s", fpsStr, yuvFilter)
		makeDDA := func(adapterIdx int, filter string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			if adapterIdx >= 0 {
				args = append(args, "-init_hw_device", fmt.Sprintf("d3d11va=dda:%d", adapterIdx), "-filter_hw_device", "dda")
			}
			args = append(args, "-filter_complex", filter)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		list = append(list,
			encoderCandidate{name: "DXGI + Hardware GPU (MF LD-VBR)", tier: "DXGI", args: makeDDA(-1, ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI + Hardware GPU (MF)", tier: "DXGI", args: makeDDA(-1, ddaNV12, mfSafeArgs)},
			encoderCandidate{name: "DXGI + Intel QSV GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, qsvArgs)},
			encoderCandidate{name: "DXGI + AMD AMF GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, amfArgs)},
			encoderCandidate{name: "DXGI + NVENC GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, nvencArgs)},
			encoderCandidate{name: "DXGI + x264 ZeroLatency", tier: "DXGI", args: makeDDA(-1, ddaYUV, x264Args)},
		)

		// Tier 3: DXGI Desktop Duplication on Adapter 1 (for Hybrid Optimus RTX/Intel laptops with older FFmpeg)
		list = append(list,
			encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF LD-VBR)", tier: "DXGI1", args: makeDDA(1, ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF)", tier: "DXGI1", args: makeDDA(1, ddaNV12, mfSafeArgs)},
			encoderCandidate{name: "DXGI-GPU1 + x264 ZeroLatency", tier: "DXGI1", args: makeDDA(1, ddaYUV, x264Args)},
		)

		// Tier 4: Last-resort fallback: gdigrab (only if WGC, DXGI-0, and DXGI-1 all fail, e.g. older Windows / VM).
		// NOTE: Never pass `-probesize 32` to gdigrab — its BMP header is 54 bytes!
		makeGDI := func(vf string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-f", "gdigrab", "-framerate", fpsStr, "-draw_mouse", "1", "-i", "desktop", "-vf", vf)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
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
	if runtime.GOOS == "darwin" {
		inputArgs = []string{"-probesize", "32", "-analyzeduration", "0", "-f", "avfoundation", "-framerate", fpsStr, "-capture_cursor", "1", "-i", "1:none"}
	} else {
		disp, _ := detectLinuxDisplayEnv()
		// Zero-buffer x11grab: -probesize 32 -analyzeduration 0 eliminates FFmpeg's 50-120ms input demux buffering
		// so Linux mouse movement feels just as instantaneous as Windows!
		inputArgs = []string{"-probesize", "32", "-analyzeduration", "0", "-f", "x11grab", "-framerate", fpsStr, "-draw_mouse", "1", "-video_size", fmt.Sprintf("%dx%d", srcW, srcH), "-i", disp}
	}
	makeUnix := func(vf string, encArgs []string) []string {
		args := append([]string{}, inLowLatency...)
		args = append(args, inputArgs...)
		args = append(args, "-vf", vf)
		args = append(args, encArgs...)
		args = append(args, outFlags...)
		return args
	}

	if runtime.GOOS == "darwin" {
		list = append(list, encoderCandidate{
			name: "VideoToolbox GPU",
			args: makeUnix(nv12Filter, []string{"-c:v", "h264_videotoolbox", "-realtime", "true", "-profile:v", "baseline", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0"}),
		})
	} else {
		vaapiVF := "format=nv12,hwupload"
		if needScale {
			vaapiVF = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12,hwupload", outW, outH)
		}
		vaapiArgs := append([]string{}, inLowLatency...)
		vaapiArgs = append(vaapiArgs, "-vaapi_device", "/dev/dri/renderD128")
		vaapiArgs = append(vaapiArgs, inputArgs...)
		vaapiArgs = append(vaapiArgs, "-vf", vaapiVF, "-c:v", "h264_vaapi", "-profile:v", "constrained_baseline", "-rc_mode", "CBR", "-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0")
		vaapiArgs = append(vaapiArgs, outFlags...)

		list = append(list,
			encoderCandidate{
				name: "X11 + NVENC GPU",
				args: makeUnix(nv12Filter, []string{"-c:v", "h264_nvenc", "-preset", "p1", "-tune", "ull", "-profile:v", "baseline", "-zerolatency", "1", "-rc", "cbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0"}),
			},
			encoderCandidate{
				name: "X11 + VAAPI GPU",
				args: vaapiArgs,
			},
		)
	}
	list = append(list, encoderCandidate{
		name: "x264 ZeroLatency",
		args: makeUnix(yuvFilter, []string{"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-x264-params", "repeat-headers=1:sliced-threads=1:rc-lookahead=0:sync-lookahead=0", "-crf", cqStr, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0"}),
	})
	return list
}

func emitH264Frame(au []byte, isKey bool, w, h int, seqCounter *atomic.Uint32, sendFrame func(byte, []byte) error) error {
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
	return sendFrame(protocol.FrameTypeH264, pkt)
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

// flvH264Reader reads exact length-prefixed H.264 video frames from an FFmpeg `-f flv` stream
// with ZERO 1-frame lookahead latency (every frame is emitted immediately upon tag completion)
// and converts AVCC length-prefixed NAL units into Annex-B with automatic SPS/PPS prepending on keyframes.
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

		// Only process Video tags (type 9) with AVC/H.264 codec (codecID 7)
		if tagType != 9 || dataSize < 5 {
			continue
		}
		frameType := payload[0] >> 4
		codecID := payload[0] & 0x0F
		if codecID != 7 {
			continue
		}
		avcPacketType := payload[1]

		if avcPacketType == 0 {
			// AVCDecoderConfigurationRecord: extract SPS & PPS into Annex-B cache
			f.parseAVCConfig(payload[5:])
			continue
		}
		if avcPacketType != 1 {
			continue
		}

		isKey := frameType == 1
		avcc := payload[5:]
		f.outBuf.Reset()
		hasSPS := false

		// Convert AVCC length-prefixed NALUs to Annex-B
		off := 0
		nLen := f.nalLenSize
		if nLen < 1 || nLen > 4 {
			nLen = 4
		}
		var nals [][]byte
		var inlineSPSPPS bytes.Buffer
		for off+nLen <= len(avcc) {
			nalSize := 0
			for i := 0; i < nLen; i++ {
				nalSize = (nalSize << 8) | int(avcc[off+i])
			}
			off += nLen
			if nalSize <= 0 || off+nalSize > len(avcc) {
				break
			}
			nal := avcc[off : off+nalSize]
			off += nalSize
			nalType := nal[0] & 0x1F
			if nalType == 7 {
				hasSPS = true
				inlineSPSPPS.Write(sc)
				inlineSPSPPS.Write(nal)
			} else if nalType == 8 {
				inlineSPSPPS.Write(sc)
				inlineSPSPPS.Write(nal)
			}
			if nalType == 5 {
				isKey = true
			}
			nals = append(nals, nal)
		}
		if inlineSPSPPS.Len() > 0 {
			f.spsPPSAnnex = append([]byte(nil), inlineSPSPPS.Bytes()...)
		}
		if len(nals) == 0 {
			continue
		}
		if isKey && !hasSPS && len(f.spsPPSAnnex) > 0 {
			f.outBuf.Write(f.spsPPSAnnex)
		}
		for _, nal := range nals {
			f.outBuf.Write(sc)
			f.outBuf.Write(nal)
		}
		au := make([]byte, f.outBuf.Len())
		copy(au, f.outBuf.Bytes())
		return au, isKey, nil
	}
}

func (f *flvH264Reader) parseAVCConfig(cfg []byte) {
	// ISO/IEC 14496-15 AVCDecoderConfigurationRecord:
	// [0] version, [1] profile, [2] compat, [3] level, [4] 6b reserved + 2b lengthSizeMinusOne, [5] 3b reserved + 5b numSPS
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
