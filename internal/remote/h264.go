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
	cachedEncMu      sync.RWMutex
	cachedEncByCodec = map[string]string{}
	warmupOnce       sync.Mutex
	warmupRunning    bool
	warmupCancel     context.CancelFunc
)

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
			candidates := videoEncoderCandidates(codec, 60, w, h, outW, outH, 82)
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
					cachedEncByCodec[codec] = cand.name
					cachedEncMu.Unlock()
					break
				}
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
	return streamVideoFFmpeg(ctx, "h264", fps, maxWidth, quality, seqCounter, keyframeReqCh, sendFrame, sendInfo)
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

	candidates := videoEncoderCandidates(codec, fps, w, h, outW, outH, quality)
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
			return cand.name, nil
		case <-probeTimer.C:
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			lastErr = errors.New("encoder startup timed out")
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
			cachedEncByCodec[codec] = cand.name
			cachedEncMu.Unlock()
		}

		codecTitle := "H.264"
		if codec == "hevc" {
			codecTitle = "H.265/HEVC"
		}
		sendInfo(codec, cand.name, fmt.Sprintf("สตรีมวิดีโอ GPU %s (%s · %dx%d @ %d FPS)", codecTitle, cand.name, outW, outH, fps))

		// Tight 12-frame shock absorber (200ms max) eliminates bufferbloat while absorbing brief Wi-Fi/WAN jitter.
		type auPacket struct {
			data  []byte
			isKey bool
		}
		frameCh := make(chan auPacket, 12)
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
				if len(lastKeyAU) > 0 {
					if err := emitVideoFrame(frameType, lastKeyAU, true, outW, outH, seqCounter, sendFrame); err != nil {
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
				if err := emitVideoFrame(frameType, pkt.data, pkt.isKey, outW, outH, seqCounter, sendFrame); err != nil {
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
		lastErr = fmt.Errorf("no working %s encoder found", strings.ToUpper(codec))
	}
	return lastEnc, lastErr
}

type encoderCandidate struct {
	name string
	tier string // Capture tier on Windows: "WGC", "DXGI", "DXGI1", "GDI"
	args []string
}

func h264EncoderCandidates(fps, srcW, srcH, outW, outH, quality int) []encoderCandidate {
	return videoEncoderCandidates("h264", fps, srcW, srcH, outW, outH, quality)
}

func videoEncoderCandidates(codec string, fps, srcW, srcH, outW, outH, quality int) []encoderCandidate {
	fpsStr := strconv.Itoa(fps)
	// 2-second GOP (e.g. 120 frames @ 60 FPS): balances low bandwidth with rapid packet-loss recovery!
	gopStr := strconv.Itoa(fps * 2)

	// Map UI quality selector to crisp, generous VBV bitrate targets.
	// NOTE: H.265 (HEVC) achieves equal/superior sharpness at ~60% of H.264's bitrate!
	// And for x264, bufsize MUST be >= 4M-12M so 1080p keyframes NEVER crush into macroblock mosaic!
	cqStr := "20"
	targetBitrate := "5M"
	maxRate := "7M"
	bufSize := "7M"
	hevcBitrate := "3500k"
	hevcMaxRate := "5M"
	if quality > 0 && quality <= 68 {
		cqStr = "25"
		targetBitrate = "2500k"
		maxRate = "3500k"
		bufSize = "4M"
		hevcBitrate = "1800k"
		hevcMaxRate = "2600k"
	} else if quality >= 93 {
		cqStr = "16"
		targetBitrate = "14M"
		maxRate = "18M"
		bufSize = "16M"
		hevcBitrate = "9M"
		hevcMaxRate = "12M"
	} else if quality >= 88 {
		cqStr = "18"
		targetBitrate = "8M"
		maxRate = "11M"
		bufSize = "10M"
		hevcBitrate = "5500k"
		hevcMaxRate = "7500k"
	}

	needScale := outW != (srcW&^1) || outH != (srcH&^1)
	nv12Filter := "format=nv12"
	yuvFilter := "format=yuv420p"
	if needScale {
		nv12Filter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12", outW, outH)
		yuvFilter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=yuv420p", outW, outH)
	}

	// Zero-latency length-prefixed FLV / Enhanced-FLV output (supports both H.264 AVC & H.265 HEVC!)
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
		wgcSrc := fmt.Sprintf("gfxcapture=monitor_idx=0:capture_cursor=1:max_framerate=%s", fpsStr)
		if needScale {
			wgcSrc += fmt.Sprintf(":width=%d:height=%d:resize_mode=scale:scale_mode=bilinear", outW, outH)
		}
		wgcLavfi := wgcSrc + ",hwdownload,format=bgra"
		wgcNV12 := wgcSrc + ",hwdownload,format=bgra,format=nv12"
		wgcYUV := wgcSrc + ",hwdownload,format=bgra,format=yuv420p"

		ddaLavfi := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1:allow_fallback=1,hwdownload,format=bgra", fpsStr)
		ddaNV12 := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1:allow_fallback=1,hwdownload,format=bgra,%s", fpsStr, nv12Filter)
		ddaYUV := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1:allow_fallback=1,hwdownload,format=bgra,%s", fpsStr, yuvFilter)

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
		makeGDI := func(vf string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-f", "gdigrab", "-framerate", fpsStr, "-draw_mouse", "1", "-i", "desktop", "-vf", vf)
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
				"-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcAMFArgs := []string{
				"-c:v", "hevc_amf", "-usage", "ultralowlatency", "-quality", "speed",
				"-preanalysis", "0", "-vbaq", "0",
				"-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcQSVArgs := []string{
				"-c:v", "hevc_qsv", "-preset", "veryfast", "-async_depth", "1", "-look_ahead", "0",
				"-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcMFArgs := []string{
				"-c:v", "hevc_mf", "-hw_encoding", "1", "-scenario", "display_remoting", "-rate_control", "ld_vbr",
				"-quality", "65", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}
			hevcMFSafeArgs := []string{
				"-c:v", "hevc_mf", "-hw_encoding", "1", "-scenario", "display_remoting",
				"-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0",
			}

			// Hardware H.265 GPU candidates ONLY (if none supported, ServeScreenSession cleanly falls back to 60 FPS H.264!)
			list = append(list,
				encoderCandidate{name: "WGC + H.265 D3D12 GPU", tier: "WGC", args: makeWGCD12(hevcD12Args)},
				encoderCandidate{name: "WGC + H.265 NVENC GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcNVENCArgs)},
				encoderCandidate{name: "WGC + H.265 AMD AMF GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcAMFArgs)},
				encoderCandidate{name: "WGC + H.265 Intel QSV GPU", tier: "WGC", args: makeWGC(wgcNV12, hevcQSVArgs)},
				encoderCandidate{name: "WGC + H.265 Hardware GPU (MF)", tier: "WGC", args: makeWGC(wgcNV12, hevcMFArgs)},
				encoderCandidate{name: "WGC + H.265 Hardware GPU (MF Safe)", tier: "WGC", args: makeWGC(wgcNV12, hevcMFSafeArgs)},
				encoderCandidate{name: "DXGI + H.265 D3D12 GPU", tier: "DXGI", args: makeDDAD12(hevcD12Args)},
				encoderCandidate{name: "DXGI + H.265 Hardware GPU (MF)", tier: "DXGI", args: makeDDA(-1, ddaNV12, hevcMFArgs)},
				encoderCandidate{name: "DXGI + H.265 Intel QSV GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, hevcQSVArgs)},
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
			"-c:v", "h264_amf", "-usage", "ultralowlatency", "-quality", "speed", "-profile:v", "baseline",
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

		// Tier 1: WGC (gfxcapture) + Zero-Delay Hardware GPU (D3D12VA 342 FPS / NVENC / AMF / QSV) -> crisp x264 -> MF
		list = append(list,
			encoderCandidate{name: "WGC + H.264 D3D12 GPU", tier: "WGC", args: makeWGCD12(h264D12Args)},
			encoderCandidate{name: "WGC + NVENC GPU", tier: "WGC", args: makeWGC(wgcNV12, nvencArgs)},
			encoderCandidate{name: "WGC + AMD AMF GPU", tier: "WGC", args: makeWGC(wgcNV12, amfArgs)},
			encoderCandidate{name: "WGC + Intel QSV GPU", tier: "WGC", args: makeWGC(wgcNV12, qsvArgs)},
			encoderCandidate{name: "WGC + x264 ZeroLatency", tier: "WGC", args: makeWGC(wgcYUV, x264Args)},
			encoderCandidate{name: "WGC + Hardware GPU (MF LD-VBR)", tier: "WGC", args: makeWGC(wgcNV12, mfArgs)},
			encoderCandidate{name: "WGC + Hardware GPU (MF)", tier: "WGC", args: makeWGC(wgcNV12, mfSafeArgs)},
		)

		// Tier 2: DXGI Desktop Duplication (ddagrab Adapter 0 with allow_fallback=1)
		list = append(list,
			encoderCandidate{name: "DXGI + H.264 D3D12 GPU", tier: "DXGI", args: makeDDAD12(h264D12Args)},
			encoderCandidate{name: "DXGI + Hardware GPU (MF LD-VBR)", tier: "DXGI", args: makeDDA(-1, ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI + Hardware GPU (MF)", tier: "DXGI", args: makeDDA(-1, ddaNV12, mfSafeArgs)},
			encoderCandidate{name: "DXGI + Intel QSV GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, qsvArgs)},
			encoderCandidate{name: "DXGI + AMD AMF GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, amfArgs)},
			encoderCandidate{name: "DXGI + NVENC GPU", tier: "DXGI", args: makeDDA(-1, ddaNV12, nvencArgs)},
			encoderCandidate{name: "DXGI + x264 ZeroLatency", tier: "DXGI", args: makeDDA(-1, ddaYUV, x264Args)},
		)

		// Tier 3: DXGI Adapter 1 (Hybrid Optimus laptops with older FFmpeg lacking gfxcapture)
		list = append(list,
			encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF LD-VBR)", tier: "DXGI1", args: makeDDA(1, ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI-GPU1 + Hardware GPU (MF)", tier: "DXGI1", args: makeDDA(1, ddaNV12, mfSafeArgs)},
			encoderCandidate{name: "DXGI-GPU1 + x264 ZeroLatency", tier: "DXGI1", args: makeDDA(1, ddaYUV, x264Args)},
		)

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
	if runtime.GOOS == "darwin" {
		inputArgs = []string{"-probesize", "32", "-analyzeduration", "0", "-f", "avfoundation", "-framerate", fpsStr, "-capture_cursor", "1", "-i", "1:none"}
	} else {
		disp, _ := detectLinuxDisplayEnv()
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

	if codec == "hevc" {
		if runtime.GOOS == "darwin" {
			list = append(list, encoderCandidate{
				name: "VideoToolbox H.265 GPU",
				args: makeUnix(nv12Filter, []string{"-c:v", "hevc_videotoolbox", "-realtime", "true", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0"}),
			})
		} else {
			vaapiVF := "format=nv12,hwupload"
			if needScale {
				vaapiVF = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12,hwupload", outW, outH)
			}
			vaapiArgs := append([]string{}, inLowLatency...)
			vaapiArgs = append(vaapiArgs, "-vaapi_device", "/dev/dri/renderD128")
			vaapiArgs = append(vaapiArgs, inputArgs...)
			vaapiArgs = append(vaapiArgs, "-vf", vaapiVF, "-c:v", "hevc_vaapi", "-rc_mode", "VBR", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-g", gopStr, "-bf", "0")
			vaapiArgs = append(vaapiArgs, outFlags...)
			list = append(list,
				encoderCandidate{
					name: "X11 + H.265 NVENC GPU",
					args: makeUnix(nv12Filter, []string{"-c:v", "hevc_nvenc", "-preset", "p1", "-tune", "ull", "-zerolatency", "1", "-rc", "cbr", "-b:v", hevcBitrate, "-maxrate", hevcMaxRate, "-bufsize", hevcMaxRate, "-g", gopStr, "-bf", "0"}),
				},
				encoderCandidate{
					name: "X11 + H.265 VAAPI GPU",
					args: vaapiArgs,
				},
			)
		}
		return list
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
