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
)

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

	for _, cand := range candidates {
		lastEnc = cand.name
		cmd := exec.CommandContext(ctx, ffmpegPath, cand.args...)
		executil.HideWindow(cmd)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			lastErr = err
			continue
		}
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}

		scanner := newAnnexBScanner(stdout)
		// Guard first-frame probe with a 3-second timeout so an unsupported GPU encoder never hangs.
		type probeRes struct {
			au  []byte
			err error
		}
		probeCh := make(chan probeRes, 1)
		go func() {
			au, err := scanner.NextAccessUnit()
			probeCh <- probeRes{au: au, err: err}
		}()

		var firstAU []byte
		probeTimer := time.NewTimer(3 * time.Second)
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
			continue
		case pr := <-probeCh:
			probeTimer.Stop()
			if pr.err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				lastErr = pr.err
				continue
			}
			firstAU = pr.au
		}

		cachedEncMu.Lock()
		cachedEncName = cand.name
		cachedEncMu.Unlock()

		sendInfo("h264", cand.name, fmt.Sprintf("สตรีมวิดีโอ GPU/H.264 (%s · %dx%d @ %d FPS)", cand.name, outW, outH, fps))

		// Decouple FFmpeg stdout reading from network writes with a tight 3-frame low-latency buffer (<50ms max).
		// Also cache the latest keyframe (SPS+PPS+IDR) so viewer keyframe requests unlock instantly (zero black screen!).
		type auPacket struct {
			data  []byte
			isKey bool
		}
		frameCh := make(chan auPacket, 3)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			defer close(frameCh)
			droppingUntilKey := false
			pushAU := func(au []byte) bool {
				isKey := isH264Keyframe(au)
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

			if !pushAU(firstAU) {
				return
			}
			for ctx.Err() == nil {
				au, err := scanner.NextAccessUnit()
				if err != nil {
					return
				}
				if !pushAU(au) {
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
	args []string
}

func h264EncoderCandidates(fps, srcW, srcH, outW, outH, quality int) []encoderCandidate {
	fpsStr := strconv.Itoa(fps)
	gopStr := strconv.Itoa(fps * 2) // keyframe every 2 seconds for snappy recovery & steady bitrate

	// Map UI quality selector to strictly rate-controlled low-latency VBR targets
	// (prevents 18+ Mbps CQP spikes that saturate Cloudflare Tunnel TCP and cause 25 FPS + mouse lag!).
	cqStr := "24"
	targetBitrate := "3500k"
	maxRate := "5M"
	bufSize := "1000k"
	if quality > 0 && quality <= 68 {
		cqStr = "28"
		targetBitrate = "2M"
		maxRate = "3M"
		bufSize = "600k"
	} else if quality >= 88 {
		cqStr = "20"
		targetBitrate = "8M"
		maxRate = "11M"
		bufSize = "2200k"
	}

	// Skip redundant CPU scaling when capturing at native 100% resolution!
	needScale := outW != (srcW&^1) || outH != (srcH&^1)
	nv12Filter := "format=nv12"
	yuvFilter := "format=yuv420p"
	if needScale {
		nv12Filter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=nv12", outW, outH)
		yuvFilter = fmt.Sprintf("scale=%d:%d:flags=fast_bilinear,format=yuv420p", outW, outH)
	}

	// Critical low-latency output flags: -flush_packets 1 disables FFmpeg's 32KB pipe buffering
	outFlags := []string{"-flush_packets", "1", "-f", "h264", "pipe:1"}
	inLowLatency := []string{"-loglevel", "error", "-fflags", "+nobuffer+flush_packets", "-flags", "+low_delay"}

	var list []encoderCandidate

	if runtime.GOOS == "windows" {
		// 1) Preferred: Windows DXGI Desktop Duplication (ddagrab — GPU VRAM <1ms capture!)
		ddaNV12 := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1,hwdownload,format=bgra,%s", fpsStr, nv12Filter)
		ddaYUV := fmt.Sprintf("ddagrab=framerate=%s:draw_mouse=1,hwdownload,format=bgra,%s", fpsStr, yuvFilter)
		makeDDA := func(filter string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-filter_complex", filter)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}

		// Native NVENC (requires recent NVIDIA driver matching FFmpeg SDK)
		nvencArgs := []string{
			"-c:v", "h264_nvenc", "-preset", "p1", "-tune", "ull", "-profile:v", "baseline",
			"-zerolatency", "1", "-rc-lookahead", "0", "-delay", "0", "-forced-idr", "1",
			"-rc", "vbr", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		// Windows Media Foundation Hardware Encoder (works on NVIDIA/Intel/AMD regardless of NVENC SDK version!
		// Uses Microsoft's official Display Remoting low-delay VBR scenario at 150-350+ FPS!)
		mfArgs := []string{
			"-c:v", "h264_mf", "-hw_encoding", "1", "-scenario", "display_remoting", "-rate_control", "ld_vbr",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-g", gopStr, "-bf", "0",
		}
		// Intel QuickSync Hardware Encoder (strictly rate-controlled VBR with -b:v, NEVER uncapped CQP global_quality!)
		qsvArgs := []string{
			"-c:v", "h264_qsv", "-preset", "veryfast", "-profile:v", "baseline",
			"-async_depth", "1", "-look_ahead", "0", "-rdo", "0", "-forced_idr", "1",
			"-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		amfArgs := []string{
			"-c:v", "h264_amf", "-usage", "ultralowlatency", "-quality", "speed", "-profile:v", "baseline",
			"-preanalysis", "0", "-vbaq", "0",
			"-rc", "vbr_latency", "-b:v", targetBitrate, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}
		x264Args := []string{
			"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline",
			"-x264-params", "repeat-headers=1:annexb=1:sliced-threads=1:rc-lookahead=0:sync-lookahead=0",
			"-crf", cqStr, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0",
		}

		list = append(list,
			encoderCandidate{name: "DXGI + NVENC GPU", args: makeDDA(ddaNV12, nvencArgs)},
			encoderCandidate{name: "DXGI + Hardware GPU (MF Remoting)", args: makeDDA(ddaNV12, mfArgs)},
			encoderCandidate{name: "DXGI + Intel QSV GPU", args: makeDDA(ddaNV12, qsvArgs)},
			encoderCandidate{name: "DXGI + AMD AMF GPU", args: makeDDA(ddaNV12, amfArgs)},
			encoderCandidate{name: "DXGI + x264 ZeroLatency", args: makeDDA(ddaYUV, x264Args)},
		)

		// 2) Fallback: gdigrab if ddagrab is unavailable (e.g. older Windows / hybrid GPU restriction)
		makeGDI := func(vf string, encArgs []string) []string {
			args := append([]string{}, inLowLatency...)
			args = append(args, "-f", "gdigrab", "-framerate", fpsStr, "-draw_mouse", "1", "-i", "desktop", "-vf", vf)
			args = append(args, encArgs...)
			args = append(args, outFlags...)
			return args
		}
		list = append(list,
			encoderCandidate{name: "GDI + NVENC GPU", args: makeGDI(nv12Filter, nvencArgs)},
			encoderCandidate{name: "GDI + Hardware GPU (MF Remoting)", args: makeGDI(nv12Filter, mfArgs)},
			encoderCandidate{name: "GDI + Intel QSV GPU", args: makeGDI(nv12Filter, qsvArgs)},
			encoderCandidate{name: "GDI + AMD AMF GPU", args: makeGDI(nv12Filter, amfArgs)},
			encoderCandidate{name: "GDI + x264 ZeroLatency", args: makeGDI(yuvFilter, x264Args)},
		)
		return list
	}

	var inputArgs []string
	if runtime.GOOS == "darwin" {
		inputArgs = []string{"-f", "avfoundation", "-framerate", fpsStr, "-capture_cursor", "1", "-i", "1:none"}
	} else {
		inputArgs = []string{"-f", "x11grab", "-framerate", fpsStr, "-i", ":0.0"}
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
	}
	list = append(list, encoderCandidate{
		name: "x264 ZeroLatency",
		args: makeUnix(yuvFilter, []string{"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-x264-params", "repeat-headers=1:annexb=1:sliced-threads=1:rc-lookahead=0:sync-lookahead=0", "-crf", cqStr, "-maxrate", maxRate, "-bufsize", bufSize, "-g", gopStr, "-bf", "0"}),
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

// annexBScanner splits an Annex-B H.264 byte stream into clean access units (grouping SPS/PPS + IDR)
// without ever dropping start codes.
type annexBScanner struct {
	r   io.Reader
	buf []byte
	tmp []byte
}

func newAnnexBScanner(r io.Reader) *annexBScanner {
	return &annexBScanner{
		r:   r,
		tmp: make([]byte, 64*1024),
	}
}

// findStartCode finds the earliest 3-byte (00 00 01) or 4-byte (00 00 00 01) Annex-B start code.
// Returns (index, startCodeLength) or (-1, 0) if not found.
func findStartCode(b []byte) (int, int) {
	for i := 0; i+2 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 {
			if b[i+2] == 1 {
				return i, 3
			}
			if b[i+2] == 0 && i+3 < len(b) && b[i+3] == 1 {
				return i, 4
			}
		}
	}
	return -1, 0
}

func (s *annexBScanner) nextNAL() ([]byte, error) {
	for {
		idx, scLen := findStartCode(s.buf)
		if idx >= 0 {
			if idx > 0 {
				s.buf = s.buf[idx:]
			}
			nextIdx, _ := findStartCode(s.buf[scLen:])
			if nextIdx >= 0 {
				nal := append([]byte(nil), s.buf[scLen:scLen+nextIdx]...)
				s.buf = s.buf[scLen+nextIdx:]
				return nal, nil
			}
		}
		n, err := s.r.Read(s.tmp)
		if n > 0 {
			s.buf = append(s.buf, s.tmp[:n]...)
		}
		if err != nil {
			if idx, scLen := findStartCode(s.buf); idx == 0 && len(s.buf) > scLen {
				nal := append([]byte(nil), s.buf[scLen:]...)
				s.buf = nil
				return nal, nil
			}
			return nil, err
		}
		if len(s.buf) > 8*1024*1024 {
			return nil, io.ErrShortBuffer
		}
	}
}

func (s *annexBScanner) NextAccessUnit() ([]byte, error) {
	sc := []byte{0, 0, 0, 1}
	var out bytes.Buffer
	for {
		nal, err := s.nextNAL()
		if err != nil {
			if out.Len() > 0 {
				return out.Bytes(), nil
			}
			return nil, err
		}
		if len(nal) == 0 {
			continue
		}
		out.Write(sc)
		out.Write(nal)
		nalType := nal[0] & 0x1F
		if nalType == 1 || nalType == 5 {
			return out.Bytes(), nil
		}
	}
}
