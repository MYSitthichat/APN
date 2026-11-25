package remote

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/protocol"
)

const (
	tileSize        = 128
	tileCodecJPEG   = byte(0)
	tileCodecPNG    = byte(1)
	maxInFlightACKs = 3

	// videoHealthyRun is how long a video stream must run before its end counts as transient.
	videoHealthyRun = 4 * time.Second
	// maxVideoShortRuns is how many short-lived video runs in a row are retried before falling back.
	maxVideoShortRuns = 2
)

// ScreenCapturer captures desktop frames, reusing OS handles & memory buffers when supported.
type ScreenCapturer interface {
	Capture() (*image.RGBA, error)
	Close()
}

// heldInput remembers which keys and mouse buttons the viewer currently holds down.
// It is used by a single reader goroutine, so it needs no locking.
type heldInput struct {
	keys    map[string]InputEvent
	buttons map[string]InputEvent
}

func newHeldInput() *heldInput {
	return &heldInput{keys: map[string]InputEvent{}, buttons: map[string]InputEvent{}}
}

func (h *heldInput) track(ev InputEvent) {
	keyID := ev.Code
	if keyID == "" {
		keyID = ev.Key
	}
	switch ev.Type {
	case "key_down":
		if keyID != "" {
			h.keys[keyID] = ev
		}
	case "key_up":
		delete(h.keys, keyID)
	case "mouse_down":
		h.buttons[ev.Button] = ev
	case "mouse_up":
		delete(h.buttons, ev.Button)
	}
}

// releaseAll returns key_up / mouse_up events for everything still held and forgets them.
func (h *heldInput) releaseAll() []InputEvent {
	out := make([]InputEvent, 0, len(h.keys)+len(h.buttons))
	for _, ev := range h.keys {
		ev.Type = "key_up"
		ev.Text = ""
		out = append(out, ev)
	}
	for _, ev := range h.buttons {
		ev.Type = "mouse_up"
		out = append(out, ev)
	}
	h.keys = map[string]InputEvent{}
	h.buttons = map[string]InputEvent{}
	return out
}

// InputEvent represents mouse, keyboard, ACK pacing, or stream quality control sent from the viewer.
type InputEvent struct {
	Type     string  `json:"type"`                // mouse_move, mouse_down, mouse_up, mouse_wheel, key_down, key_up, key_text, config, ack, keyframe
	X        float64 `json:"x,omitempty"`         // normalized 0.0..1.0
	Y        float64 `json:"y,omitempty"`         // normalized 0.0..1.0
	Button   string  `json:"button,omitempty"`    // left, right, middle
	DeltaY   int     `json:"delta_y,omitempty"`   // scroll delta
	Key      string  `json:"key,omitempty"`       // KeyboardEvent.key
	Code     string  `json:"code,omitempty"`      // KeyboardEvent.code
	Text     string  `json:"text,omitempty"`      // Unicode text for direct typing
	Ctrl     bool    `json:"ctrl,omitempty"`
	Alt      bool    `json:"alt,omitempty"`
	Shift    bool    `json:"shift,omitempty"`
	FPS      int     `json:"fps,omitempty"`       // for Type == "config"
	Quality  int     `json:"quality,omitempty"`   // for Type == "config"
	Codec    string  `json:"codec,omitempty"`     // "tiles", "png", "h264"
	MaxWidth int     `json:"max_width,omitempty"` // 0 = Native 100%, or 1920/1280
	Seq      uint32  `json:"seq,omitempty"`       // for Type == "ack"
	T        float64 `json:"t,omitempty"`         // for Type == "ping": viewer timestamp echoed back as {"pong":t}
	// LocalCursor (Type == "config") switches between a locally drawn cursor and one in the video.
	LocalCursor *bool `json:"local_cursor,omitempty"`
}

// StreamOptions configures a live remote screen session.
type StreamOptions struct {
	InitialFPS      int
	InitialQuality  int
	InitialCodec    string // "tiles" (default), "png", "h264"
	InitialMaxWidth int    // 0 = Native 100%
	AllowInput      bool
	LocalCursor     bool // viewer draws the cursor; leave it out of the video where the host can report its shape
	BytesSent       *atomic.Int64
	BytesRecv       *atomic.Int64
}

type streamRuntimeState struct {
	mu                 sync.Mutex
	localCursor        bool
	encoder            string
	hevcSteppedDown    bool // H.265 failed on this host and the session fell back to H.264
	fps                int
	quality            int
	codec              string
	maxWidth           int
	forceKeyframe      bool
	pendingH264Upgrade bool
	h264AutoRetries    int
	fallbackNotice     string

	ackedSeq      atomic.Uint32
	ackNotify     chan struct{}
	modeCh        chan struct{}
	keyframeReqCh chan struct{}
}

// ServeScreenSession streams desktop video using either:
//  1) Parallel Dirty-Tile Differential Engine (Native 100% Sharpness, JPEG Q82 / Lossless PNG, ACK-paced)
//  2) Hardware H.264 Video Stream (DXGI/NVENC/QSV/x264 via ffmpeg + WebCodecs VideoDecoder) with auto-fallback
func ServeScreenSession(stream io.ReadWriteCloser, opts StreamOptions) error {
	fps := clamp(opts.InitialFPS, 1, 60)
	if opts.InitialFPS <= 0 {
		fps = 24
	}
	quality := clamp(opts.InitialQuality, 35, 95)
	if opts.InitialQuality <= 0 {
		quality = 82
	}
	// Preserve backward compatibility with older v0.4.0 viewers that omit Codec
	// and only decode FrameTypeJPEG (0x01).
	legacyJPEG := opts.InitialCodec == ""
	codec := normalizeCodec(opts.InitialCodec)
	if legacyJPEG {
		codec = "jpeg"
	}

	st := &streamRuntimeState{
		fps:           fps,
		quality:       quality,
		codec:         codec,
		maxWidth:      opts.InitialMaxWidth,
		localCursor:   opts.LocalCursor,
		ackNotify:     make(chan struct{}, 1),
		modeCh:        make(chan struct{}, 1),
		keyframeReqCh: make(chan struct{}, 1),
	}
	stats := &streamStats{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex
	sendFrame := func(frameType byte, payload []byte) error {
		writeMu.Lock()
		start := time.Now()
		err := protocol.WriteTypedFrame(stream, frameType, payload)
		took := time.Since(start)
		writeMu.Unlock()
		if err == nil {
			if opts.BytesSent != nil {
				opts.BytesSent.Add(int64(len(payload) + 5))
			}
			switch frameType {
			case protocol.FrameTypeH264, protocol.FrameTypeHEVC, protocol.FrameTypeTileBatch, protocol.FrameTypeJPEG:
				stats.addSent(len(payload)+5, took)
			}
		}
		return err
	}

	// Host-side mouse_move coalescer: never replay stale queued mouse_move events during brief bursts!
	moveCh := make(chan InputEvent, 1)
	if opts.AllowInput {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case mv := <-moveCh:
					_ = ApplyInputEvent(mv)
				}
			}
		}()
	}

	// Reader loop: handle input, ACK flow control, and live codec/quality switches
	go func() {
		defer cancel()
		held := newHeldInput()
		// If the link drops while a key or button is down (e.g. mid Ctrl+C or a drag),
		// release it on the host so it does not stay stuck after the session ends.
		defer func() {
			if opts.AllowInput {
				for _, up := range held.releaseAll() {
					_ = ApplyInputEvent(up)
				}
			}
		}()
		for {
			fType, payload, err := protocol.ReadTypedFrame(stream)
			if err != nil {
				return
			}
			if opts.BytesRecv != nil {
				opts.BytesRecv.Add(int64(len(payload) + 5))
			}
			if fType == protocol.FrameTypeClipboard {
				if opts.AllowInput && len(payload) > 1 {
					kind := payload[0]
					data := append([]byte(nil), payload[1:]...)
					go func() {
						_ = ApplyClipboardPayload(kind, data)
					}()
				}
				continue
			}
			if fType != protocol.FrameTypeInput {
				continue
			}
			var ev InputEvent
			if err := json.Unmarshal(payload, &ev); err != nil {
				continue
			}
			switch ev.Type {
			case "capture_check":
				go runCaptureCheck(ctx, func(done bool, results []captureCheckResult) {
					msg, _ := json.Marshal(map[string]any{"capture_check": map[string]any{"done": done, "results": results}})
					_ = sendFrame(protocol.FrameTypeStats, msg)
				})
			case "ping":
				// Answered through the same stream as the video, so the round trip includes any
				// queueing behind picture frames: the delay the user actually feels.
				pong, _ := json.Marshal(map[string]float64{"pong": ev.T})
				go func() { _ = sendFrame(protocol.FrameTypeStats, pong) }()
			case "ack":
				if ev.Seq > st.ackedSeq.Load() {
					st.ackedSeq.Store(ev.Seq)
				}
				select {
				case st.ackNotify <- struct{}{}:
				default:
				}
			case "keyframe":
				st.mu.Lock()
				st.forceKeyframe = true
				st.mu.Unlock()
				select {
				case st.keyframeReqCh <- struct{}{}:
				default:
				}
			case "config":
				st.mu.Lock()
				prevCodec := st.codec
				prevFPS := st.fps
				prevQuality := st.quality
				prevMaxW := st.maxWidth
				prevLocalCursor := st.localCursor
				if ev.LocalCursor != nil {
					st.localCursor = *ev.LocalCursor
				}
				if ev.FPS > 0 {
					st.fps = clamp(ev.FPS, 1, 60)
				}
				if ev.Quality > 0 {
					st.quality = clamp(ev.Quality, 35, 95)
				}
				if ev.Codec != "" {
					st.codec = normalizeCodec(ev.Codec)
					st.pendingH264Upgrade = false
					st.fallbackNotice = ""
					if st.codec == "h264" || st.codec == "hevc" {
						st.h264AutoRetries = 0
					}
				}
				if ev.MaxWidth >= 0 {
					if ev.MaxWidth != st.maxWidth {
						st.maxWidth = ev.MaxWidth
						st.forceKeyframe = true
					}
				}
				vidChanged := (st.codec == "h264" || st.codec == "hevc") && (st.fps != prevFPS || st.quality != prevQuality || st.maxWidth != prevMaxW ||
					(st.localCursor != prevLocalCursor && cursorShapeSupported()))
				if st.codec != prevCodec || vidChanged {
					st.forceKeyframe = true
					select {
					case st.modeCh <- struct{}{}:
					default:
					}
				}
				st.mu.Unlock()
			case "mouse_move":
				if opts.AllowInput {
					// Latest-wins overwrite so cursor jumps directly to newest position with zero backlog!
					select {
					case <-moveCh:
					default:
					}
					select {
					case moveCh <- ev:
					default:
					}
				}
			default:
				if opts.AllowInput {
					held.track(ev)
					_ = ApplyInputEvent(ev)
				}
			}
		}
	}()


	sendInfo := func(codecName, encoderName, notice string) {
		st.mu.Lock()
		st.encoder = encoderName
		st.mu.Unlock()
		msg, _ := json.Marshal(map[string]string{
			"codec":   codecName,
			"encoder": encoderName,
			"notice":  notice,
		})
		_ = sendFrame(protocol.FrameTypeInfo, msg)
	}

	// Tell the viewer whenever the host clipboard changes (any copy, e.g. right-click -> Copy in a
	// Linux terminal) so it pulls the content without waiting for Ctrl+C. Debounced, so a burst of
	// selection changes costs one pull.
	if opts.AllowInput {
		go func() {
			changes := WatchClipboardChanges(ctx)
			if changes == nil {
				return
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-changes:
				}
				sleepCtx(ctx, 300*time.Millisecond)
				select {
				case <-changes:
				default:
				}
				if ctx.Err() != nil {
					return
				}
				_ = sendFrame(protocol.FrameTypeClipboardChanged, nil)
			}
		}()
	}

	// Per-second statistics so the viewer can show where frames are lost (see streamStats).
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		load := newSysLoadSampler()
		defer load.Close()
		last := time.Now()
		var hints []string
		var hintsAt time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				snap := stats.take(now.Sub(last))
				if now.Sub(hintsAt) >= 5*time.Second {
					hints, hintsAt = hostScreenHints(), now
				}
				snap.ScreenHints = hints
				last = now
				st.mu.Lock()
				snap.TargetFPS = st.fps
				snap.Codec = st.codec
				snap.Encoder = st.encoder
				snap.LocalCur = st.localCursor && cursorShapeSupported() && (st.codec == "h264" || st.codec == "hevc")
				st.mu.Unlock()
				snap.FFmpegUpdate = bootstrap.FFmpegWGCUpgradeState()
				snap.setLoad(load.Sample())
				msg, _ := json.Marshal(map[string]any{"stats": snap})
				_ = sendFrame(protocol.FrameTypeStats, msg)
			}
		}
	}()

	// When FFmpeg was just upgraded to a build with Windows Graphics Capture, restart video so this
	// session moves off DXGI/GDI capture (and back to H.265 if only the old FFmpeg prevented it).
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-bootstrap.FFmpegUpdated():
		}
		st.mu.Lock()
		switch {
		case st.hevcSteppedDown && st.codec == "h264":
			st.codec = "hevc"
		case st.codec == "tiles" && st.fallbackNotice != "":
			// Smart Tiles was an automatic fallback from video, not the viewer's choice.
			st.codec = "h264"
			if st.hevcSteppedDown {
				st.codec = "hevc"
			}
			st.pendingH264Upgrade = false
			st.fallbackNotice = ""
		}
		st.hevcSteppedDown = false
		st.forceKeyframe = true
		st.mu.Unlock()
		stats.setHEVCFailure("")
		select {
		case st.modeCh <- struct{}{}:
		default:
		}
	}()

	// cursorLocal is true while the viewer draws the cursor from FrameTypeCursor reports; an empty
	// shape hands it back to the video when that stops (codec or setting change).
	cursorLocal := false
	sendCursor := func(shape string) {
		msg, _ := json.Marshal(map[string]string{"shape": shape})
		_ = sendFrame(protocol.FrameTypeCursor, msg)
	}

	var seq atomic.Uint32
	videoShortRuns := 0

	for ctx.Err() == nil {
		st.mu.Lock()
		curCodec := st.codec
		curFPS := st.fps
		curMaxW := st.maxWidth
		curQuality := st.quality
		localCur := st.localCursor && cursorShapeSupported() && (curCodec == "hevc" || curCodec == "h264")
		st.mu.Unlock()

		if cursorLocal && !localCur {
			sendCursor("")
		}
		cursorLocal = localCur

		if curCodec == "hevc" || curCodec == "h264" {
			vidCtx, vidCancel := context.WithCancel(ctx)
			if localCur {
				go watchCursorShape(vidCtx, sendCursor)
			}
			// Cancel video loop immediately if user switches codec or changes FPS/Resolution/Quality
			var modeChanged atomic.Bool
			go func() {
				select {
				case <-vidCtx.Done():
				case <-st.modeCh:
					modeChanged.Store(true)
					vidCancel()
				}
			}()

			encName, err := streamVideoFFmpeg(vidCtx, curCodec, curFPS, curMaxW, curQuality, &seq, st.keyframeReqCh, sendFrame, sendInfo, !localCur, stats)
			vidCancel()
			if ctx.Err() != nil {
				return nil
			}
			if modeChanged.Load() {
				// The viewer changed a setting (quality, FPS, scale, cursor or codec): start again with
				// it. This is not an encoder failure, so it must not step down to H.264 or Smart Tiles.
				videoShortRuns = 0
				continue
			}
			// A working encoder that stopped on its own (resolution change, display sleep, GPU reset)
			// is restarted with the same codec. Only repeated short runs fall back below.
			var ended *videoStreamEndedError
			if errors.As(err, &ended) {
				if ended.upgraded {
					// WGC works again; if H.265 had been given up only because capture failed, try it again.
					st.mu.Lock()
					if st.hevcSteppedDown && st.codec == "h264" {
						st.codec = "hevc"
						st.hevcSteppedDown = false
						curCodec = "hevc"
						stats.setHEVCFailure("")
					}
					st.mu.Unlock()
				}
				if ended.ran >= videoHealthyRun {
					videoShortRuns = 0
				} else {
					videoShortRuns++
				}
				st.mu.Lock()
				sameCodec := st.codec == curCodec
				st.mu.Unlock()
				if sameCodec && videoShortRuns <= maxVideoShortRuns {
					stats.addRestart()
					sleepCtx(ctx, time.Duration(videoShortRuns+1)*300*time.Millisecond)
					continue
				}
			}
			videoShortRuns = 0
			// If user switched mode intentionally, re-loop with new mode
			st.mu.Lock()
			stillSame := st.codec == curCodec
			if stillSame {
				if curCodec == "hevc" && bootstrap.HasFFmpeg() {
					// Remote host GPU has no H.265 encoder -> seamlessly step down to 60 FPS H.264!
					st.codec = "h264"
					st.forceKeyframe = true
					st.hevcSteppedDown = true
					reason := "ไม่มีตัวเข้ารหัส H.265 ที่ใช้ได้"
					if err != nil {
						reason += " (" + err.Error() + ")"
					}
					stats.setHEVCFailure(reason)
				} else {
					// Auto-fallback to Smart Tiles cleanly if ffmpeg/video unavailable.
					// Keep the real failure notice visible (never wipe it on serveDirtyTileLoop entry!)
					// and auto-upgrade back to 60 FPS video once FFmpeg finishes downloading OR after
					// a transient screen lock / UAC interruption (up to 2 auto-retries).
					st.codec = "tiles"
					st.forceKeyframe = true
					hasFF := bootstrap.HasFFmpeg()
					if !hasFF {
						st.pendingH264Upgrade = true
						st.fallbackNotice = "กำลังติดตั้งตัวเข้ารหัส 60 FPS (FFmpeg) เบื้องหลัง — ใช้ Smart Tiles ชั่วคราวและจะสลับเป็น 60 FPS อัตโนมัติเมื่อพร้อม"
					} else {
						maxRetries := 2
						if os.Getenv("APN_SERVICE_WORKER") == "1" {
							// On a System Service PC sitting at the Windows Lock/Login Screen (Winlogon),
							// keep retrying GPU video capture so it upgrades to 60 FPS the instant the user logs in!
							maxRetries = 120
						}
						if st.h264AutoRetries < maxRetries {
							st.h264AutoRetries++
							st.pendingH264Upgrade = true
						}
						reason := "encoder unavailable"
						if err != nil {
							reason = err.Error()
						}
						st.fallbackNotice = "โหมดวิดีโอ (" + encName + ") ไม่พร้อมชั่วคราว: " + reason + " — สลับเป็น Smart Tiles อัตโนมัติ"
					}
				}
			}
			st.mu.Unlock()
			continue
		}

		if curCodec == "jpeg" {
			if err := serveLegacyJPEGLoop(ctx, st, sendFrame); err != nil {
				return err
			}
			continue
		}

		if err := serveDirtyTileLoop(ctx, st, &seq, sendFrame, sendInfo); err != nil {
			return err
		}
	}
	return nil
}

// serveLegacyJPEGLoop serves full-frame FrameTypeJPEG (0x01) for backward compatibility with older viewers,
// while still benefiting from the fast zero-alloc CreateDIBSection capturer and bilinear scaling.
func serveLegacyJPEGLoop(ctx context.Context, st *streamRuntimeState, sendFrame func(byte, []byte) error) error {
	capturer := NewCapturer()
	defer capturer.Close()

	var (
		jpegBuf     bytes.Buffer
		scaleBuf    *image.RGBA
		lastErrSent time.Time
	)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-st.modeCh:
			st.mu.Lock()
			isLegacy := st.codec == "jpeg"
			st.mu.Unlock()
			if !isLegacy {
				return nil
			}
		default:
		}

		st.mu.Lock()
		fps := st.fps
		quality := st.quality
		maxW := st.maxWidth
		st.mu.Unlock()

		frameInterval := time.Second / time.Duration(fps)
		start := time.Now()

		rawImg, err := capturer.Capture()
		if err != nil {
			if time.Since(lastErrSent) > 2*time.Second {
				lastErrSent = time.Now()
				_ = sendFrame(protocol.FrameTypeError, []byte(err.Error()))
			}
			sleepCtx(ctx, 100*time.Millisecond)
			continue
		}

		img := rawImg
		if maxW > 0 && rawImg.Bounds().Dx() > maxW {
			img, scaleBuf = scaleBilinear(rawImg, maxW, scaleBuf)
		}
		b := img.Bounds()
		jpegBuf.Reset()
		var dim [4]byte
		binary.BigEndian.PutUint16(dim[0:2], uint16(b.Dx()))
		binary.BigEndian.PutUint16(dim[2:4], uint16(b.Dy()))
		jpegBuf.Write(dim[:])
		if err := jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: quality}); err == nil {
			if err := sendFrame(protocol.FrameTypeJPEG, jpegBuf.Bytes()); err != nil {
				return err
			}
		}

		sleepDur := frameInterval - time.Since(start)
		if sleepDur < 10*time.Millisecond {
			sleepDur = 10 * time.Millisecond
		}
		sleepCtx(ctx, sleepDur)
	}
}

type dirtyTile struct {
	x, y, w, h int
	codec      byte
	data       []byte
}

func serveDirtyTileLoop(
	ctx context.Context,
	st *streamRuntimeState,
	seqCounter *atomic.Uint32,
	sendFrame func(byte, []byte) error,
	sendInfo func(codec, encoder, notice string),
) error {
	capturer := NewCapturer()
	defer capturer.Close()

	st.mu.Lock()
	initNotice := st.fallbackNotice
	st.mu.Unlock()
	encLabel := "Zero-Alloc Dirty-Tiles (Native Sharp)"
	if initNotice != "" {
		encLabel = "Smart Dirty-Tiles (Fallback)"
	}
	sendInfo("tiles", encLabel, initNotice)

	var (
		prevHashes     []uint64
		prevW, prevH   int
		lastErrSent    time.Time
		lastFFCheckAt  = time.Now()
		batchBuf       bytes.Buffer
		scaleBuf       *image.RGBA
		pngEncoder     = png.Encoder{CompressionLevel: png.BestSpeed}
	)

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 2 {
		workers = 2
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-st.modeCh:
			st.mu.Lock()
			isVid := st.codec == "h264" || st.codec == "hevc"
			st.mu.Unlock()
			if isVid {
				return nil
			}
		default:
		}

		// ACK Flow Control: keep at most maxInFlightACKs frames in flight so latency never builds up.
		curSent := seqCounter.Load()
		if curSent > 0 && curSent-st.ackedSeq.Load() >= maxInFlightACKs {
			waitTimer := time.NewTimer(350 * time.Millisecond)
			select {
			case <-ctx.Done():
				waitTimer.Stop()
				return nil
			case <-st.ackNotify:
				waitTimer.Stop()
			case <-waitTimer.C:
				// Safety release in case a headless test client doesn't send ACKs
				st.ackedSeq.Store(curSent)
			}
		}

		st.mu.Lock()
		fps := st.fps
		quality := st.quality
		codec := st.codec
		maxW := st.maxWidth
		forceKF := st.forceKeyframe
		st.forceKeyframe = false
		pendingUp := st.pendingH264Upgrade
		retryWait := 3 * time.Second
		if st.h264AutoRetries > 0 {
			if os.Getenv("APN_SERVICE_WORKER") == "1" {
				retryWait = 6 * time.Second
			} else {
				retryWait = 12 * time.Second
			}
		}
		if pendingUp && time.Since(lastFFCheckAt) >= retryWait {
			lastFFCheckAt = time.Now()
			if bootstrap.HasFFmpeg() {
				st.codec = "h264"
				st.fps = 60
				st.pendingH264Upgrade = false
				st.fallbackNotice = ""
				st.mu.Unlock()
				return nil // Hot-upgrade live session straight into 60 FPS GPU H.264!
			}
		}
		st.mu.Unlock()

		// Cap CPU tile capture rate cleanly so encoder never starves input/OS threads.
		effectiveFPS := fps
		if codec == "png" && effectiveFPS > 15 {
			effectiveFPS = 15
		} else if effectiveFPS > 30 {
			effectiveFPS = 30
		}
		frameInterval := time.Second / time.Duration(effectiveFPS)
		start := time.Now()

		rawImg, err := capturer.Capture()
		if err != nil {
			if time.Since(lastErrSent) > 2*time.Second {
				lastErrSent = time.Now()
				_ = sendFrame(protocol.FrameTypeError, []byte(err.Error()))
			}
			sleepCtx(ctx, 100*time.Millisecond)
			continue
		}

		img := rawImg
		if maxW > 0 && rawImg.Bounds().Dx() > maxW {
			img, scaleBuf = scaleBilinear(rawImg, maxW, scaleBuf)
		}

		b := img.Bounds()
		w, h := b.Dx(), b.Dy()
		cols := (w + tileSize - 1) / tileSize
		rows := (h + tileSize - 1) / tileSize
		totalTiles := cols * rows

		if w != prevW || h != prevH || len(prevHashes) != totalTiles {
			prevHashes = make([]uint64, totalTiles)
			prevW, prevH = w, h
			forceKF = true
		}

		var dirty []dirtyTile
		for row := 0; row < rows; row++ {
			ty := row * tileSize
			th := tileSize
			if ty+th > h {
				th = h - ty
			}
			for col := 0; col < cols; col++ {
				tx := col * tileSize
				tw := tileSize
				if tx+tw > w {
					tw = w - tx
				}
				idx := row*cols + col
				hash := hashTileRGBA(img, tx, ty, tw, th)
				if forceKF || hash != prevHashes[idx] {
					prevHashes[idx] = hash
					dirty = append(dirty, dirtyTile{x: tx, y: ty, w: tw, h: th})
				}
			}
		}

		if len(dirty) == 0 {
			// Screen unchanged -> send 0 bytes!
			sleepDur := frameInterval - time.Since(start)
			if sleepDur < 12*time.Millisecond {
				sleepDur = 12 * time.Millisecond
			}
			sleepCtx(ctx, sleepDur)
			continue
		}

		// Hybrid Smart Codec:
		// In PNG mode, if >40% of the screen changed in a single burst (e.g. scrolling/window drag/first frame),
		// use fast high-quality JPEG (Q86) for that motion burst so it NEVER stalls or floods bandwidth,
		// and use crystal-clear lossless PNG for small/moderate text/UI updates!
		usePNG := codec == "png" && len(dirty)*10 <= totalTiles*4
		encQuality := quality
		if codec == "png" && !usePNG && encQuality < 86 {
			encQuality = 86
		}
		encodeDirtyTilesParallel(img, dirty, usePNG, encQuality, &pngEncoder, workers)

		seq := seqCounter.Add(1)
		batchBuf.Reset()
		var hdr [10]byte
		binary.BigEndian.PutUint32(hdr[0:4], seq)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(w))
		binary.BigEndian.PutUint16(hdr[6:8], uint16(h))
		binary.BigEndian.PutUint16(hdr[8:10], uint16(len(dirty)))
		batchBuf.Write(hdr[:])

		var thdr [13]byte
		for i := range dirty {
			t := &dirty[i]
			binary.BigEndian.PutUint16(thdr[0:2], uint16(t.x))
			binary.BigEndian.PutUint16(thdr[2:4], uint16(t.y))
			binary.BigEndian.PutUint16(thdr[4:6], uint16(t.w))
			binary.BigEndian.PutUint16(thdr[6:8], uint16(t.h))
			thdr[8] = t.codec
			binary.BigEndian.PutUint32(thdr[9:13], uint32(len(t.data)))
			batchBuf.Write(thdr[:])
			batchBuf.Write(t.data)
		}

		if err := sendFrame(protocol.FrameTypeTileBatch, batchBuf.Bytes()); err != nil {
			return err
		}

		// Always yield a small minimum breather so input & UI stay silky responsive even under heavy load.
		sleepDur := frameInterval - time.Since(start)
		if sleepDur < 8*time.Millisecond {
			sleepDur = 8 * time.Millisecond
		}
		sleepCtx(ctx, sleepDur)
	}
}

func encodeDirtyTilesParallel(img *image.RGBA, tiles []dirtyTile, usePNG bool, quality int, pngEnc *png.Encoder, maxWorkers int) {
	if len(tiles) <= 2 {
		var buf bytes.Buffer
		for i := range tiles {
			encodeOneTile(img, &tiles[i], usePNG, quality, pngEnc, &buf)
		}
		return
	}

	numW := maxWorkers
	if len(tiles) < numW {
		numW = len(tiles)
	}
	var nextIdx atomic.Int32
	var wg sync.WaitGroup
	wg.Add(numW)
	for w := 0; w < numW; w++ {
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			buf.Grow(16 * 1024)
			for {
				i := int(nextIdx.Add(1) - 1)
				if i >= len(tiles) {
					return
				}
				encodeOneTile(img, &tiles[i], usePNG, quality, pngEnc, &buf)
			}
		}()
	}
	wg.Wait()
}

func encodeOneTile(img *image.RGBA, t *dirtyTile, usePNG bool, quality int, pngEnc *png.Encoder, buf *bytes.Buffer) {
	sub := img.SubImage(image.Rect(t.x, t.y, t.x+t.w, t.y+t.h))
	buf.Reset()
	if usePNG {
		t.codec = tileCodecPNG
		_ = pngEnc.Encode(buf, sub)
	} else {
		t.codec = tileCodecJPEG
		_ = jpeg.Encode(buf, sub, &jpeg.Options{Quality: quality})
	}
	t.data = append([]byte(nil), buf.Bytes()...)
}

// hashTileRGBA computes a fast 64-bit FNV-1a hash over a rectangular RGBA region.
func hashTileRGBA(img *image.RGBA, x, y, w, h int) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var hash uint64 = offset64
	stride := img.Stride
	pix := img.Pix
	rowBytes := w * 4
	for ry := 0; ry < h; ry++ {
		off := (y+ry)*stride + x*4
		row := pix[off : off+rowBytes]
		// Process 8 bytes at a time for high throughput
		i := 0
		for ; i+8 <= len(row); i += 8 {
			v := binary.LittleEndian.Uint64(row[i : i+8])
			hash ^= v
			hash *= prime64
		}
		for ; i < len(row); i++ {
			hash ^= uint64(row[i])
			hash *= prime64
		}
	}
	return hash
}

// scaleBilinear produces smooth, anti-aliased downscaled frames (eliminating nearest-neighbor jagged text).
func scaleBilinear(src *image.RGBA, maxWidth int, reuse *image.RGBA) (*image.RGBA, *image.RGBA) {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	if sw <= maxWidth || sw == 0 || sh == 0 {
		return src, reuse
	}
	dw := maxWidth
	dh := sh * dw / sw
	if dh <= 0 {
		dh = 1
	}
	dst := reuse
	if dst == nil || dst.Bounds().Dx() != dw || dst.Bounds().Dy() != dh {
		dst = image.NewRGBA(image.Rect(0, 0, dw, dh))
	}

	xRatio := float64(sw-1) / float64(dw)
	yRatio := float64(sh-1) / float64(dh)
	srcPix := src.Pix
	dstPix := dst.Pix
	srcStride := src.Stride
	dstStride := dst.Stride

	for y := 0; y < dh; y++ {
		gy := float64(y) * yRatio
		y0 := int(gy)
		y1 := y0 + 1
		if y1 >= sh {
			y1 = sh - 1
		}
		fy := gy - float64(y0)
		iy0 := y0 * srcStride
		iy1 := y1 * srcStride
		dstRow := y * dstStride

		for x := 0; x < dw; x++ {
			gx := float64(x) * xRatio
			x0 := int(gx)
			x1 := x0 + 1
			if x1 >= sw {
				x1 = sw - 1
			}
			fx := gx - float64(x0)

			c00 := iy0 + x0*4
			c10 := iy0 + x1*4
			c01 := iy1 + x0*4
			c11 := iy1 + x1*4

			w00 := (1 - fx) * (1 - fy)
			w10 := fx * (1 - fy)
			w01 := (1 - fx) * fy
			w11 := fx * fy

			di := dstRow + x*4
			dstPix[di] = uint8(float64(srcPix[c00])*w00 + float64(srcPix[c10])*w10 + float64(srcPix[c01])*w01 + float64(srcPix[c11])*w11)
			dstPix[di+1] = uint8(float64(srcPix[c00+1])*w00 + float64(srcPix[c10+1])*w10 + float64(srcPix[c01+1])*w01 + float64(srcPix[c11+1])*w11)
			dstPix[di+2] = uint8(float64(srcPix[c00+2])*w00 + float64(srcPix[c10+2])*w10 + float64(srcPix[c01+2])*w01 + float64(srcPix[c11+2])*w11)
			dstPix[di+3] = 255
		}
	}
	return dst, dst
}

func normalizeCodec(c string) string {
	switch c {
	case "png", "h264", "hevc", "tiles", "jpeg":
		return c
	default:
		return "tiles"
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

var errUnsupportedPlatform = errors.New("screen capture not supported on this host without helper tool")
