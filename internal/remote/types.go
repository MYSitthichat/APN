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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/protocol"
)

const (
	tileSize        = 128
	tileCodecJPEG   = byte(0)
	tileCodecPNG    = byte(1)
	maxInFlightACKs = 3
)

// ScreenCapturer captures desktop frames, reusing OS handles & memory buffers when supported.
type ScreenCapturer interface {
	Capture() (*image.RGBA, error)
	Close()
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
}

// StreamOptions configures a live remote screen session.
type StreamOptions struct {
	InitialFPS      int
	InitialQuality  int
	InitialCodec    string // "tiles" (default), "png", "h264"
	InitialMaxWidth int    // 0 = Native 100%
	AllowInput      bool
	BytesSent       *atomic.Int64
	BytesRecv       *atomic.Int64
}

type streamRuntimeState struct {
	mu            sync.Mutex
	fps           int
	quality       int
	codec         string
	maxWidth      int
	forceKeyframe bool

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
		ackNotify:     make(chan struct{}, 1),
		modeCh:        make(chan struct{}, 1),
		keyframeReqCh: make(chan struct{}, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		for {
			fType, payload, err := protocol.ReadTypedFrame(stream)
			if err != nil {
				return
			}
			if opts.BytesRecv != nil {
				opts.BytesRecv.Add(int64(len(payload) + 5))
			}
			if fType != protocol.FrameTypeInput {
				continue
			}
			var ev InputEvent
			if err := json.Unmarshal(payload, &ev); err != nil {
				continue
			}
			switch ev.Type {
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
				if ev.FPS > 0 {
					st.fps = clamp(ev.FPS, 1, 60)
				}
				if ev.Quality > 0 {
					st.quality = clamp(ev.Quality, 35, 95)
				}
				if ev.Codec != "" {
					st.codec = normalizeCodec(ev.Codec)
				}
				if ev.MaxWidth >= 0 {
					if ev.MaxWidth != st.maxWidth {
						st.maxWidth = ev.MaxWidth
						st.forceKeyframe = true
					}
				}
				h264Changed := st.codec == "h264" && (st.fps != prevFPS || st.quality != prevQuality || st.maxWidth != prevMaxW)
				if st.codec != prevCodec || h264Changed {
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
					_ = ApplyInputEvent(ev)
				}
			}
		}
	}()

	var writeMu sync.Mutex
	sendFrame := func(frameType byte, payload []byte) error {
		writeMu.Lock()
		err := protocol.WriteTypedFrame(stream, frameType, payload)
		writeMu.Unlock()
		if err == nil && opts.BytesSent != nil {
			opts.BytesSent.Add(int64(len(payload) + 5))
		}
		return err
	}

	sendInfo := func(codecName, encoderName, notice string) {
		msg, _ := json.Marshal(map[string]string{
			"codec":   codecName,
			"encoder": encoderName,
			"notice":  notice,
		})
		_ = sendFrame(protocol.FrameTypeInfo, msg)
	}

	var seq atomic.Uint32

	for ctx.Err() == nil {
		st.mu.Lock()
		curCodec := st.codec
		curFPS := st.fps
		curMaxW := st.maxWidth
		curQuality := st.quality
		st.mu.Unlock()

		if curCodec == "h264" {
			h264Ctx, h264Cancel := context.WithCancel(ctx)
			// Cancel H.264 loop immediately if user switches codec or changes FPS/Resolution/Quality
			go func() {
				select {
				case <-h264Ctx.Done():
				case <-st.modeCh:
					h264Cancel()
				}
			}()

			encName, err := streamH264FFmpeg(h264Ctx, curFPS, curMaxW, curQuality, &seq, st.keyframeReqCh, sendFrame, sendInfo)
			h264Cancel()
			if ctx.Err() != nil {
				return nil
			}
			// If user switched mode intentionally, re-loop with new mode
			st.mu.Lock()
			stillH264 := st.codec == "h264"
			if stillH264 {
				// Auto-fallback to Smart Tiles cleanly if ffmpeg/H.264 unavailable
				st.codec = "tiles"
				st.forceKeyframe = true
			}
			st.mu.Unlock()
			if stillH264 && err != nil {
				sendInfo("tiles", "Smart Dirty-Tiles (Fallback)", "โหมด H.264 ("+encName+") ไม่พร้อมใช้งาน: "+err.Error()+" — สลับเป็น Smart Tiles ความละเอียดเต็มอัตโนมัติ")
			}
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

	sendInfo("tiles", "Zero-Alloc Dirty-Tiles (Native Sharp)", "")

	var (
		prevHashes   []uint64
		prevW, prevH int
		lastErrSent  time.Time
		batchBuf     bytes.Buffer
		scaleBuf     *image.RGBA
		pngEncoder   = png.Encoder{CompressionLevel: png.BestSpeed}
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
			isH264 := st.codec == "h264"
			st.mu.Unlock()
			if isH264 {
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
	case "png", "h264", "tiles", "jpeg":
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
