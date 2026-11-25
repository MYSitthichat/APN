package remote

import (
	"sync/atomic"
	"time"
)

// streamStats counts what happens to video on the host during one screen session, so the viewer
// can tell where a stutter comes from: the encoder (encoded FPS), the network (send stalls,
// dropped frames) or its own decoder. All methods accept a nil receiver.
type streamStats struct {
	encoded   atomic.Uint32 // frames that came out of the encoder
	sent      atomic.Uint32 // picture frames written to the stream
	sentBytes atomic.Uint64
	dropped   atomic.Uint32 // frames thrown away because the network could not keep up
	restarts  atomic.Uint32 // encoder relaunches (keyframe requests, recoveries); total, not per second
	stallNs   atomic.Int64  // longest single frame write in the current second
	queueMax  atomic.Int32  // deepest send queue in the current second

	// fallback lists why faster capture/encoder paths were skipped for the running encoder,
	// e.g. "WGC: FFmpeg has no gfxcapture". hevcFail says why H.265 was given up for H.264.
	fallback atomic.Pointer[[]string]
	hevcFail atomic.Pointer[string]
}

func (s *streamStats) setFallback(reasons []string) {
	if s != nil {
		cp := append([]string(nil), reasons...)
		s.fallback.Store(&cp)
	}
}

func (s *streamStats) setHEVCFailure(reason string) {
	if s != nil {
		s.hevcFail.Store(&reason)
	}
}

func (s *streamStats) addEncoded() {
	if s != nil {
		s.encoded.Add(1)
	}
}

func (s *streamStats) addDropped(n int) {
	if s != nil && n > 0 {
		s.dropped.Add(uint32(n))
	}
}

func (s *streamStats) addRestart() {
	if s != nil {
		s.restarts.Add(1)
	}
}

func (s *streamStats) noteQueue(depth int) {
	if s == nil {
		return
	}
	for {
		cur := s.queueMax.Load()
		if int32(depth) <= cur || s.queueMax.CompareAndSwap(cur, int32(depth)) {
			return
		}
	}
}

// addSent records one picture frame write and how long the write blocked. A write that blocks
// means the transport (QUIC/TCP/relay) is not accepting data as fast as frames are produced.
func (s *streamStats) addSent(bytes int, took time.Duration) {
	if s == nil {
		return
	}
	s.sent.Add(1)
	s.sentBytes.Add(uint64(bytes))
	for {
		cur := s.stallNs.Load()
		if int64(took) <= cur || s.stallNs.CompareAndSwap(cur, int64(took)) {
			return
		}
	}
}

// streamStatsSnapshot is the per-second report sent to the viewer (FrameTypeStats).
type streamStatsSnapshot struct {
	EncodedFPS int     `json:"enc_fps"`
	SentFPS    int     `json:"sent_fps"`
	Kbps       int     `json:"kbps"`
	Dropped    int     `json:"dropped"`
	Restarts   int     `json:"restarts"`
	StallMs    float64 `json:"stall_ms"`
	QueueMax   int     `json:"queue_max"`
	TargetFPS  int     `json:"target_fps"`
	Codec      string  `json:"codec"`
	Encoder    string  `json:"encoder,omitempty"`
	LocalCur   bool    `json:"local_cursor"`
	// Fallback explains why the host is not on its fastest capture/encoder path (empty when it is).
	Fallback     []string `json:"fallback,omitempty"`
	FFmpegUpdate string   `json:"ffmpeg_update,omitempty"` // automatic FFmpeg upgrade: running, done, failed: ...
	// Host load over the last second; nil when it cannot be measured on this host.
	CPU       *float64 `json:"cpu,omitempty"`
	GPU       *float64 `json:"gpu,omitempty"`
	GPUEngine string   `json:"gpu_engine,omitempty"` // busiest GPU engine: 3D, VideoEncode, NVENC, ...
	// ScreenHints are host conditions that make the picture black or blank (see screenhints.go).
	ScreenHints []string `json:"screen_hints,omitempty"`
}

// setLoad fills the host CPU/GPU load, leaving unknown (-1) values out.
func (s *streamStatsSnapshot) setLoad(cpu, gpu float64, engine string) {
	round := func(v float64) *float64 { r := float64(int(v*10+0.5)) / 10; return &r }
	if cpu >= 0 {
		s.CPU = round(cpu)
	}
	if gpu >= 0 {
		s.GPU = round(gpu)
		s.GPUEngine = engine
	}
}

// take returns the counters accumulated over elapsed and resets the per-second ones.
func (s *streamStats) take(elapsed time.Duration) streamStatsSnapshot {
	if elapsed <= 0 {
		elapsed = time.Second
	}
	perSec := func(n uint64) int { return int(float64(n)/elapsed.Seconds() + 0.5) }
	bytes := s.sentBytes.Swap(0)
	var fallback []string
	if h := s.hevcFail.Load(); h != nil && *h != "" {
		fallback = append(fallback, "H.265 → H.264: "+*h)
	}
	if f := s.fallback.Load(); f != nil {
		fallback = append(fallback, (*f)...)
	}
	return streamStatsSnapshot{
		Fallback:   fallback,
		EncodedFPS: perSec(uint64(s.encoded.Swap(0))),
		SentFPS:    perSec(uint64(s.sent.Swap(0))),
		Kbps:       int(float64(bytes) * 8 / 1000 / elapsed.Seconds()),
		Dropped:    int(s.dropped.Swap(0)),
		Restarts:   int(s.restarts.Load()),
		StallMs:    float64(s.stallNs.Swap(0)/int64(time.Microsecond)) / 1000,
		QueueMax:   int(s.queueMax.Swap(0)),
	}
}
