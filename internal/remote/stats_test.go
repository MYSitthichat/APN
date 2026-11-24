package remote

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/protocol"
)

func TestStreamStatsTake(t *testing.T) {
	var s streamStats
	for i := 0; i < 60; i++ {
		s.addEncoded()
	}
	for i := 0; i < 50; i++ {
		s.addSent(10_000, time.Duration(i)*time.Millisecond)
	}
	s.addDropped(3)
	s.addRestart()
	s.noteQueue(4)
	s.noteQueue(2)

	got := s.take(time.Second)
	if got.EncodedFPS != 60 || got.SentFPS != 50 || got.Dropped != 3 || got.Restarts != 1 || got.QueueMax != 4 {
		t.Fatalf("unexpected snapshot %+v", got)
	}
	if got.Kbps != 4000 { // 50 x 10 kB in one second
		t.Fatalf("kbps = %d, want 4000", got.Kbps)
	}
	if got.StallMs != 49 {
		t.Fatalf("stall = %v ms, want 49", got.StallMs)
	}

	// Per-second counters reset; the restart total does not.
	again := s.take(time.Second)
	if again.EncodedFPS != 0 || again.SentFPS != 0 || again.Dropped != 0 || again.StallMs != 0 || again.Restarts != 1 {
		t.Fatalf("counters not reset: %+v", again)
	}

	var nilStats *streamStats
	nilStats.addEncoded()
	nilStats.addSent(1, time.Millisecond)
	nilStats.addDropped(1)
	nilStats.addRestart()
	nilStats.noteQueue(1)
}

func TestEncoderCandidatesCursorFlag(t *testing.T) {
	for _, draw := range []bool{true, false} {
		for _, c := range videoEncoderCandidates("h264", 60, 1920, 1080, 1920, 1080, 82, draw) {
			joined := strings.Join(c.args, " ")
			on := strings.Contains(joined, "capture_cursor=1") || strings.Contains(joined, "draw_mouse=1") ||
				strings.Contains(joined, "-draw_mouse 1") || strings.Contains(joined, "-capture_cursor 1")
			if on != draw {
				t.Fatalf("drawCursor=%v but candidate %q has cursor on=%v: %s", draw, c.name, on, joined)
			}
		}
	}
}

// TestScreenSessionAnswersPing checks that a viewer ping comes back as FrameTypeStats {"pong":t}.
func TestScreenSessionAnswersPing(t *testing.T) {
	host, viewer := net.Pipe()
	defer viewer.Close()
	go func() {
		_ = ServeScreenSession(host, StreamOptions{InitialCodec: "tiles", InitialFPS: 1})
		_ = host.Close()
	}()

	ping, _ := json.Marshal(map[string]any{"type": "ping", "t": 1234.5})
	go func() { _ = protocol.WriteTypedFrame(viewer, protocol.FrameTypeInput, ping) }()

	_ = viewer.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		fType, payload, err := protocol.ReadTypedFrame(viewer)
		if err != nil {
			t.Fatalf("no pong: %v", err)
		}
		if fType != protocol.FrameTypeStats {
			continue
		}
		var msg struct {
			Pong *float64 `json:"pong"`
		}
		if json.Unmarshal(payload, &msg) == nil && msg.Pong != nil {
			if *msg.Pong != 1234.5 {
				t.Fatalf("pong = %v, want 1234.5", *msg.Pong)
			}
			return
		}
	}
}
