package remote

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"relayvpn/internal/protocol"
)

// TestWatchSecureDesktop walks the host through a UAC prompt in user mode (cannot be shown) and
// in the System Service (shown with Smart Tiles): user mode alerts the viewer, the service
// restarts the stream loop instead.
func TestWatchSecureDesktop(t *testing.T) {
	type state struct{ active, reach bool }
	var mu sync.Mutex
	cur := state{}
	probe := func() (bool, bool) {
		mu.Lock()
		defer mu.Unlock()
		return cur.active, cur.reach
	}
	alerts := make(chan string, 16)
	sendFrame := func(ft byte, payload []byte) error {
		if ft != protocol.FrameTypeInfo {
			t.Errorf("frame type %#x", ft)
		}
		var m map[string]string
		_ = json.Unmarshal(payload, &m)
		alerts <- m["alert"]
		return nil
	}
	st := &streamRuntimeState{modeCh: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchSecureDesktop(ctx, st, sendFrame, probe, 5*time.Millisecond)

	set := func(s state) {
		mu.Lock()
		cur = s
		mu.Unlock()
	}
	wantAlert := func(blocked bool) {
		t.Helper()
		select {
		case a := <-alerts:
			if (a != "") != blocked {
				t.Fatalf("alert %q, want blocked=%v", a, blocked)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no alert")
		}
	}
	wantRestart := func(want bool) {
		t.Helper()
		select {
		case <-st.modeCh:
			if !want {
				t.Fatal("unexpected stream restart")
			}
		case <-time.After(100 * time.Millisecond):
			if want {
				t.Fatal("stream loop was not restarted")
			}
		}
	}

	set(state{true, false}) // user mode: UAC prompt appears
	wantAlert(true)
	wantRestart(false)
	set(state{false, false}) // prompt closed
	wantAlert(false)
	wantRestart(false)

	set(state{true, true}) // System Service: UAC prompt appears
	wantRestart(true)
	set(state{false, false})
	wantRestart(true)
	select {
	case a := <-alerts:
		t.Fatalf("service mode sent alert %q", a)
	default:
	}
}
