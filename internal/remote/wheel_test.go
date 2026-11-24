package remote

import (
	"testing"
	"time"
)

func resetWheel() {
	wheelMu.Lock()
	wheelAccum = 0
	wheelLast = time.Time{}
	wheelMu.Unlock()
}

func TestWheelNotchesMouseNotch(t *testing.T) {
	resetWheel()
	if n := wheelNotches(100); n != 1 {
		t.Fatalf("one 100px mouse notch = %d clicks, want 1", n)
	}
}

func TestWheelNotchesTouchpadAccumulates(t *testing.T) {
	resetWheel()
	// First small delta after idle scrolls one notch immediately.
	if n := wheelNotches(10); n != 1 {
		t.Fatalf("first touchpad delta = %d, want 1", n)
	}
	// Continuous small deltas accumulate instead of one click per event.
	total := 0
	for i := 0; i < 12; i++ {
		total += wheelNotches(10)
	}
	if total < 1 || total > 3 {
		t.Fatalf("120px of touchpad scroll gave %d clicks, want about 2", total)
	}
}

func TestWheelNotchesDirectionChangeAndCap(t *testing.T) {
	resetWheel()
	_ = wheelNotches(50)
	if n := wheelNotches(-100); n != 1 {
		t.Fatalf("direction change should start fresh, got %d", n)
	}
	resetWheel()
	if n := wheelNotches(100000); n != 10 {
		t.Fatalf("huge delta should cap at 10 clicks, got %d", n)
	}
}
