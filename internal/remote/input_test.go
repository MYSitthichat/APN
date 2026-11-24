package remote

import (
	"errors"
	"sort"
	"testing"
	"time"
)

func TestHeldInputReleasesStuckKeysAndButtons(t *testing.T) {
	h := newHeldInput()
	h.track(InputEvent{Type: "key_down", Code: "ControlLeft", Key: "Control"})
	h.track(InputEvent{Type: "key_down", Code: "KeyC", Key: "c"})
	h.track(InputEvent{Type: "key_up", Code: "KeyC", Key: "c"})
	h.track(InputEvent{Type: "mouse_down", Button: "left", X: 0.5, Y: 0.25})
	h.track(InputEvent{Type: "mouse_down", Button: "right"})
	h.track(InputEvent{Type: "mouse_up", Button: "right"})

	ups := h.releaseAll()
	var got []string
	for _, ev := range ups {
		got = append(got, ev.Type+":"+ev.Code+ev.Button)
	}
	sort.Strings(got)
	want := []string{"key_up:ControlLeft", "mouse_up:left"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("releaseAll = %v, want %v", got, want)
	}
	for _, ev := range ups {
		if ev.Type == "mouse_up" && (ev.X != 0.5 || ev.Y != 0.25) {
			t.Fatalf("mouse_up should keep the press position, got %+v", ev)
		}
	}
	if again := h.releaseAll(); len(again) != 0 {
		t.Fatalf("second releaseAll should be empty, got %v", again)
	}
}

func TestHeldInputUsesKeyWhenCodeMissing(t *testing.T) {
	h := newHeldInput()
	h.track(InputEvent{Type: "key_down", Key: "Shift"})
	h.track(InputEvent{Type: "key_up", Key: "Shift"})
	if ups := h.releaseAll(); len(ups) != 0 {
		t.Fatalf("key released by Key should not be held, got %v", ups)
	}
}

func TestVideoStreamEndedErrorUnwraps(t *testing.T) {
	cause := errors.New("x11grab: display resized")
	var err error = &videoStreamEndedError{encoder: "X11 + VAAPI GPU", ran: 42 * time.Second, cause: cause}
	var ended *videoStreamEndedError
	if !errors.As(err, &ended) || ended.ran < videoHealthyRun {
		t.Fatalf("errors.As failed or run too short: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is should reach the FFmpeg cause")
	}
}
