package remote

import (
	"sync"
	"time"
)

// wheelPixelsPerNotch is how many viewer wheel pixels make one X11 scroll button click.
const wheelPixelsPerNotch = 60

var (
	wheelMu    sync.Mutex
	wheelAccum int
	wheelLast  time.Time
)

// wheelNotches turns a pixel wheel delta from the viewer into X11 scroll clicks (buttons 4/5),
// keeping the remainder so smooth touchpad scrolling is neither lost nor multiplied.
// The first event after a pause always scrolls at least one notch so a single tick feels instant.
func wheelNotches(deltaY int) int {
	if deltaY == 0 {
		return 0
	}
	wheelMu.Lock()
	defer wheelMu.Unlock()
	now := time.Now()
	if now.Sub(wheelLast) > 250*time.Millisecond || (wheelAccum > 0) != (deltaY > 0) {
		wheelAccum = 0
	}
	idle := now.Sub(wheelLast) > 250*time.Millisecond
	wheelLast = now
	wheelAccum += deltaY
	n := wheelAccum / wheelPixelsPerNotch
	if n == 0 && idle {
		if deltaY > 0 {
			n = 1
		} else {
			n = -1
		}
	}
	wheelAccum -= n * wheelPixelsPerNotch
	if n < 0 {
		n = -n
	}
	if n > 10 {
		n = 10
	}
	return n
}
