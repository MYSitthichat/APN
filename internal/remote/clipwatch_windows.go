//go:build windows

package remote

import (
	"context"
	"time"
)

var (
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")

	// ownClipSeq is the clipboard sequence number right after APN's own last write.
	ownClipSeq uint32
)

// ClipboardSeq returns the window-station clipboard sequence number; it changes on every copy.
func ClipboardSeq() uint32 {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return uint32(r)
}

// WatchClipboardChanges signals when another application changes the clipboard.
// Changes made by ApplyClipboardPayload are ignored.
func WatchClipboardChanges(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(400 * time.Millisecond)
		defer t.Stop()
		last := ClipboardSeq()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			clipApplyMu.Lock()
			cur := ClipboardSeq()
			own := ownClipSeq
			clipApplyMu.Unlock()
			if cur == last {
				continue
			}
			last = cur
			if cur == own {
				continue
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch
}
