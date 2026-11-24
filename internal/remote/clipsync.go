package remote

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// ClipboardHash identifies clipboard content (kind 0/2 = text, 1/3 = PNG image) so the
// viewer and host can skip re-sending content the other side already has.
func ClipboardHash(kind byte, data []byte) string {
	k := kind
	switch k {
	case 2:
		k = 0
	case 3:
		k = 1
	}
	h := sha256.New()
	h.Write([]byte{k})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// clipApplyMu serialises ApplyClipboardPayload with the host clipboard watcher, so a change
// APN makes itself is never reported back to the viewer as a new copy (echo loop).
var clipApplyMu sync.Mutex
