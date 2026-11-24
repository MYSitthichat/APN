//go:build !windows && !linux

package remote

import "context"

// ClipboardSeq is not available on this OS; callers compare content hashes instead.
func ClipboardSeq() uint32 { return 0 }

// WatchClipboardChanges is not implemented on this OS (macOS); the viewer still pulls the
// host clipboard on Ctrl+C. A nil channel never fires.
func WatchClipboardChanges(_ context.Context) <-chan struct{} { return nil }
