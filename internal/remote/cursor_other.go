//go:build !windows

package remote

import "context"

// cursorShapeSupported reports whether this host can report its cursor shape. Elsewhere the
// cursor stays drawn into the video.
func cursorShapeSupported() bool { return false }

func watchCursorShape(ctx context.Context, send func(shape string)) { <-ctx.Done() }
