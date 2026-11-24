//go:build !linux

package bootstrap

import (
	"context"
	"log/slog"
)

// EnsureLinuxClipboardTools is a no-op outside Linux.
func EnsureLinuxClipboardTools(_ context.Context, _ *slog.Logger) {}
