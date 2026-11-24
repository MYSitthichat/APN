package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestUpgradeFFmpegForWGCDownload downloads the real FFmpeg build into a temporary BinDir and
// checks it has gfxcapture. Network and Windows only: set APN_NET_TEST=1 to run it.
func TestUpgradeFFmpegForWGCDownload(t *testing.T) {
	if os.Getenv("APN_NET_TEST") != "1" || runtime.GOOS != "windows" {
		t.Skip("set APN_NET_TEST=1 on Windows to download FFmpeg")
	}
	dir := t.TempDir()
	t.Setenv("APN_BIN_DIR", dir)
	old := filepath.Join(dir, "ffmpeg.exe")
	if err := os.WriteFile(old, []byte("old ffmpeg without gfxcapture"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := NewManager(nil).upgradeFFmpegForWGC(ctx); err != nil {
		t.Fatal(err)
	}
	if !FFmpegHasFilter(ctx, old, "gfxcapture") {
		t.Fatal("installed ffmpeg.exe has no gfxcapture")
	}
	if p, ok := FindFFmpeg(); !ok || p != old {
		t.Fatalf("FindFFmpeg = %q, want %q", p, old)
	}
}
