package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestPinnedCloudflaredDownload downloads the pinned cloudflared for this platform and checks
// its hash. Network only: set APN_NET_TEST=1.
func TestPinnedCloudflaredDownload(t *testing.T) {
	if os.Getenv("APN_NET_TEST") != "1" {
		t.Skip("set APN_NET_TEST=1 to download cloudflared")
	}
	pin, name := cloudflaredDownloadTarget()
	if pin.URL == "" {
		t.Skip("no cloudflared build for this platform")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	dest := filepath.Join(t.TempDir(), name)
	if err := NewManager(nil).downloadDirectBinary(ctx, pin, dest, "test"); err != nil {
		t.Fatal(err)
	}
	bad := pin
	bad.SHA256 = strings.Repeat("0", 64)
	if err := NewManager(nil).downloadDirectBinary(ctx, bad, dest+".bad", "test"); err == nil {
		t.Fatal("a download with the wrong hash was installed")
	}
	if _, err := os.Stat(dest + ".bad"); !os.IsNotExist(err) {
		t.Fatal("rejected download left a file behind")
	}
}
