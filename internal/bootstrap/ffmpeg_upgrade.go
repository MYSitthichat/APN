package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"relayvpn/internal/executil"
)

var (
	wgcUpgradeMu    sync.Mutex
	wgcUpgradeState string // "", "running", "done", "failed: ..."
	ffmpegUpdatedCh = make(chan struct{})
	ffmpegUpdatedMu sync.Once
)

// FFmpegUpdated is closed once FFmpeg was replaced by a newer build in this process, so running
// screen sessions can restart video and pick up the faster capture path.
func FFmpegUpdated() <-chan struct{} { return ffmpegUpdatedCh }

// FFmpegWGCUpgradeState describes the automatic FFmpeg upgrade for the stats panel: "" (not
// needed), "running", "done" or "failed: <reason>".
func FFmpegWGCUpgradeState() string {
	wgcUpgradeMu.Lock()
	defer wgcUpgradeMu.Unlock()
	return wgcUpgradeState
}

// RequestFFmpegWGCUpgrade is called when the installed FFmpeg has no gfxcapture filter, which
// forces Windows capture down to DXGI or the ~11 FPS GDI path. It downloads a build that has it
// into BinDir (which FindFFmpeg prefers) in the background, at most once per process.
func RequestFFmpegWGCUpgrade() {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return
	}
	wgcUpgradeMu.Lock()
	if wgcUpgradeState != "" {
		wgcUpgradeMu.Unlock()
		return
	}
	wgcUpgradeState = "running"
	wgcUpgradeMu.Unlock()

	go func() {
		logger := slog.Default()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		err := NewManager(logger).upgradeFFmpegForWGC(ctx)
		wgcUpgradeMu.Lock()
		if err != nil {
			wgcUpgradeState = "failed: " + err.Error()
		} else {
			wgcUpgradeState = "done"
		}
		wgcUpgradeMu.Unlock()
		if err != nil {
			logger.Warn("ffmpeg upgrade for Windows Graphics Capture failed", "err", err)
			return
		}
		logger.Info("ffmpeg upgraded: Windows Graphics Capture (gfxcapture) available")
		ffmpegUpdatedMu.Do(func() { close(ffmpegUpdatedCh) })
	}()
}

func (m *Manager) upgradeFFmpegForWGC(ctx context.Context) error {
	dir := BinDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	removeOldFFmpeg(dir)
	newPath := filepath.Join(dir, "ffmpeg-update.exe")
	defer os.Remove(newPath)

	// Only the pinned, hash-checked build: never an unpinned "latest" one.
	if err := m.downloadAndExtractZipEntry(ctx, FFmpegWindows, "/bin/ffmpeg.exe", newPath, "กำลังอัปเดต FFmpeg (WGC)..."); err != nil {
		return err
	}
	if !FFmpegHasFilter(ctx, newPath, "gfxcapture") {
		return errors.New("FFmpeg ที่ดาวน์โหลดมายังไม่มี gfxcapture")
	}
	return replaceFFmpeg(dir, newPath)
}

// replaceFFmpeg swaps in the new binary. A running ffmpeg.exe cannot be overwritten on Windows but
// can be renamed, so the old one is moved aside first and deleted on a later run.
func replaceFFmpeg(dir, newPath string) error {
	dest := filepath.Join(dir, "ffmpeg.exe")
	var old string
	if _, err := os.Stat(dest); err == nil {
		old = filepath.Join(dir, fmt.Sprintf("ffmpeg-old-%d.exe", time.Now().UnixNano()))
		if err := os.Rename(dest, old); err != nil {
			return fmt.Errorf("move old ffmpeg aside: %w", err)
		}
	}
	if err := os.Rename(newPath, dest); err != nil {
		if old != "" {
			_ = os.Rename(old, dest)
		}
		return fmt.Errorf("install new ffmpeg: %w", err)
	}
	if old != "" {
		_ = os.Remove(old) // fails while an old ffmpeg is still running; removed next time
	}
	return nil
}

func removeOldFFmpeg(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "ffmpeg-old-*.exe"))
	for _, p := range matches {
		_ = os.Remove(p)
	}
}

var (
	filterCacheMu sync.Mutex
	filterCache   = map[string]bool{}
)

// FFmpegHasFilter reports whether the ffmpeg binary at path lists the named filter
// (`ffmpeg -filters`). Results are cached per path, size and modification time.
func FFmpegHasFilter(ctx context.Context, path, filter string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	key := fmt.Sprintf("%s|%d|%d|%s", path, info.Size(), info.ModTime().UnixNano(), filter)
	filterCacheMu.Lock()
	v, ok := filterCache[key]
	filterCacheMu.Unlock()
	if ok {
		return v
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, "-hide_banner", "-filters")
	executil.HideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	has := filterListed(string(out), filter)
	filterCacheMu.Lock()
	filterCache[key] = has
	filterCacheMu.Unlock()
	return has
}

// filterListed parses `ffmpeg -filters` output, whose rows look like
// " ... gfxcapture        |->V       Windows Graphics Capture".
func filterListed(out, filter string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == filter {
			return true
		}
	}
	return false
}
