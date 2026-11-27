//go:build linux

package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var waylandToolsMu sync.Mutex
var waylandToolsTried time.Time

// EnsureWaylandCaptureTools installs GStreamer's PipeWire source and gst-launch-1.0 with apt when
// APN runs as root and they are missing. APN captures a GNOME Wayland desktop from Mutter's
// PipeWire stream through gst-launch-1.0; without these two packages the remote picture stays
// black. Runs in the background, at most once every 10 minutes (same policy as the FFmpeg and
// clipboard-tool installs).
func EnsureWaylandCaptureTools(ctx context.Context, logger *slog.Logger) {
	if os.Geteuid() != 0 {
		return
	}
	waylandToolsMu.Lock()
	if !waylandToolsTried.IsZero() && time.Since(waylandToolsTried) < 10*time.Minute {
		waylandToolsMu.Unlock()
		return
	}
	waylandToolsTried = time.Now()
	waylandToolsMu.Unlock()

	apt, err := exec.LookPath("apt-get")
	if err != nil {
		return
	}
	pkgs := []string{"gstreamer1.0-pipewire", "gstreamer1.0-tools", "gstreamer1.0-plugins-base"}
	go func() {
		ictx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		args := append([]string{"install", "-y", "-qq", "--no-install-recommends"}, pkgs...)
		cmd := exec.CommandContext(ictx, apt, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			upd := exec.CommandContext(ictx, apt, "update", "-qq")
			upd.Env = env
			_ = upd.Run()
			cmd = exec.CommandContext(ictx, apt, args...)
			cmd.Env = env
			if out2, err2 := cmd.CombinedOutput(); err2 != nil {
				if logger != nil {
					logger.Warn("could not install GStreamer PipeWire tools for Wayland screen capture",
						"packages", pkgs, "err", err2, "output", strings.TrimSpace(string(out)+"\n"+string(out2)))
				}
				return
			}
		}
		if logger != nil {
			logger.Info("installed GStreamer PipeWire tools for Wayland screen capture", "packages", pkgs)
		}
	}()
}
