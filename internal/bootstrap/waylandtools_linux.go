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

var waylandToolPackages = []string{"gstreamer1.0-pipewire", "gstreamer1.0-tools", "gstreamer1.0-plugins-base"}

// EnsureWaylandCaptureTools installs GStreamer's PipeWire source and gst-launch-1.0 with apt when
// APN runs as root and they are missing. APN captures a GNOME Wayland desktop from Mutter's
// PipeWire stream through gst-launch-1.0; without these packages the remote picture stays black.
//
// It only ever adds packages. apt is asked first what it would do (a simulation); if that would
// upgrade or remove anything already installed (gstreamer1.0-pipewire must match the installed
// PipeWire version, so an out-of-date machine would get its PipeWire libraries upgraded), nothing
// is installed and the viewer tells the user the command to run themselves.
// Runs in the background, at most once every 10 minutes.
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
	go func() {
		ictx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		run := func(args ...string) (string, error) {
			cmd := exec.CommandContext(ictx, apt, args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		installArgs := append([]string{"install", "-y", "-qq", "--no-install-recommends"}, waylandToolPackages...)
		simArgs := append([]string{"-s", "install", "--no-install-recommends"}, waylandToolPackages...)

		plan, err := run(simArgs...)
		if err != nil {
			// Package lists may be stale on a fresh machine: refresh them (changes no package) and ask again.
			_, _ = run("update", "-qq")
			if plan, err = run(simArgs...); err != nil {
				if logger != nil {
					logger.Warn("GStreamer PipeWire tools for Wayland screen capture are not installable with apt",
						"packages", waylandToolPackages, "err", err, "output", strings.TrimSpace(plan))
				}
				return
			}
		}
		if changed := aptChangesInstalled(plan); len(changed) > 0 {
			if logger != nil {
				logger.Warn("not installing GStreamer PipeWire tools for Wayland screen capture: apt would also upgrade or remove installed packages",
					"packages", waylandToolPackages, "would_change", changed,
					"install_yourself", "sudo apt install "+strings.Join(waylandToolPackages[:2], " "))
			}
			return
		}
		if !strings.Contains(plan, "Inst ") {
			return // already installed
		}
		if out, err := run(installArgs...); err != nil {
			if logger != nil {
				logger.Warn("could not install GStreamer PipeWire tools for Wayland screen capture",
					"packages", waylandToolPackages, "err", err, "output", strings.TrimSpace(out))
			}
			return
		}
		if logger != nil {
			logger.Info("installed GStreamer PipeWire tools for Wayland screen capture", "packages", waylandToolPackages)
		}
	}()
}

// aptChangesInstalled lists the packages an `apt-get -s` plan would upgrade, downgrade or remove.
// A new package reads "Inst name (version ...)"; one already installed carries its current
// version in brackets: "Inst name [old] (new ...)". "Remv" removes one.
func aptChangesInstalled(plan string) []string {
	var changed []string
	for _, line := range strings.Split(plan, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "Remv", "Purg":
			changed = append(changed, f[1])
		case "Inst":
			if len(f) >= 3 && strings.HasPrefix(f[2], "[") {
				changed = append(changed, f[1])
			}
		}
	}
	return changed
}
