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

var clipToolsOnce sync.Once

// EnsureLinuxClipboardTools installs xclip (and wl-clipboard on Wayland) with apt when APN runs
// as the root System Service and they are missing. APN itself no longer needs them (pure-Go X11
// clipboard), but terminal apps such as AI coding agents read pasted images by calling
// `xclip -t image/png -o` / `wl-paste`, so without them an image copied on Windows cannot be
// pasted into those apps. Runs once per process, in the background, and only via apt as root
// (same policy as the FFmpeg auto-install).
func EnsureLinuxClipboardTools(ctx context.Context, logger *slog.Logger) {
	clipToolsOnce.Do(func() {
		if os.Geteuid() != 0 {
			return
		}
		apt, err := exec.LookPath("apt-get")
		if err != nil {
			return
		}
		var missing []string
		if _, err := exec.LookPath("xclip"); err != nil {
			missing = append(missing, "xclip")
		}
		if _, err := exec.LookPath("wl-paste"); err != nil && waylandSessionPresent() {
			missing = append(missing, "wl-clipboard")
		}
		if len(missing) == 0 {
			return
		}
		go func() {
			ictx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			defer cancel()
			env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			args := append([]string{"install", "-y", "-qq", "--no-install-recommends"}, missing...)
			cmd := exec.CommandContext(ictx, apt, args...)
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				// Package lists may be stale on a fresh machine: refresh once and retry.
				upd := exec.CommandContext(ictx, apt, "update", "-qq")
				upd.Env = env
				_ = upd.Run()
				cmd = exec.CommandContext(ictx, apt, args...)
				cmd.Env = env
				if out2, err2 := cmd.CombinedOutput(); err2 != nil {
					if logger != nil {
						logger.Warn("could not install clipboard tools for pasting images into terminal apps",
							"packages", missing, "err", err2, "output", strings.TrimSpace(string(out)+"\n"+string(out2)))
					}
					return
				}
			}
			if logger != nil {
				logger.Info("installed clipboard tools so terminal apps can paste images", "packages", missing)
			}
		}()
	})
}

func waylandSessionPresent() bool {
	matches, _ := os.ReadDir("/run/user")
	for _, m := range matches {
		if ents, err := os.ReadDir("/run/user/" + m.Name()); err == nil {
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), "wayland-") && !strings.HasSuffix(e.Name(), ".lock") {
					return true
				}
			}
		}
	}
	return false
}
