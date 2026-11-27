//go:build linux && capturediag

package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestWaylandToolsInstallDiag runs the real GStreamer auto-install on this machine (as root) and
// waits for it to finish or refuse:
//
//	go test -tags capturediag -run TestWaylandToolsInstallDiag ./internal/bootstrap/
func TestWaylandToolsInstallDiag(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	EnsureWaylandCaptureTools(context.Background(), logger)
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if exec.Command("gst-inspect-1.0", "--exists", "pipewiresrc").Run() == nil {
			t.Log("pipewiresrc is installed")
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Log("pipewiresrc still missing after 3 minutes (install refused or failed: see the log above)")
}
