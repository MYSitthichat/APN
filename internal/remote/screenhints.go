package remote

import (
	"os"
	"path/filepath"
	"strings"
)

// Screen hints explain a picture that is black or blank although video is flowing: the host's
// display server or screen state, not the encoder or network, is the cause. Sent in the stats
// report; the viewer turns them into advice.
const (
	hintWayland     = "wayland"       // Linux Wayland session: x11grab sees only an empty XWayland root
	hintWaylandGst  = "wayland_tools" // GNOME Wayland: GStreamer's PipeWire source is not installed
	hintLoginScreen = "login_screen"  // the captured display is the login greeter, nobody is logged in
	hintNoDisplay   = "no_display"    // no monitor connected to any GPU output
	hintDisplayOff  = "display_off"   // every connected monitor is off (DPMS / power saving)
	hintLidClosed   = "lid_closed"    // laptop lid closed
)

// linuxDisplayHints reads monitor and lid state below root ("/" on a real host).
func linuxDisplayHints(root string) []string {
	var hints []string
	conns, _ := filepath.Glob(filepath.Join(root, "sys/class/drm/card*-*"))
	connected, on := 0, 0
	for _, c := range conns {
		if strings.Contains(filepath.Base(c), "Writeback") {
			continue
		}
		if readTrim(filepath.Join(c, "status")) != "connected" {
			continue
		}
		connected++
		dpms := readTrim(filepath.Join(c, "dpms"))
		enabled := readTrim(filepath.Join(c, "enabled"))
		if enabled != "disabled" && (dpms == "" || dpms == "On") {
			on++
		}
	}
	// No connector entries at all says nothing (e.g. NVIDIA without kernel modesetting).
	if len(conns) > 0 && connected == 0 {
		hints = append(hints, hintNoDisplay)
	} else if connected > 0 && on == 0 {
		hints = append(hints, hintDisplayOff)
	}
	lids, _ := filepath.Glob(filepath.Join(root, "proc/acpi/button/lid/*/state"))
	for _, l := range lids {
		if strings.Contains(readTrim(l), "closed") {
			hints = append(hints, hintLidClosed)
			break
		}
	}
	return hints
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
