package remote

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeHintFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, v := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxDisplayHints(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"nothing known", nil, nil},
		{"monitor on", map[string]string{
			"sys/class/drm/card0-HDMI-A-1/status": "connected", "sys/class/drm/card0-HDMI-A-1/dpms": "On", "sys/class/drm/card0-HDMI-A-1/enabled": "enabled",
			"sys/class/drm/card0-DP-1/status": "disconnected", "sys/class/drm/card0-DP-1/dpms": "Off",
		}, nil},
		{"no monitor", map[string]string{
			"sys/class/drm/card0-HDMI-A-1/status": "disconnected", "sys/class/drm/card0-Writeback-1/status": "unknown",
		}, []string{hintNoDisplay}},
		{"monitor asleep", map[string]string{
			"sys/class/drm/card0-HDMI-A-1/status": "connected", "sys/class/drm/card0-HDMI-A-1/dpms": "Off", "sys/class/drm/card0-HDMI-A-1/enabled": "enabled",
		}, []string{hintDisplayOff}},
		{"lid closed, panel disabled", map[string]string{
			"sys/class/drm/card1-eDP-1/status": "connected", "sys/class/drm/card1-eDP-1/dpms": "On", "sys/class/drm/card1-eDP-1/enabled": "disabled",
			"proc/acpi/button/lid/LID0/state": "state:      closed",
		}, []string{hintDisplayOff, hintLidClosed}},
		{"lid closed, external monitor on", map[string]string{
			"sys/class/drm/card1-eDP-1/status": "connected", "sys/class/drm/card1-eDP-1/enabled": "disabled",
			"sys/class/drm/card1-HDMI-A-1/status": "connected", "sys/class/drm/card1-HDMI-A-1/dpms": "On", "sys/class/drm/card1-HDMI-A-1/enabled": "enabled",
			"proc/acpi/button/lid/LID/state": "state:      closed",
		}, []string{hintLidClosed}},
		{"lid open", map[string]string{"proc/acpi/button/lid/LID/state": "state:      open"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeHintFiles(t, root, c.files)
			if got := linuxDisplayHints(root); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
