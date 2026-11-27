//go:build linux

package bootstrap

import (
	"reflect"
	"testing"
)

func TestAptChangesInstalled(t *testing.T) {
	onlyNew := `NOTE: This is only a simulation!
Reading package lists...
Inst gstreamer1.0-tools (1.24.2-1ubuntu0.1 Ubuntu:24.04/noble-updates [amd64])
Inst gstreamer1.0-pipewire (1.0.5-1ubuntu3 Ubuntu:24.04/noble-updates [amd64])
Conf gstreamer1.0-tools (1.24.2-1ubuntu0.1 Ubuntu:24.04/noble-updates [amd64])
Conf gstreamer1.0-pipewire (1.0.5-1ubuntu3 Ubuntu:24.04/noble-updates [amd64])`
	if got := aptChangesInstalled(onlyNew); len(got) != 0 {
		t.Fatalf("new packages only: got %v, want none", got)
	}

	withUpgrade := onlyNew + `
Inst libpipewire-0.3-0t64 [1.0.5-1ubuntu1] (1.0.5-1ubuntu3 Ubuntu:24.04/noble-updates [amd64])
Inst pipewire-bin [1.0.5-1ubuntu1] (1.0.5-1ubuntu3 Ubuntu:24.04/noble-updates [amd64])
Remv some-conflicting-package [2.0]`
	want := []string{"libpipewire-0.3-0t64", "pipewire-bin", "some-conflicting-package"}
	if got := aptChangesInstalled(withUpgrade); !reflect.DeepEqual(got, want) {
		t.Fatalf("with upgrades: got %v, want %v", got, want)
	}

	if got := aptChangesInstalled("0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n"); len(got) != 0 {
		t.Fatalf("already installed: got %v, want none", got)
	}
}
