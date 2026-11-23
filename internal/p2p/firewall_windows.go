//go:build windows

package p2p

import (
	"os"
	"os/exec"
	"strconv"

	"relayvpn/internal/executil"
)

func runNetshHidden(args ...string) {
	cmd := exec.Command("netsh", args...)
	executil.HideWindow(cmd)
	_ = cmd.Run()
}

// ensurePeerFirewallRules best-effort registers Windows Defender Firewall inbound allow rules
// for the currently running APN executable (UDP QUIC + LAN Discovery + optional WS peer port)
// so version upgrades never silently block LAN Discovery or P2P connections.
func ensurePeerFirewallRules(quicPort, wsPort int) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	runNetshHidden("advfirewall", "firewall", "delete", "rule", "name=RelayVPN P2P UDP")
	runNetshHidden("advfirewall", "firewall", "delete", "rule", "name=RelayVPN LAN Discovery")
	runNetshHidden("advfirewall", "firewall", "delete", "rule", "name=RelayVPN P2P WS")

	if quicPort > 0 {
		runNetshHidden("advfirewall", "firewall", "add", "rule",
			"name=RelayVPN P2P UDP",
			"dir=in", "action=allow", "protocol=UDP",
			"localport="+strconv.Itoa(quicPort),
			"program="+exe,
			"profile=any",
		)
	}
	runNetshHidden("advfirewall", "firewall", "add", "rule",
		"name=RelayVPN LAN Discovery",
		"dir=in", "action=allow", "protocol=UDP",
		"localport="+strconv.Itoa(lanDiscoveryPort),
		"program="+exe,
		"profile=any",
	)
	if wsPort > 0 {
		runNetshHidden("advfirewall", "firewall", "add", "rule",
			"name=RelayVPN P2P WS",
			"dir=in", "action=allow", "protocol=TCP",
			"localport="+strconv.Itoa(wsPort),
			"program="+exe,
			"profile=any",
		)
	}
}
