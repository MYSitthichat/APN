package p2p

import (
	"net"
	"testing"
)

func TestIsSlowOverlayIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"2001:0:14c9:d700:cf4:23c3:e47d:942c", true}, // Windows Teredo relay
		{"2002:c000:0201::1", true},                   // 6to4 relay
		{"fdfd::1a34:a5f4", true},                     // IPv6 ULA virtual NIC (Radmin/overlay)
		{"fc00::1", true},                             // IPv6 ULA
		{"10.99.19.149", true},                        // APN L3 VPN subnet
		{"26.142.88.15", true},                        // Radmin VPN IPv4
		{"25.10.20.30", true},                         // LogMeIn Hamachi IPv4
		{"100.64.0.1", true},                          // Tailscale / CGNAT overlay
		{"100.127.255.254", true},                     // Tailscale / CGNAT upper bound
		{"100.128.0.1", false},                        // Public IPv4 outside 100.64.0.0/10
		{"10.4.88.210", false},                        // Physical LAN IPv4
		{"192.168.1.50", false},                       // Physical LAN IPv4
		{"172.16.10.5", false},                        // Private LAN IPv4
		{"147.50.182.237", false},                     // Public STUN IPv4
		{"2403:6200:88a0::1", false},                  // Native ISP global IPv6
	}
	for _, tc := range cases {
		got := IsSlowOverlayIP(net.ParseIP(tc.ip))
		if got != tc.want {
			t.Errorf("IsSlowOverlayIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsVirtualVPNInterface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Radmin VPN", true},
		{"Ethernet 2 (Radmin VPN)", true},
		{"ZeroTier One [abc123]", true},
		{"Tailscale", true},
		{"Hamachi", true},
		{"WireGuard Tunnel", true},
		{"Wintun Userspace Tunnel", true},
		{"APN-VPN", true},
		{"wg0", true},
		{"tun0", true},
		{"utun3", true},
		{"zt0", true},
		{"Ethernet", false},
		{"Wi-Fi", false},
		{"eth0", false},
		{"enp3s0", false},
		{"wlan0", false},
	}
	for _, tc := range cases {
		if got := isVirtualVPNInterface(tc.name); got != tc.want {
			t.Errorf("isVirtualVPNInterface(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
