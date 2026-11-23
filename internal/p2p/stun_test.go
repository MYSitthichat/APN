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
		{"fdfd::1a34:a5f4", true},                     // IPv6 ULA virtual NIC
		{"fc00::1", true},                             // IPv6 ULA
		{"10.99.19.149", true},                        // APN L3 VPN subnet
		{"10.4.88.210", false},                        // Physical LAN IPv4
		{"192.168.1.50", false},                       // Physical LAN IPv4
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
