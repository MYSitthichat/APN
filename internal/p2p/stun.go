package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	stunMagicCookie     uint32 = 0x2112A442
	attrMappedAddr      uint16 = 0x0001
	attrXorMappedAddr   uint16 = 0x0020
)

// DefaultSTUNServers are standard public RFC 5389 STUN endpoints used only to learn
// our own NAT-mapped public UDP IP:Port (no user traffic passes through STUN).
var DefaultSTUNServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
}

// DiscoverPublicAddr queries STUN over the shared quic.Transport UDP socket so the returned
// public IP:Port corresponds to the exact UDP socket used for QUIC hole punching.
func DiscoverPublicAddr(ctx context.Context, tr *quic.Transport, servers []string) (string, error) {
	if tr == nil {
		return "", errors.New("quic transport is nil")
	}
	if len(servers) == 0 {
		servers = DefaultSTUNServers
	}

	var lastErr error
	for _, srv := range servers {
		addr, err := querySTUNOnce(ctx, tr, srv)
		if err == nil && addr != "" {
			return addr, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no STUN servers succeeded")
	}
	return "", lastErr
}

func querySTUNOnce(ctx context.Context, tr *quic.Transport, server string) (string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return "", fmt.Errorf("resolve STUN %s: %w", server, err)
	}

	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return "", err
	}

	// Build 20-byte RFC 5389 Binding Request
	var req [20]byte
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID[:])

	if _, err := tr.WriteTo(req[:], udpAddr); err != nil {
		return "", fmt.Errorf("send STUN to %s: %w", server, err)
	}

	readCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	buf := make([]byte, 1500)
	for {
		n, _, err := tr.ReadNonQUICPacket(readCtx, buf)
		if err != nil {
			return "", fmt.Errorf("read STUN from %s: %w", server, err)
		}
		mapped, ok := parseSTUNResponse(buf[:n], txID)
		if ok {
			return mapped, nil
		}
	}
}

func parseSTUNResponse(pkt []byte, expectedTxID [12]byte) (string, bool) {
	if len(pkt) < 20 {
		return "", false
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if msgType != stunBindingResponse || cookie != stunMagicCookie {
		return "", false
	}
	if !bytes.Equal(pkt[8:20], expectedTxID[:]) {
		return "", false
	}
	if 20+msgLen > len(pkt) {
		return "", false
	}

	attrs := pkt[20 : 20+msgLen]
	var fallbackMapped string
	for len(attrs) >= 4 {
		aType := binary.BigEndian.Uint16(attrs[0:2])
		aLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+aLen > len(attrs) {
			break
		}
		val := attrs[4 : 4+aLen]
		switch aType {
		case attrXorMappedAddr:
			if addr, ok := parseAddrAttr(val, true, expectedTxID); ok {
				return addr, true
			}
		case attrMappedAddr:
			if addr, ok := parseAddrAttr(val, false, expectedTxID); ok {
				fallbackMapped = addr
			}
		}
		// STUN attributes are padded to 4-byte boundaries
		step := 4 + ((aLen + 3) &^ 3)
		if step > len(attrs) {
			break
		}
		attrs = attrs[step:]
	}
	if fallbackMapped != "" {
		return fallbackMapped, true
	}
	return "", false
}

func parseAddrAttr(val []byte, xor bool, txID [12]byte) (string, bool) {
	if len(val) < 8 {
		return "", false
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}

	switch family {
	case 0x01: // IPv4
		ipBytes := make([]byte, 4)
		copy(ipBytes, val[4:8])
		if xor {
			var cookieBytes [4]byte
			binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
			for i := 0; i < 4; i++ {
				ipBytes[i] ^= cookieBytes[i]
			}
		}
		return net.JoinHostPort(net.IP(ipBytes).String(), strconv.Itoa(int(port))), true

	case 0x02: // IPv6
		if len(val) < 20 {
			return "", false
		}
		ipBytes := make([]byte, 16)
		copy(ipBytes, val[4:20])
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:16], txID[:])
			for i := 0; i < 16; i++ {
				ipBytes[i] ^= mask[i]
			}
		}
		return net.JoinHostPort(net.IP(ipBytes).String(), strconv.Itoa(int(port))), true
	}
	return "", false
}

// IsSlowOverlayIP reports whether ip belongs to a tunneled/overlay address range
// that degrades P2P streaming performance (APN's own 10.99/16 VPN subnet, Radmin VPN 26.0.0.0/8,
// Hamachi 25.0.0.0/8, Tailscale/CGNAT overlay 100.64.0.0/10, Windows Teredo 2001:0000::/32,
// 6to4 2002::/16, or IPv6 ULA fc00::/7 virtual NICs).
func IsSlowOverlayIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// APN's own Built-in L3 VPN subnet
		if ip4[0] == 10 && ip4[1] == 99 {
			return true
		}
		// Radmin VPN (26.0.0.0/8) & LogMeIn Hamachi (25.0.0.0/8): double-tunneled virtual VPNs
		// whose relay servers / smaller MTU cause severe remote-desktop stutter if auto-selected.
		if ip4[0] == 26 || ip4[0] == 25 {
			return true
		}
		// Tailscale / Headscale / NetBird / CGNAT overlay (100.64.0.0/10)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		return false
	}
	ip16 := ip.To16()
	if len(ip16) != net.IPv6len {
		return true
	}
	// Teredo tunneling (2001:0000::/32): slow Microsoft/ISP UDP relay, 1280 MTU, severe jitter/loss
	if ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x00 && ip16[3] == 0x00 {
		return true
	}
	// 6to4 (2002::/16): deprecated public relay
	if ip16[0] == 0x20 && ip16[1] == 0x02 {
		return true
	}
	// IPv6 Unique Local Address (fc00::/7, e.g. fdfd:: Radmin/overlay/Hyper-V virtual NICs)
	if ip16[0]&0xfe == 0xfc {
		return true
	}
	return false
}

// isVirtualVPNInterface reports whether a local network interface name belongs to a
// third-party or virtual VPN/tunnel adapter (Radmin VPN, ZeroTier, Tailscale, Hamachi,
// WireGuard, OpenVPN, Wintun, Cloudflare WARP, etc.) that should be excluded from
// automatic LAN discovery broadcasts and candidate UDP advertisement.
func isVirtualVPNInterface(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" {
		return false
	}
	for _, kw := range []string{
		"radmin", "hamachi", "zerotier", "tailscale",
		"wireguard", "wintun", "openvpn", "tap-windows",
		"nordlynx", "cloudflarewarp", "warp", "apn-vpn", "relayvpn",
	} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	for _, pfx := range []string{"zt", "wg", "utun", "tun", "tap", "tailscale"} {
		if strings.HasPrefix(low, pfx) && len(low) > len(pfx) {
			next := low[len(pfx)]
			if next >= '0' && next <= '9' {
				return true
			}
		}
	}
	return false
}

// LocalLANIPs returns usable non-loopback local IPv4 (and native global IPv6) addresses on this device,
// excluding virtual VPN adapters and slow overlay subnets (APN 10.99.x, Radmin 26.x, Hamachi 25.x,
// Tailscale 100.64.x, Teredo/6to4/ULA), and prioritizing physical LANs.
func LocalLANIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var primaryV4, secondaryV4, v6 []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualVPNInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			if IsSlowOverlayIP(ipNet.IP) {
				continue
			}
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				// Prefer physical private LAN subnets (192.168.x.x / 10.x.x.x) first
				if (ip4[0] == 192 && ip4[1] == 168) || ip4[0] == 10 {
					primaryV4 = append(primaryV4, ip4.String())
				} else {
					secondaryV4 = append(secondaryV4, ip4.String())
				}
			} else if ipNet.IP.IsGlobalUnicast() {
				v6 = append(v6, ipNet.IP.String())
			}
		}
	}
	out := append(primaryV4, secondaryV4...)
	return append(out, v6...)
}
