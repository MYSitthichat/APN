package p2p

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"relayvpn/internal/config"
)

// ipv4Packet builds a minimal IPv4 packet with a TCP/UDP port pair or an ICMP header.
func ipv4Packet(src, dst string, proto uint8, a, b uint16, icmpType uint8) []byte {
	l4len := 8
	if proto == protoTCP {
		l4len = 20
	}
	pkt := make([]byte, 20+l4len)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	l4 := pkt[20:]
	switch proto {
	case protoTCP, protoUDP:
		binary.BigEndian.PutUint16(l4[0:2], a)
		binary.BigEndian.PutUint16(l4[2:4], b)
	case protoICMP:
		l4[0] = icmpType
		binary.BigEndian.PutUint16(l4[4:6], a) // identifier
	}
	return pkt
}

const (
	meIP   = "10.99.10.20"
	peerIP = "10.99.30.40"
)

func guardNode(reverse bool) *Node {
	return &Node{vpnIP: meIP, cfg: &config.PeerConfig{AllowReverseAccess: reverse}}
}

func TestVPNGuardOutboundPeerOnlyReplies(t *testing.T) {
	n := guardNode(false)
	host := &connectedPeer{vpnIP: peerIP, outbound: true} // we connected to it

	// The machine we connected to opens RDP / SMB / SSH to us: refused.
	for _, port := range []uint16{3389, 445, 22, 5432} {
		if n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoTCP, 50000, port, 0)) {
			t.Fatalf("an outbound peer reached our TCP port %d without our password", port)
		}
	}
	if n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoUDP, 50000, 137, 0)) {
		t.Fatal("an outbound peer reached our UDP port 137")
	}
	if n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoICMP, 7, 0, 8)) {
		t.Fatal("an outbound peer's ping request was let in")
	}

	// We open RDP to it: its replies come back; only on that port pair.
	now := time.Now()
	host.vpnFlows.noteOutbound(ipv4Packet(meIP, peerIP, protoTCP, 51515, 3389, 0), now)
	if !n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoTCP, 3389, 51515, 0)) {
		t.Fatal("the reply to our own RDP connection was dropped")
	}
	if n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoTCP, 3389, 445, 0)) {
		t.Fatal("a packet to another port of ours was let in on the back of our RDP connection")
	}
	// Our ping and its reply; ICMP errors about our traffic.
	host.vpnFlows.noteOutbound(ipv4Packet(meIP, peerIP, protoICMP, 99, 0, 8), now)
	if !n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoICMP, 99, 0, 0)) {
		t.Fatal("the reply to our ping was dropped")
	}
	if n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoICMP, 98, 0, 0)) {
		t.Fatal("an echo reply we never asked for was let in")
	}
	if !n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoICMP, 0, 0, 3)) {
		t.Fatal("an ICMP unreachable about our traffic was dropped")
	}
	// UDP (e.g. DNS) replies.
	host.vpnFlows.noteOutbound(ipv4Packet(meIP, peerIP, protoUDP, 40000, 53, 0), now)
	if !n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoUDP, 53, 40000, 0)) {
		t.Fatal("the UDP reply was dropped")
	}

	// Conversations expire.
	expired := &connectedPeer{vpnIP: peerIP, outbound: true}
	expired.vpnFlows.noteOutbound(ipv4Packet(meIP, peerIP, protoUDP, 40001, 53, 0), now.Add(-flowTTLUDP-time.Second))
	if expired.vpnFlows.allowReply(ipv4Packet(peerIP, meIP, protoUDP, 53, 40001, 0), now) {
		t.Fatal("a reply to an expired UDP conversation was let in")
	}
}

func TestVPNGuardReverseAccessAllowsOutboundPeer(t *testing.T) {
	n := guardNode(true)
	host := &connectedPeer{vpnIP: peerIP, outbound: true}
	if !n.acceptVPNPacket(host, ipv4Packet(peerIP, meIP, protoTCP, 50000, 3389, 0)) {
		t.Fatal("allow_reverse_access is on, but the outbound peer was refused")
	}
}

func TestVPNGuardInboundPeerAndAddresses(t *testing.T) {
	n := guardNode(false)
	viewer := &connectedPeer{vpnIP: peerIP, outbound: false} // it connected here with our password
	if !n.acceptVPNPacket(viewer, ipv4Packet(peerIP, meIP, protoTCP, 50000, 3389, 0)) {
		t.Fatal("a peer that authenticated to us could not open RDP over the VPN")
	}
	// Spoofed source, foreign destination, non-IPv4, truncated.
	if n.acceptVPNPacket(viewer, ipv4Packet("10.99.77.77", meIP, protoTCP, 50000, 3389, 0)) {
		t.Fatal("a packet with another machine's source address was let in")
	}
	if n.acceptVPNPacket(viewer, ipv4Packet(peerIP, "10.99.1.1", protoTCP, 50000, 3389, 0)) {
		t.Fatal("a packet for another machine was let in (this machine would act as a router)")
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if n.acceptVPNPacket(viewer, v6) {
		t.Fatal("an IPv6 packet was let in")
	}
	if n.acceptVPNPacket(viewer, ipv4Packet(peerIP, meIP, protoTCP, 1, 2, 0)[:22]) {
		t.Fatal("a truncated packet was let in")
	}
	noIP := &connectedPeer{outbound: false}
	if n.acceptVPNPacket(noIP, ipv4Packet(peerIP, meIP, protoTCP, 50000, 3389, 0)) {
		t.Fatal("a packet from a peer without a VPN address was let in")
	}
}

func TestVPNGuardFragments(t *testing.T) {
	n := guardNode(false)
	host := &connectedPeer{vpnIP: peerIP, outbound: true}
	frag := ipv4Packet(peerIP, meIP, protoUDP, 53, 40000, 0)
	binary.BigEndian.PutUint16(frag[6:8], 185) // fragment offset, no ports in this piece
	if n.acceptVPNPacket(host, frag) {
		t.Fatal("a later fragment was let in with no conversation open")
	}
	host.vpnFlows.noteOutbound(ipv4Packet(meIP, peerIP, protoUDP, 40000, 53, 0), time.Now())
	if !n.acceptVPNPacket(host, frag) {
		t.Fatal("a later fragment of a reply was dropped")
	}
}
