package p2p

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// VPN packet guard.
//
// Every connected peer can send IPv4 packets into this machine's VPN interface, and on Windows
// the firewall lets all of 10.99.0.0/16 in. That is intended for a peer that connected HERE with
// this machine's password. A peer this machine connected TO never proved it knows our password,
// so (unless allow_reverse_access is on) it may only answer conversations this machine started:
// the reply to an RDP, SMB or ping we sent it. New connections it opens are dropped, the same
// rule the screen, shell, file and clipboard streams already follow.
//
// For every peer, a packet must also come from that peer's own VPN address and be addressed to
// ours, so one peer cannot pose as another or use this machine as a router.

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	flowTTLTCP  = 10 * time.Minute
	flowTTLUDP  = 2 * time.Minute
	flowTTLICMP = 30 * time.Second
	flowMax     = 16384
)

// flowKey identifies a conversation from this machine's side: for TCP and UDP our port and the
// peer's port; for ICMP echo the identifier.
type flowKey struct {
	proto  uint8
	local  uint16
	remote uint16
}

// vpnFlowTable remembers conversations this machine started with one peer.
type vpnFlowTable struct {
	mu        sync.Mutex
	flows     map[flowKey]time.Time // key -> expiry
	lastPrune time.Time
}

// ipv4Info is what the guard needs from an IPv4 packet.
type ipv4Info struct {
	src, dst     net.IP
	proto        uint8
	srcPort      uint16 // TCP/UDP
	dstPort      uint16
	icmpType     uint8
	icmpID       uint16
	laterFragmnt bool // a fragment after the first: no transport header
}

func parseIPv4(pkt []byte) (ipv4Info, bool) {
	var in ipv4Info
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return in, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return in, false
	}
	in.src = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).To4()
	in.dst = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).To4()
	in.proto = pkt[9]
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		in.laterFragmnt = true
		return in, true
	}
	l4 := pkt[ihl:]
	switch in.proto {
	case protoTCP, protoUDP:
		if len(l4) < 4 {
			return in, false
		}
		in.srcPort = binary.BigEndian.Uint16(l4[0:2])
		in.dstPort = binary.BigEndian.Uint16(l4[2:4])
	case protoICMP:
		if len(l4) < 8 {
			return in, false
		}
		in.icmpType = l4[0]
		in.icmpID = binary.BigEndian.Uint16(l4[4:6])
	}
	return in, true
}

func flowTTL(proto uint8) time.Duration {
	switch proto {
	case protoTCP:
		return flowTTLTCP
	case protoUDP:
		return flowTTLUDP
	}
	return flowTTLICMP
}

// noteOutbound records (or refreshes) the conversation of a packet this machine sends.
func (t *vpnFlowTable) noteOutbound(pkt []byte, now time.Time) {
	in, ok := parseIPv4(pkt)
	if !ok || in.laterFragmnt {
		return
	}
	var k flowKey
	switch in.proto {
	case protoTCP, protoUDP:
		k = flowKey{proto: in.proto, local: in.srcPort, remote: in.dstPort}
	case protoICMP:
		if in.icmpType != 8 { // only echo requests start a conversation
			return
		}
		k = flowKey{proto: protoICMP, local: in.icmpID}
	default:
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flows == nil {
		t.flows = make(map[flowKey]time.Time)
	}
	if now.Sub(t.lastPrune) > 30*time.Second || len(t.flows) >= flowMax {
		for fk, exp := range t.flows {
			if now.After(exp) {
				delete(t.flows, fk)
			}
		}
		t.lastPrune = now
		if len(t.flows) >= flowMax {
			t.flows = make(map[flowKey]time.Time) // still full of live flows: start over
		}
	}
	t.flows[k] = now.Add(flowTTL(in.proto))
}

// allowReply reports whether an inbound packet belongs to a conversation this machine started.
func (t *vpnFlowTable) allowReply(pkt []byte, now time.Time) bool {
	in, ok := parseIPv4(pkt)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	live := func(k flowKey) bool {
		exp, ok := t.flows[k]
		if !ok || now.After(exp) {
			return false
		}
		t.flows[k] = now.Add(flowTTL(k.proto)) // replies keep the conversation alive too
		return true
	}
	anyLive := func() bool {
		for _, exp := range t.flows {
			if !now.After(exp) {
				return true
			}
		}
		return false
	}
	if in.laterFragmnt {
		return anyLive() // the first fragment was checked; later ones carry no ports
	}
	switch in.proto {
	case protoTCP, protoUDP:
		return live(flowKey{proto: in.proto, local: in.dstPort, remote: in.srcPort})
	case protoICMP:
		switch in.icmpType {
		case 0: // echo reply
			return live(flowKey{proto: protoICMP, local: in.icmpID})
		case 3, 11: // unreachable, time exceeded: about something we sent
			return anyLive()
		}
	}
	return false
}

// acceptVPNPacket decides whether a packet received from peer p may enter this machine's VPN
// interface (see the comment at the top of this file).
func (n *Node) acceptVPNPacket(p *connectedPeer, pkt []byte) bool {
	in, ok := parseIPv4(pkt)
	if !ok {
		return false
	}
	n.mu.RLock()
	ownIP := n.vpnIP
	reverse := n.cfg != nil && n.cfg.AllowReverseAccess
	n.mu.RUnlock()
	peerIP := net.ParseIP(p.vpnIP).To4()
	self := net.ParseIP(ownIP).To4()
	if peerIP == nil || self == nil || !in.src.Equal(peerIP) || !in.dst.Equal(self) {
		return false
	}
	if p.outbound && !reverse {
		return p.vpnFlows.allowReply(pkt, time.Now())
	}
	return true
}
