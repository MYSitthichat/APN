package p2p

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"
)

const lanDiscoveryPort = 44333

// DiscoveredPeer represents another RelayVPN peer spotted on the same LAN/Wi-Fi.
type DiscoveredPeer struct {
	DeviceID    string    `json:"device_id"`
	PeerID      string    `json:"peer_id"`
	Name        string    `json:"name"`
	OS          string    `json:"os"`
	Fingerprint string    `json:"fingerprint"`
	QUICAddr    string    `json:"quic_addr"`
	WSAddr      string    `json:"ws_addr,omitempty"`
	LastSeen    time.Time `json:"last_seen"`
}

type lanBeacon struct {
	Magic       string `json:"m"`
	DeviceID    string `json:"did"`
	PeerID      string `json:"id"`
	Name        string `json:"name"`
	OS          string `json:"os"`
	Fingerprint string `json:"fp"`
	QUICPort    int    `json:"qp"`
	WSPort      int    `json:"wp"`
}

type lanDiscovery struct {
	selfDeviceID string
	selfID       string
	selfName     string
	selfOS       string
	fingerprint  string
	quicPort     int
	wsPort       int

	mu    sync.RWMutex
	peers map[string]DiscoveredPeer
}

func newLANDiscovery(selfDeviceID, selfID, selfName, selfOS, fp string, quicPort, wsPort int) *lanDiscovery {
	return &lanDiscovery{
		selfDeviceID: selfDeviceID,
		selfID:       selfID,
		selfName:     selfName,
		selfOS:       selfOS,
		fingerprint:  fp,
		quicPort:     quicPort,
		wsPort:       wsPort,
		peers:        make(map[string]DiscoveredPeer),
	}
}

func (d *lanDiscovery) start(ctx context.Context) {
	go d.listenLoop(ctx)
	go d.broadcastLoop(ctx)
}

func (d *lanDiscovery) listenLoop(ctx context.Context) {
	pc, err := net.ListenPacket("udp4", ":44333")
	if err != nil {
		// Another local instance already holds the LAN discovery port; degrade gracefully.
		return
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var b lanBeacon
		if err := json.Unmarshal(buf[:n], &b); err != nil || b.Magic != "RVPN-LAN" {
			continue
		}
		if (b.PeerID == "" && b.DeviceID == "") || (b.DeviceID != "" && b.DeviceID == d.selfDeviceID) || b.PeerID == d.selfID {
			continue
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			continue
		}
		// Never learn a peer via RelayVPN's own 10.99.x.x virtual LAN!
		if ip := net.ParseIP(host).To4(); ip != nil && ip[0] == 10 && ip[1] == 99 {
			continue
		}
		dp := DiscoveredPeer{
			DeviceID:    b.DeviceID,
			PeerID:      b.PeerID,
			Name:        b.Name,
			OS:          b.OS,
			Fingerprint: b.Fingerprint,
			LastSeen:    time.Now().UTC(),
		}
		if b.QUICPort > 0 {
			dp.QUICAddr = net.JoinHostPort(host, itoa(b.QUICPort))
		}
		if b.WSPort > 0 {
			dp.WSAddr = net.JoinHostPort(host, itoa(b.WSPort))
		}
		key := b.DeviceID
		if key == "" {
			key = b.PeerID
		}
		d.mu.Lock()
		// If we already discovered this peer on a real physical LAN (192.168.x / 10.x), don't downgrade it to a virtual VPN (26.x)!
		if existing, ok := d.peers[key]; ok {
			exHost, _, _ := net.SplitHostPort(existing.QUICAddr)
			if isPreferredLAN(exHost) && !isPreferredLAN(host) && time.Since(existing.LastSeen) < 10*time.Second {
				d.mu.Unlock()
				continue
			}
		}
		d.peers[key] = dp
		d.mu.Unlock()
	}
}

func (d *lanDiscovery) broadcastLoop(ctx context.Context) {
	payload, _ := json.Marshal(lanBeacon{
		Magic:       "RVPN-LAN",
		DeviceID:    d.selfDeviceID,
		PeerID:      d.selfID,
		Name:        d.selfName,
		OS:          d.selfOS,
		Fingerprint: d.fingerprint,
		QUICPort:    d.quicPort,
		WSPort:      d.wsPort,
	})

	sendAll := func() {
		targets := ifaceBroadcastTargets()
		// Bind a socket to EACH active local IPv4 address so Windows actually emits
		// broadcast packets out of EVERY interface (Wi-Fi, Ethernet, Radmin, etc.).
		for _, t := range targets {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: t.localIP, Port: 0})
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(payload, &net.UDPAddr{IP: t.bcastIP, Port: lanDiscoveryPort})
			_, _ = conn.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4bcast, Port: lanDiscoveryPort})
			_ = conn.Close()
		}
		// Fallback unbound broadcast
		if conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4bcast, Port: lanDiscoveryPort}); err == nil {
			_, _ = conn.Write(payload)
			_ = conn.Close()
		}
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	sendAll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendAll()
			d.pruneStale()
		}
	}
}

type bcastTarget struct {
	localIP net.IP
	bcastIP net.IP
}

func ifaceBroadcastTargets() []bcastTarget {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []bcastTarget
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || (ip4[0] == 10 && ip4[1] == 99) {
				continue
			}
			mask := ipNet.Mask
			if len(mask) != 4 {
				continue
			}
			bcast := net.IPv4(
				ip4[0]|^mask[0],
				ip4[1]|^mask[1],
				ip4[2]|^mask[2],
				ip4[3]|^mask[3],
			)
			out = append(out, bcastTarget{localIP: ip4, bcastIP: bcast})
		}
	}
	return out
}

func isPreferredLAN(host string) bool {
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return false
	}
	return (ip[0] == 192 && ip[1] == 168) || (ip[0] == 10 && ip[1] != 99)
}

func (d *lanDiscovery) pruneStale() {
	cutoff := time.Now().UTC().Add(-12 * time.Second)
	d.mu.Lock()
	for id, p := range d.peers {
		if p.LastSeen.Before(cutoff) {
			delete(d.peers, id)
		}
	}
	d.mu.Unlock()
}

func (d *lanDiscovery) findByDeviceID(deviceID string) (DiscoveredPeer, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if p, ok := d.peers[deviceID]; ok {
		return p, true
	}
	for _, p := range d.peers {
		if p.DeviceID == deviceID || p.PeerID == deviceID {
			return p, true
		}
	}
	return DiscoveredPeer{}, false
}

func (d *lanDiscovery) list() []DiscoveredPeer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]DiscoveredPeer, 0, len(d.peers))
	for _, p := range d.peers {
		out = append(out, p)
	}
	return out
}

func itoa(n int) string {
	return string([]byte(net.JoinHostPort("", "")[:0])) + formatInt(n)
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
