// Package mobile provides gomobile-compatible bindings for building native iOS (.xcframework)
// and Android (.aar) apps with NEPacketTunnelProvider / Android VpnService.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"

	"relayvpn/internal/config"
	"relayvpn/internal/p2p"
	"relayvpn/internal/version"
)

// PacketCallback receives inbound L3 IPv4 packets from remote P2P peers so iOS NEPacketTunnelProvider
// or Android VpnService can inject them into the mobile TUN interface.
type PacketCallback interface {
	OnPacket(pkt []byte)
}

// Engine wraps a RelayVPN P2P Node for iOS Swift / Android Kotlin callers.
type Engine struct {
	mu     sync.Mutex
	node   *p2p.Node
	cancel context.CancelFunc
}

// Version returns the embedded RelayVPN core version string.
func Version() string {
	return version.Version
}

// NewEngine creates a mobile P2P engine storing identity & config inside dataDir.
func NewEngine(dataDir string) (*Engine, error) {
	cfgPath := filepath.Join(dataDir, "peer.json")
	cfg, err := config.LoadJSON[config.PeerConfig](cfgPath)
	if err != nil {
		cfg, err = config.DefaultPeerConfig(dataDir)
		if err != nil {
			return nil, err
		}
		cfg.UIAddr = "" // Native mobile UI drives Engine directly
		cfg.AllowScreen = false
		cfg.AllowInput = false
		cfg.AllowShell = false
		if err := config.SaveJSON(cfgPath, cfg, 0o600); err != nil {
			return nil, err
		}
	}
	node, err := p2p.NewNode(cfg, nil)
	if err != nil {
		return nil, err
	}
	node.SetConfigPath(cfgPath)
	return &Engine{node: node}, nil
}

// Start begins listening for QUIC P2P + STUN discovery.
func (e *Engine) Start(cb PacketCallback) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	if cb != nil {
		e.node.SetPacketSink(func(pkt []byte) {
			cb.OnPacket(pkt)
		})
	}
	if err := e.node.StartAsync(ctx); err != nil {
		cancel()
		return err
	}
	e.cancel = cancel
	return nil
}

// Stop shuts down the mobile P2P engine cleanly.
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel := e.cancel
	e.cancel = nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// MyDeviceID returns this device's 9-digit formatted ID.
func (e *Engine) MyDeviceID() string {
	return p2p.FormatDeviceID(e.node.Snapshot().DeviceID)
}

// MyTempPIN returns the current 6-digit temporary PIN.
func (e *Engine) MyTempPIN() string {
	return e.node.Snapshot().TempPIN
}

// MyVPNIP returns this device's assigned Virtual LAN IPv4 address (10.99.x.y).
func (e *Engine) MyVPNIP() string {
	return e.node.Snapshot().VPN.VPNIP
}

// ConnectSmart connects to a remote peer by 9-digit ID + PIN/Password, Ticket, or WSS URL.
func (e *Engine) ConnectSmart(target, password string) (string, error) {
	info, err := e.node.ConnectSmart(context.Background(), target, password)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(info)
	return string(b), nil
}

// FeedOutboundPacket routes a raw IPv4 packet read from iOS NEPacketTunnelProvider / Android VpnService.
func (e *Engine) FeedOutboundPacket(pkt []byte) error {
	if len(pkt) == 0 {
		return errors.New("empty packet")
	}
	return e.node.InjectOutboundPacket(pkt)
}

// StatusJSON returns the full live peer snapshot as JSON for Swift/Kotlin UI rendering.
func (e *Engine) StatusJSON() string {
	b, _ := json.Marshal(e.node.Snapshot())
	return string(b)
}
