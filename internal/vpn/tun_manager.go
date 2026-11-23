package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

const tunPacketOffset = 16

// PacketHandler is called whenever the OS writes an outbound IPv4 packet into the TUN interface.
type PacketHandler func(dstIP string, pkt []byte)

// Manager owns the OS-level L3 Virtual Network Interface (Wintun / /dev/net/tun / utun).
type Manager struct {
	vpnIP   string
	logger  *slog.Logger
	handler PacketHandler

	mu        sync.Mutex
	dev       tun.Device
	ifName    string
	active    bool
	lastError string
	cancel    context.CancelFunc

	txPackets atomic.Int64
	rxPackets atomic.Int64
	txBytes   atomic.Int64
	rxBytes   atomic.Int64
}

// Status summarizes the live L3 VPN interface state for the Web Dashboard.
type Status struct {
	Enabled   bool   `json:"enabled"`
	VPNIP     string `json:"vpn_ip"`
	Subnet    string `json:"subnet"`
	Interface string `json:"interface,omitempty"`
	LastError string `json:"last_error,omitempty"`
	TXPackets int64  `json:"tx_packets"`
	RXPackets int64  `json:"rx_packets"`
	TXBytes   int64  `json:"tx_bytes"`
	RXBytes   int64  `json:"rx_bytes"`
}

// NewManager creates an L3 VPN TUN manager bound to vpnIP (e.g. "10.99.48.29").
func NewManager(vpnIP string, handler PacketHandler, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		vpnIP:   vpnIP,
		handler: handler,
		logger:  logger,
	}
}

// Start creates and configures the OS TUN virtual network adapter and starts reading packets.
func (m *Manager) Start(parentCtx context.Context) error {
	m.mu.Lock()
	if m.active {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	if err := preflightTUN(); err != nil {
		m.setError(err.Error())
		return err
	}

	dev, err := tun.CreateTUN(defaultTUNName(), DefaultMTU)
	if err != nil {
		friendly := formatTUNError(err)
		m.setError(friendly)
		return errors.New(friendly)
	}

	realName, err := dev.Name()
	if err != nil || realName == "" {
		realName = defaultTUNName()
	}

	if err := configureInterfaceIP(realName, m.vpnIP, DefaultMTU); err != nil {
		_ = dev.Close()
		friendly := fmt.Sprintf("สร้างการ์ดแลน %s สำเร็จ แต่ตั้งค่า IP %s ไม่สำเร็จ (ต้องรันสิทธิ์ Admin/sudo): %v", realName, m.vpnIP, err)
		m.setError(friendly)
		return errors.New(friendly)
	}

	ctx, cancel := context.WithCancel(parentCtx)

	m.mu.Lock()
	m.dev = dev
	m.ifName = realName
	m.active = true
	m.lastError = ""
	m.cancel = cancel
	m.mu.Unlock()

	m.logger.Info("L3 VPN virtual interface up", "iface", realName, "ip", m.vpnIP+"/16", "mtu", DefaultMTU)
	go m.readLoop(ctx, dev)
	return nil
}

// Stop tears down the virtual network interface cleanly.
func (m *Manager) Stop() {
	m.mu.Lock()
	dev := m.dev
	cancel := m.cancel
	m.dev = nil
	m.cancel = nil
	m.active = false
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if dev != nil {
		_ = dev.Close()
	}
}

// InjectPacket writes an inbound IPv4 packet received from a remote peer into the local OS TUN adapter.
func (m *Manager) InjectPacket(pkt []byte) error {
	m.mu.Lock()
	dev := m.dev
	active := m.active
	m.mu.Unlock()
	if !active || dev == nil {
		return errors.New("L3 VPN interface is not active")
	}

	buf := make([]byte, tunPacketOffset+len(pkt))
	copy(buf[tunPacketOffset:], pkt)
	_, err := dev.Write([][]byte{buf}, tunPacketOffset)
	if err == nil {
		m.rxPackets.Add(1)
		m.rxBytes.Add(int64(len(pkt)))
	}
	return err
}

func (m *Manager) readLoop(ctx context.Context, dev tun.Device) {
	batch := dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	if batch > 32 {
		batch = 32
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunPacketOffset+DefaultMTU+128)
	}

	for ctx.Err() == nil {
		n, err := dev.Read(bufs, sizes, tunPacketOffset)
		if err != nil {
			if ctx.Err() == nil {
				m.logger.Warn("TUN read loop stopped", "err", err)
			}
			return
		}
		for i := 0; i < n; i++ {
			sz := sizes[i]
			if sz <= 0 {
				continue
			}
			pkt := bufs[i][tunPacketOffset : tunPacketOffset+sz]
			dstIP, ok := ExtractIPv4Dst(pkt)
			if !ok {
				continue
			}
			m.txPackets.Add(1)
			m.txBytes.Add(int64(sz))
			if m.handler != nil {
				// Copy slice before dispatching so buffer reuse never races
				pktCopy := append([]byte(nil), pkt...)
				m.handler(dstIP, pktCopy)
			}
		}
	}
}

func (m *Manager) setError(msg string) {
	m.mu.Lock()
	m.lastError = msg
	m.mu.Unlock()
}

// Status returns live L3 VPN interface status & packet counters.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Enabled:   m.active,
		VPNIP:     m.vpnIP,
		Subnet:    "10.99.0.0/16",
		Interface: m.ifName,
		LastError: m.lastError,
		TXPackets: m.txPackets.Load(),
		RXPackets: m.rxPackets.Load(),
		TXBytes:   m.txBytes.Load(),
		RXBytes:   m.rxBytes.Load(),
	}
}
