package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/config"
	"relayvpn/internal/installer"
	"relayvpn/internal/protocol"
	"relayvpn/internal/remote"
	"relayvpn/internal/rendezvous"
	"relayvpn/internal/security"
	"relayvpn/internal/updater"
	"relayvpn/internal/version"
	"relayvpn/internal/vpn"
)

type peerHello struct {
	DeviceID     string                     `json:"device_id,omitempty"`
	PeerID       string                     `json:"peer_id"`
	Name         string                     `json:"name"`
	OS           string                     `json:"os"`
	Version      string                     `json:"version,omitempty"`
	VPNIP        string                     `json:"vpn_ip,omitempty"`
	Fingerprint  string                     `json:"fingerprint"`
	PairSecret   string                     `json:"pair_secret,omitempty"`
	UDPAddrs     []string                   `json:"udp_addrs,omitempty"`
	Targets      []protocol.TargetInfo      `json:"targets,omitempty"`
	Capabilities protocol.AgentCapabilities `json:"capabilities"`
}

type peerHelloResponse struct {
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	Peer  peerHello `json:"peer"`
}

type connectedPeer struct {
	deviceID     string
	id           string
	name         string
	osInfo       string
	appVersion   string
	vpnIP        string
	fingerprint  string
	remoteAddr   string
	transport    string
	connectedAt  time.Time
	targets      []protocol.TargetInfo
	capabilities protocol.AgentCapabilities
	session      MuxSession
	cancel       context.CancelFunc
	activeConns  atomic.Int64
	// outbound is true when this machine started the connection (it authenticated to the other
	// side, not the other way round). Such peers get no access to this machine by default.
	outbound bool
	// vpnFlows: VPN conversations this machine started with the peer. For an outbound peer only
	// their replies may enter the VPN interface (vpn_guard.go).
	vpnFlows vpnFlowTable

	tunMu     sync.Mutex
	tunStream io.ReadWriteCloser
}

// PeerInfo summarizes an active P2P neighbor (who can both be controlled and control us).
type PeerInfo struct {
	DeviceID     string                     `json:"device_id"`
	ID           string                     `json:"id"`
	Name         string                     `json:"name"`
	OS           string                     `json:"os"`
	Version      string                     `json:"version,omitempty"`
	VPNIP        string                     `json:"vpn_ip,omitempty"`
	Fingerprint  string                     `json:"fingerprint"`
	RemoteAddr   string                     `json:"remote_addr"`
	Transport    string                     `json:"transport"`
	ConnectedAt  time.Time                  `json:"connected_at"`
	Targets      []protocol.TargetInfo      `json:"targets"`
	Capabilities protocol.AgentCapabilities `json:"capabilities"`
	ActiveConns  int64                      `json:"active_conns"`
}

// ApprovalTimeout is how long an incoming request waits for the owner before it is refused.
const ApprovalTimeout = 35 * time.Second

// PendingApproval represents an incoming connection waiting for the host owner to Accept or Reject.
type PendingApproval struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	PeerID      string    `json:"peer_id"`
	Name        string    `json:"name"`
	OS          string    `json:"os"`
	RemoteAddr  string    `json:"remote_addr"`
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type approvalWaiter struct {
	info PendingApproval
	ch   chan bool
}

// ActiveSession tracks a live incoming remote session served by this node.
type ActiveSession struct {
	ID         string    `json:"id"`
	PeerID     string    `json:"peer_id"`
	TargetAddr string    `json:"target_addr"`
	StartedAt  time.Time `json:"started_at"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
}

type liveSession struct {
	id         string
	peerID     string
	targetAddr string
	startedAt  time.Time
	sent       atomic.Int64
	recv       atomic.Int64
	closeFn    func()
}

// TunnelStatus describes a local TCP port-forward mapped to a connected P2P peer.
type TunnelStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LocalAddr   string `json:"local_addr"`
	PeerID      string `json:"peer_id"`
	TargetAddr  string `json:"target_addr"`
	Running     bool   `json:"running"`
	LastError   string `json:"last_error,omitempty"`
	ActiveConns int64  `json:"active_conns"`
	BytesSent   int64  `json:"bytes_sent"`
	BytesRecv   int64  `json:"bytes_recv"`
}

type managedTunnel struct {
	id         string
	name       string
	localAddr  string
	peerID     string
	targetAddr string

	mu        sync.Mutex
	running   bool
	lastError string
	listener  net.Listener

	activeConns atomic.Int64
	bytesSent   atomic.Int64
	bytesRecv   atomic.Int64
}

// SavedPeerInfo exposes a remembered peer in history with live online/connected status (never exposes plaintext password).
type SavedPeerInfo struct {
	DeviceID         string `json:"device_id"`
	Name             string `json:"name"`
	Group            string `json:"group,omitempty"`
	OS               string `json:"os,omitempty"`
	Version          string `json:"version,omitempty"`
	VPNIP            string `json:"vpn_ip,omitempty"`
	Online           bool   `json:"online"`
	Connected        bool   `json:"connected"`
	OnlineVia        string `json:"online_via,omitempty"` // "connected", "lan", "cloud", ""
	HasSavedPassword bool   `json:"has_saved_password"`
	LastConnected    string `json:"last_connected,omitempty"`
}

// ProbeResult summarizes target reachability and metadata before prompting for a password.
// It never performs an empty-password auth handshake, so it cannot trigger host rate limits.
type ProbeResult struct {
	Target           string    `json:"target"`
	Kind             string    `json:"kind"` // "id", "direct", "ticket"
	DeviceID         string    `json:"device_id,omitempty"`
	Name             string    `json:"name,omitempty"`
	OS               string    `json:"os,omitempty"`
	Reachable        bool      `json:"reachable"`
	Via              string    `json:"via,omitempty"` // "connected", "lan", "cloud", "direct", "known", "ticket"
	AlreadyConnected bool      `json:"already_connected"`
	Peer             *PeerInfo `json:"peer,omitempty"`
	HasSavedPassword bool      `json:"has_saved_password"`
	Message          string    `json:"message,omitempty"`
}

type peerPresence struct {
	online    bool
	name      string
	osInfo    string
	checkedAt time.Time
}

// NodeSnapshot exposes the complete live state of a Unified P2P Peer for the Web Dashboard.
type NodeSnapshot struct {
	DeviceID             string                     `json:"device_id"`
	TempPIN              string                     `json:"temp_pin"`
	HasPermanentPassword bool                       `json:"has_permanent_password"`
	RequireApproval      bool                       `json:"require_approval"`
	RendezvousURL        string                     `json:"rendezvous_url,omitempty"`
	RendezvousStatus     string                     `json:"rendezvous_status,omitempty"`
	PeerID               string                     `json:"peer_id"`
	Name                 string                     `json:"name"`
	OS                   string                     `json:"os"`
	Fingerprint          string                     `json:"fingerprint"`
	PairSecret           string                     `json:"-"`
	QUICListenAddr       string                     `json:"quic_listen_addr"`
	WSListenAddr         string                     `json:"ws_listen_addr"`
	PublicUDPAddr        string                     `json:"public_udp_addr,omitempty"`
	STUNError            string                     `json:"stun_error,omitempty"`
	PublicWSURL          string                     `json:"public_ws_url,omitempty"`
	Ticket               string                     `json:"ticket"`
	Paused               bool                       `json:"paused"`
	VPN                  vpn.Status                 `json:"vpn"`
	Bridge               BridgeStatus               `json:"bridge"`
	Deps                 bootstrap.Status           `json:"deps"`
	Install              installer.Status           `json:"install"`
	Update               updater.Status             `json:"update"`
	Capabilities         protocol.AgentCapabilities `json:"capabilities"`
	AllowedTargets       []config.AllowedTarget     `json:"allowed_targets"`
	PendingApprovals     []PendingApproval          `json:"pending_approvals"`
	ConnectedPeers       []PeerInfo                 `json:"connected_peers"`
	SavedPeers           []SavedPeerInfo            `json:"saved_peers"`
	Account              AccountStatus              `json:"account"`
	DiscoveredPeers      []DiscoveredPeer           `json:"discovered_peers"`
	ActiveSessions       []ActiveSession            `json:"active_sessions"`
	Tunnels              []TunnelStatus             `json:"tunnels"`
	TotalBytesSent       int64                      `json:"total_bytes_sent"`
	TotalBytesRecv       int64                      `json:"total_bytes_recv"`
}

// Node is a serverless P2P peer that acts simultaneously as Host and Client.
type Node struct {
	cfg        *config.PeerConfig
	configPath string
	logger     *slog.Logger
	identity   *PeerIdentity

	quicTr       *quic.Transport
	quicListener *quic.Listener
	quicPort     int
	quicAddrStr  string

	wsServer  *http.Server
	wsPort    int
	wsAddrStr string

	lanDisc *lanDiscovery
	vpnMgr  *vpn.Manager
	depsMgr *bootstrap.Manager
	bridge  *internetBridge
	updMgr  *updater.Manager

	mu               sync.RWMutex
	onQuit           func()
	onApproval       func(PendingApproval)
	tempPIN          string
	vpnIP            string
	packetSink       func([]byte)
	publicUDPAddr    string
	stunErr          string
	publicWSURL      string
	rendezvousURL    string
	rendezvousStatus string
	paused           bool
	peers            map[string]*connectedPeer
	presence         map[string]peerPresence
	approvals        map[string]*approvalWaiter
	authLimit        *authLimiter
	sessions         map[string]*liveSession
	tunnels          map[string]*managedTunnel
	tunnelOrder      []string

	// Account sign-in (account.go). accountSyncMu lets one sync run at a time; accountKick
	// wakes the sync loop after a config change; accountQuiet (guarded by mu) mutes that wake-up
	// while the sync itself saves the config.
	accountSyncMu sync.Mutex
	accountKick   chan struct{}
	accountQuiet  bool
	accountStatMu sync.Mutex
	accountStat   accountRuntime

	rdvClient *http.Client
	rootCtx   context.Context
	seq       atomic.Uint64
	tunSeq    atomic.Uint64
	appSeq    atomic.Uint64
	totalSent atomic.Int64
	totalRecv atomic.Int64
}

// NewNode constructs a new Unified P2P Node.
func NewNode(cfg *config.PeerConfig, logger *slog.Logger) (*Node, error) {
	if cfg == nil {
		return nil, errors.New("peer config is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DeviceID == "" {
		id, err := security.GenerateDigits(9, true)
		if err != nil {
			return nil, err
		}
		cfg.DeviceID = id
	}
	if cfg.PairSecret == "" {
		sec, err := security.GenerateToken(18)
		if err != nil {
			return nil, err
		}
		cfg.PairSecret = sec
	}
	pin, err := security.GenerateDigits(6, false)
	if err != nil {
		return nil, err
	}
	id, err := LoadOrCreateIdentity(cfg.CertFile, cfg.KeyFile, cfg.PeerID)
	if err != nil {
		return nil, err
	}
	vpnIP := strings.TrimSpace(cfg.VPNIP)
	if vpnIP == "" {
		vpnIP = vpn.DeriveVPNIP(cfg.DeviceID)
		cfg.VPNIP = vpnIP
	}
	rdvURL := strings.TrimRight(strings.TrimSpace(cfg.RendezvousURL), "/")
	if rdvURL == "" && config.DefaultRendezvousURL != "" {
		rdvURL = strings.TrimRight(strings.TrimSpace(config.DefaultRendezvousURL), "/")
		cfg.RendezvousURL = rdvURL
	}
	// Never reuse a stale ephemeral trycloudflare.com URL persisted from an older run (causes HTTP 530!).
	initialWSURL := strings.TrimSpace(cfg.PublicWSURL)
	if strings.Contains(strings.ToLower(initialWSURL), ".trycloudflare.com") {
		initialWSURL = ""
		cfg.PublicWSURL = ""
	}
	node := &Node{
		cfg:           cfg,
		logger:        logger,
		identity:      id,
		tempPIN:       pin,
		vpnIP:         vpnIP,
		publicWSURL:   initialWSURL,
		rendezvousURL: rdvURL,
		peers:         make(map[string]*connectedPeer),
		presence:      make(map[string]peerPresence),
		approvals:     make(map[string]*approvalWaiter),
		authLimit:     newAuthLimiter(),
		sessions:      make(map[string]*liveSession),
		tunnels:       make(map[string]*managedTunnel),
		accountKick:   make(chan struct{}, 1),
		rdvClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext:     resilientDialContext,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			},
		},
	}
	node.vpnMgr = vpn.NewManager(vpnIP, node.routeOutboundIPPacket, logger)
	node.depsMgr = bootstrap.NewManager(logger)
	updURL := ""
	if rdvURL != "" {
		updURL = rdvURL + "/api/releases/latest"
	}
	node.updMgr = updater.NewManager(updURL, node.rdvClient)
	node.bridge = newInternetBridge(logger, func(u string) {
		node.SetPublicWSURL(u)
	})
	node.depsMgr.SetOnReady(func() {
		remote.WarmupH264Encoder()
		if node.cfg.EnableBridge && node.rootCtx != nil && node.wsPort > 0 {
			_ = node.bridge.Start(node.rootCtx, node.wsPort)
		}
	})
	return node, nil
}

// SetBridgeEnabled starts or stops the built-in zero-VPS Port 443 Internet Bridge (cloudflared).
func (n *Node) SetBridgeEnabled(enable bool) error {
	n.mu.Lock()
	n.cfg.EnableBridge = enable
	n.persistConfigLocked()
	n.mu.Unlock()
	if !enable {
		n.bridge.Stop()
		return nil
	}
	ctx := n.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := bootstrap.FindCloudflared(); !ok {
		n.depsMgr.StartAutoInstall(ctx)
	}
	return n.bridge.Start(ctx, n.wsPort)
}

// SetOnQuit registers the callback invoked when the user clicks Quit or when auto-update restarts APN.
func (n *Node) SetOnQuit(fn func()) {
	n.mu.Lock()
	n.onQuit = fn
	n.mu.Unlock()
}

// SetOnApprovalRequest registers a callback run (in its own goroutine) whenever a device asks for
// the owner's approval, e.g. to pop the APN window to the front like AnyDesk.
func (n *Node) SetOnApprovalRequest(fn func(PendingApproval)) {
	n.mu.Lock()
	n.onApproval = fn
	n.mu.Unlock()
}

// PendingApprovals lists the connection requests waiting for the owner, oldest first.
func (n *Node) PendingApprovals() []PendingApproval {
	n.mu.RLock()
	out := make([]PendingApproval, 0, len(n.approvals))
	for _, w := range n.approvals {
		out = append(out, w.info)
	}
	n.mu.RUnlock()
	slices.SortFunc(out, func(a, b PendingApproval) int { return a.RequestedAt.Compare(b.RequestedAt) })
	return out
}

// RequestQuit triggers a graceful shutdown of the APN process.
func (n *Node) RequestQuit() {
	n.mu.RLock()
	fn := n.onQuit
	n.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// CheckUpdate checks the release manifest for a newer APN version.
func (n *Node) CheckUpdate(ctx context.Context) updater.Status {
	if n.updMgr == nil {
		return updater.Status{}
	}
	return n.updMgr.Check(ctx)
}

// ApplyUpdate downloads, verifies, and installs the newer APN binary in place, then restarts APN.
func (n *Node) ApplyUpdate(ctx context.Context) error {
	if n.updMgr == nil {
		return errors.New("updater not configured")
	}
	return n.updMgr.Apply(ctx, n.RequestQuit)
}

// StartAutoDeps installs missing runtime dependencies (wintun.dll + stable ffmpeg.exe) in the background.
func (n *Node) StartAutoDeps(ctx context.Context) bool {
	if bootstrap.HasFFmpeg() {
		remote.WarmupH264Encoder()
	}
	bootstrap.EnsureLinuxClipboardTools(ctx, n.logger)
	if n.depsMgr == nil {
		return false
	}
	return n.depsMgr.StartAutoInstall(ctx)
}

// SetConfigPath enables persisting permanent password, approval mode, and rendezvous settings to peer.json.
func (n *Node) SetConfigPath(path string) {
	n.mu.Lock()
	n.configPath = path
	n.mu.Unlock()
}

// SetRendezvousHTTPClient overrides the HTTP client used for Rendezvous API calls (useful for private CA tests).
func (n *Node) SetRendezvousHTTPClient(hc *http.Client) {
	n.mu.Lock()
	n.rdvClient = hc
	n.mu.Unlock()
}

func (n *Node) persistConfigLocked() {
	n.kickAccountSync()
	if n.configPath == "" {
		return
	}
	_ = config.SaveJSON(n.configPath, n.cfg, 0o600)
}

// StartAsync binds QUIC UDP + WS Peer listeners, runs STUN discovery, LAN discovery, and Rendezvous sync.
func (n *Node) StartAsync(ctx context.Context) error {
	n.rootCtx = ctx

	quicBind := n.cfg.QUICAddr
	if quicBind == "" {
		quicBind = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", quicBind)
	if err != nil {
		return fmt.Errorf("resolve quic_addr %s: %w", quicBind, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", quicBind, err)
	}
	// Enlarge OS UDP buffers (Windows default is only 64 KB!) so 60 FPS H.264 keyframes/bursts
	// NEVER overflow the socket buffer and trigger QUIC packet loss or congestion stalls!
	for _, sz := range []int{7 << 20, 4 << 20, 2 << 20, 1 << 20} {
		if udpConn.SetReadBuffer(sz) == nil {
			break
		}
	}
	for _, sz := range []int{7 << 20, 4 << 20, 2 << 20, 1 << 20} {
		if udpConn.SetWriteBuffer(sz) == nil {
			break
		}
	}

	n.quicTr = &quic.Transport{Conn: udpConn}
	n.quicAddrStr = udpConn.LocalAddr().String()
	if ua, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		n.quicPort = ua.Port
	}

	quicLn, err := n.quicTr.Listen(n.identity.ServerTLSConfig(), defaultQUICConfig())
	if err != nil {
		_ = n.quicTr.Close()
		return fmt.Errorf("quic listen: %w", err)
	}
	n.quicListener = quicLn
	n.logger.Info("p2p peer ready (AnyDesk/RustDesk mode)", "device_id", FormatDeviceID(n.cfg.DeviceID), "pin", n.tempPIN, "quic", n.quicAddrStr)

	if n.cfg.WSAddr != "" {
		ln, err := net.Listen("tcp", n.cfg.WSAddr)
		if err != nil {
			_ = quicLn.Close()
			_ = n.quicTr.Close()
			return fmt.Errorf("listen ws_addr %s: %w", n.cfg.WSAddr, err)
		}
		n.wsAddrStr = ln.Addr().String()
		if ta, ok := ln.Addr().(*net.TCPAddr); ok {
			n.wsPort = ta.Port
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /ws/peer", n.handleIncomingWS)
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		n.wsServer = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := n.wsServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				n.logger.Warn("p2p ws listener error", "err", err)
			}
		}()
	}

	go n.acceptQUICLoop(ctx)

	go func() {
		stunCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		_, _ = n.RefreshSTUN(stunCtx)
	}()

	if n.cfg.EnableLANDisc {
		n.lanDisc = newLANDiscovery(
			n.cfg.DeviceID,
			n.cfg.PeerID,
			n.cfg.Name,
			fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			n.identity.Fingerprint,
			n.quicPort,
			n.wsPort,
		)
		n.lanDisc.start(ctx)
	}

	go ensurePeerFirewallRules(n.quicPort, n.wsPort)

	go n.rendezvousSyncLoop(ctx)
	go n.presenceLoop(ctx)
	go n.accountLoop(ctx)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
			n.CheckUpdate(ctx)
		}
	}()

	if n.cfg.EnableVPN {
		if err := n.vpnMgr.Start(ctx); err != nil {
			n.logger.Warn("auto-start L3 VPN skipped", "err", err)
		}
	}

	if n.cfg.EnableBridge && n.wsPort > 0 {
		_ = n.bridge.Start(ctx, n.wsPort)
	}

	go func() {
		<-ctx.Done()
		n.shutdown()
	}()

	return nil
}

// SetVPNEnabled starts or stops the OS-level L3 Virtual Network Interface (Wintun / TUN / utun).
func (n *Node) SetVPNEnabled(enable bool) error {
	if enable {
		ctx := n.rootCtx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := n.vpnMgr.Start(ctx); err != nil {
			return err
		}
	} else {
		n.vpnMgr.Stop()
	}
	n.mu.Lock()
	n.cfg.EnableVPN = enable
	n.persistConfigLocked()
	n.mu.Unlock()
	return nil
}

// SetPacketSink registers an optional inbound L3 IPv4 packet callback (used by mobile VPN extensions & tests).
func (n *Node) SetPacketSink(fn func([]byte)) {
	n.mu.Lock()
	n.packetSink = fn
	n.mu.Unlock()
}

// InjectOutboundPacket routes a raw outbound IPv4 packet to the connected peer matching its destination VPN IP.
func (n *Node) InjectOutboundPacket(pkt []byte) error {
	dstIP, ok := vpn.ExtractIPv4Dst(pkt)
	if !ok {
		return errors.New("packet is not IPv4")
	}
	return n.routeOutboundIPPacketErr(dstIP, pkt)
}

func (n *Node) routeOutboundIPPacket(dstIP string, pkt []byte) {
	_ = n.routeOutboundIPPacketErr(dstIP, pkt)
}

func (n *Node) routeOutboundIPPacketErr(dstIP string, pkt []byte) error {
	n.mu.RLock()
	var target *connectedPeer
	for _, p := range n.peers {
		if p.vpnIP == dstIP {
			target = p
			break
		}
	}
	n.mu.RUnlock()
	if target == nil {
		return fmt.Errorf("no connected peer owns VPN IP %s", dstIP)
	}
	if target.outbound {
		target.vpnFlows.noteOutbound(pkt, time.Now())
	}

	// Fast path: send L3 IPv4 packet as an RFC 9221 QUIC Unreliable Datagram (zero Head-of-Line Blocking, WireGuard-like!)
	if target.session.SupportsDatagrams() {
		if err := target.session.SendDatagram(pkt); err == nil {
			n.totalSent.Add(int64(len(pkt)))
			return nil
		}
	}

	// Fallback path (WebSocket/TCP 443 or oversized packet): use persistent ModeTUN stream.
	target.tunMu.Lock()
	defer target.tunMu.Unlock()

	if target.tunStream == nil {
		ctx := n.rootCtx
		if ctx == nil {
			ctx = context.Background()
		}
		openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := target.session.OpenStream(openCtx)
		cancel()
		if err != nil {
			return err
		}
		if err := protocol.WriteMessage(st, protocol.StreamOpenRequest{Mode: protocol.ModeTUN}); err != nil {
			_ = st.Close()
			return err
		}
		var resp protocol.StreamOpenResponse
		if err := protocol.ReadMessage(st, &resp); err != nil {
			_ = st.Close()
			return err
		}
		if !resp.OK {
			_ = st.Close()
			return errors.New(resp.Error)
		}
		target.tunStream = st
	}

	if err := vpn.WriteIPPacket(target.tunStream, pkt); err != nil {
		_ = target.tunStream.Close()
		target.tunStream = nil
		return err
	}
	n.totalSent.Add(int64(len(pkt)))
	return nil
}

// Run starts the P2P node and blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	if err := n.StartAsync(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func (n *Node) shutdown() {
	n.unregisterFromRendezvous()
	if n.bridge != nil {
		n.bridge.Stop()
	}
	if n.vpnMgr != nil {
		n.vpnMgr.Stop()
	}
	if n.wsServer != nil {
		shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = n.wsServer.Shutdown(shCtx)
		cancel()
	}
	if n.quicListener != nil {
		_ = n.quicListener.Close()
	}
	if n.quicTr != nil {
		_ = n.quicTr.Close()
	}
	n.stopAllTunnels()

	n.mu.Lock()
	for id, w := range n.approvals {
		select {
		case w.ch <- false:
		default:
		}
		delete(n.approvals, id)
	}
	for id, p := range n.peers {
		p.cancel()
		_ = p.session.Close()
		delete(n.peers, id)
	}
	n.mu.Unlock()
}

// RotateTempPIN generates a fresh random 6-digit temporary PIN.
func (n *Node) RotateTempPIN() (string, error) {
	pin, err := security.GenerateDigits(6, false)
	if err != nil {
		return "", err
	}
	n.mu.Lock()
	n.tempPIN = pin
	n.mu.Unlock()
	return pin, nil
}

// SetPermanentPassword sets (or clears, if empty) the salted SHA-256 permanent password and persists peer.json.
func (n *Node) SetPermanentPassword(raw string) error {
	raw = strings.TrimSpace(raw)
	var hashed string
	if raw != "" {
		if len(raw) < 4 {
			return errors.New("รหัสผ่านถาวรต้องมีอย่างน้อย 4 ตัวอักษร")
		}
		var err error
		hashed, err = security.HashPassword(raw)
		if err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.cfg.PermanentPasswordHash = hashed
	n.persistConfigLocked()
	n.mu.Unlock()
	return nil
}

// SetRequireApproval toggles interactive Accept/Reject confirmation on incoming connections.
func (n *Node) SetRequireApproval(req bool) {
	n.mu.Lock()
	n.cfg.RequireApproval = req
	n.persistConfigLocked()
	n.mu.Unlock()
}

// ResolveApproval approves or rejects a pending incoming peer connection request.
func (n *Node) ResolveApproval(reqID string, allow bool) error {
	n.mu.Lock()
	w, ok := n.approvals[reqID]
	if ok {
		delete(n.approvals, reqID)
	}
	n.mu.Unlock()
	if !ok {
		return errors.New("approval request not found or expired")
	}
	select {
	case w.ch <- allow:
	default:
	}
	return nil
}

// SetRendezvousURL sets the optional Rendezvous directory URL for 9-digit internet ID lookup.
func (n *Node) SetRendezvousURL(raw string) {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	n.mu.Lock()
	n.rendezvousURL = u
	n.cfg.RendezvousURL = u
	if u == "" {
		n.rendezvousStatus = ""
	}
	n.persistConfigLocked()
	n.mu.Unlock()
	if u != "" && n.rootCtx != nil {
		go n.registerWithRendezvous(n.rootCtx)
	}
}

// rendezvousHeartbeat is how often a device re-registers and polls presence. Each poll is a
// Worker request (Cloudflare free tier: 100k/day), so 30s keeps about twice as many devices
// within the quota as 15s did. Entries expire after the Worker's 5-minute TTL.
const rendezvousHeartbeat = 30 * time.Second

func (n *Node) rendezvousSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(rendezvousHeartbeat)
	defer ticker.Stop()

	// Brief initial wait to let STUN discover public UDP IP first
	select {
	case <-ctx.Done():
		return
	case <-time.After(1500 * time.Millisecond):
	}
	n.registerWithRendezvous(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.registerWithRendezvous(ctx)
		}
	}
}

func (n *Node) registerWithRendezvous(ctx context.Context) {
	n.mu.RLock()
	rdvURL := n.rendezvousURL
	pubWS := n.publicWSURL
	hc := n.rdvClient
	n.mu.RUnlock()
	if rdvURL == "" {
		return
	}

	udpAddrs := n.candidateUDPAddrs()
	if len(udpAddrs) > 16 {
		udpAddrs = udpAddrs[:16]
	}
	payload := map[string]any{
		"device_id":   NormalizeDeviceID(n.cfg.DeviceID),
		"peer_id":     n.cfg.PeerID,
		"name":        n.cfg.Name,
		"os":          fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"fingerprint": n.identity.Fingerprint,
		"udp_addrs":   udpAddrs,
		"ws_url":      pubWS,
	}
	n.signRendezvous("register", payload, pubWS, udpAddrs)
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rdvURL+"/api/rendezvous/register", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		n.mu.Lock()
		n.rendezvousStatus = "offline: " + err.Error()
		n.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	var result struct {
		OK            bool   `json:"ok"`
		Error         string `json:"error"`
		PunchRequests []struct {
			FromDeviceID string   `json:"from_device_id"`
			UDPAddrs     []string `json:"udp_addrs"`
		} `json:"punch_requests"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	n.mu.Lock()
	if resp.StatusCode == http.StatusOK && result.OK {
		n.rendezvousStatus = "online"
	} else if result.Error != "" {
		n.rendezvousStatus = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, result.Error)
	} else {
		n.rendezvousStatus = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	n.mu.Unlock()

	// Send reciprocal UDP hole-punch probes to any waiting callers!
	for _, pr := range result.PunchRequests {
		for _, addrStr := range pr.UDPAddrs {
			if ua, err := net.ResolveUDPAddr("udp", addrStr); err == nil && n.quicTr != nil {
				_, _ = n.quicTr.WriteTo([]byte("RVPN-PUNCH"), ua)
			}
		}
	}
}

// signRendezvous adds ts, cert and sig to a register/unregister payload, proving that this
// device holds the key of the certificate behind its fingerprint (see rendezvous.SignedMessage).
// Directories bind the device ID to that key, so nobody else can redirect the ID.
func (n *Node) signRendezvous(action string, payload map[string]any, wsURL string, udpAddrs []string) {
	if n.identity == nil || len(n.identity.Cert.Certificate) == 0 {
		return
	}
	key, ok := n.identity.Cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return
	}
	ts := time.Now().UnixMilli()
	msg := rendezvous.SignedMessage(action, NormalizeDeviceID(n.cfg.DeviceID), n.identity.Fingerprint, ts, wsURL, udpAddrs)
	sig, err := rendezvous.SignMessage(key, msg, rand.Reader)
	if err != nil {
		return
	}
	payload["ts"] = ts
	payload["cert"] = base64.StdEncoding.EncodeToString(n.identity.Cert.Certificate[0])
	payload["sig"] = sig
}

func (n *Node) unregisterFromRendezvous() {
	n.mu.RLock()
	rdvURL := n.rendezvousURL
	hc := n.rdvClient
	n.mu.RUnlock()
	if rdvURL == "" || hc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := map[string]any{
		"device_id":   NormalizeDeviceID(n.cfg.DeviceID),
		"fingerprint": n.identity.Fingerprint,
	}
	n.signRendezvous("unregister", payload, "", nil)
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rdvURL+"/api/rendezvous/unregister", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := hc.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func (n *Node) presenceLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(1200 * time.Millisecond):
	}
	n.RefreshPresence(ctx)

	ticker := time.NewTicker(rendezvousHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.RefreshPresence(ctx)
		}
	}
}

// RefreshPresence queries the Rendezvous directory (read-only, 0 KV writes) for all remembered peers' live online status.
func (n *Node) RefreshPresence(ctx context.Context) {
	n.mu.RLock()
	rdvURL := n.rendezvousURL
	hc := n.rdvClient
	ids := make([]string, 0, len(n.cfg.KnownPeers))
	for _, kp := range n.cfg.KnownPeers {
		if id := NormalizeDeviceID(kp.DeviceID); id != "" {
			ids = append(ids, id)
		}
	}
	n.mu.RUnlock()

	if rdvURL == "" || hc == nil || len(ids) == 0 {
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"ids": ids})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, rdvURL+"/api/rendezvous/presence", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var out struct {
		OK    bool `json:"ok"`
		Peers map[string]struct {
			Online bool   `json:"online"`
			Name   string `json:"name"`
			OS     string `json:"os"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || !out.OK {
		return
	}

	now := time.Now().UTC()
	n.mu.Lock()
	for id, st := range out.Peers {
		n.presence[id] = peerPresence{
			online:    st.Online,
			name:      st.Name,
			osInfo:    st.OS,
			checkedAt: now,
		}
	}
	n.mu.Unlock()
}

// RefreshSTUN queries public STUN servers on our shared QUIC UDP socket to update our public IP:Port.
func (n *Node) RefreshSTUN(ctx context.Context) (string, error) {
	if n.quicTr == nil {
		return "", errors.New("node not started")
	}
	addr, err := DiscoverPublicAddr(ctx, n.quicTr, n.cfg.STUNServers)
	n.mu.Lock()
	if err != nil {
		n.stunErr = err.Error()
	} else {
		n.publicUDPAddr = addr
		n.stunErr = ""
	}
	n.mu.Unlock()
	if err == nil {
		n.logger.Info("STUN public endpoint discovered", "public_udp", addr)
		go n.registerWithRendezvous(ctx)
	}
	return addr, err
}

// SetPublicWSURL stores an external WSS URL (such as a free trycloudflare.com tunnel) in this node's ticket.
func (n *Node) SetPublicWSURL(rawURL string) {
	u := strings.TrimSpace(rawURL)
	if u != "" {
		if strings.HasPrefix(u, "https://") {
			u = "wss://" + strings.TrimPrefix(u, "https://")
		} else if strings.HasPrefix(u, "http://") {
			u = "ws://" + strings.TrimPrefix(u, "http://")
		}
		if !strings.HasSuffix(u, "/ws/peer") {
			u = strings.TrimRight(u, "/") + "/ws/peer"
		}
	}
	n.mu.Lock()
	n.publicWSURL = u
	// Persist only permanent user-configured URLs; never persist ephemeral trycloudflare.com URLs (they expire on restart -> HTTP 530).
	if !strings.Contains(strings.ToLower(u), ".trycloudflare.com") {
		n.cfg.PublicWSURL = u
		n.persistConfigLocked()
	}
	n.mu.Unlock()
	if n.rootCtx != nil {
		go n.registerWithRendezvous(n.rootCtx)
	}
}

func (n *Node) candidateUDPAddrs() []string {
	// If bound to a specific local IP (e.g., 127.0.0.1 in local tests), advertise that exact address.
	if host, _, err := net.SplitHostPort(n.quicAddrStr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
			return []string{n.quicAddrStr}
		}
	}

	n.mu.RLock()
	pubUDP := n.publicUDPAddr
	n.mu.RUnlock()

	var udpAddrs []string
	if pubUDP != "" {
		udpAddrs = append(udpAddrs, pubUDP)
	}
	if n.quicPort > 0 {
		for _, ip := range LocalLANIPs() {
			candidate := net.JoinHostPort(ip, strconv.Itoa(n.quicPort))
			if !slices.Contains(udpAddrs, candidate) {
				udpAddrs = append(udpAddrs, candidate)
			}
		}
		if len(udpAddrs) == 0 {
			udpAddrs = append(udpAddrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(n.quicPort)))
		}
	}
	return udpAddrs
}

// MyTicket builds this peer's copy-pasteable RVPN1-... pairing ticket.
func (n *Node) MyTicket() string {
	n.mu.RLock()
	pubWS := n.publicWSURL
	pin := n.tempPIN
	n.mu.RUnlock()

	return EncodeTicket(PeerTicket{
		PeerID:      n.cfg.PeerID,
		Name:        n.cfg.Name,
		OS:          fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Fingerprint: n.identity.Fingerprint,
		PairSecret:  pin,
		UDPAddrs:    n.candidateUDPAddrs(),
		WSURL:       pubWS,
	})
}

// ConnectSmart accepts ANY of: a 9-digit Device ID, an RVPN1-... Ticket, a direct host:port, or a ws/wss URL.
func (n *Node) ConnectSmart(ctx context.Context, input, password string) (PeerInfo, error) {
	return n.ConnectSmartWithOptions(ctx, input, password, false, false)
}

// ConnectSmartWithOptions connects to a peer and optionally uses or remembers the password for 1-click reconnect.
func (n *Node) ConnectSmartWithOptions(ctx context.Context, input, password string, rememberPassword, useSavedPassword bool) (PeerInfo, error) {
	input = strings.TrimSpace(input)
	password = strings.TrimSpace(password)
	if input == "" {
		return PeerInfo{}, errors.New("กรุณากรอกรหัสเครื่อง 9 หลัก")
	}

	usedSaved := false
	if password == "" && useSavedPassword && !strings.HasPrefix(input, ticketPrefix) {
		if saved := n.savedPasswordFor(input); saved != "" {
			password = saved
			usedSaved = true
		}
	}

	var (
		info PeerInfo
		err  error
	)
	switch {
	case strings.HasPrefix(input, ticketPrefix):
		info, err = n.ConnectByTicket(ctx, input)
	case isDirectTarget(input):
		info, err = n.ConnectDirect(ctx, input, password, "")
	default:
		info, err = n.ConnectByID(ctx, input, password)
	}
	if err != nil {
		if usedSaved && strings.Contains(err.Error(), "ไม่ถูกต้อง") {
			return PeerInfo{}, errors.New("รหัสผ่านที่บันทึกไว้ไม่ตรงกับเครื่องปลายทาง (หากใช้ PIN ชั่วคราวจะเปลี่ยนทุกครั้งที่เปิดใหม่ — แนะนำตั้ง 'รหัสผ่านถาวร' ที่เครื่องปลายทาง)")
		}
		return PeerInfo{}, err
	}

	if rememberPassword && password != "" && !strings.HasPrefix(input, ticketPrefix) {
		devID := NormalizeDeviceID(info.DeviceID)
		if devID == "" {
			devID = NormalizeDeviceID(input)
		}
		if devID != "" {
			n.savePeerPassword(devID, password)
		}
	}
	return info, nil
}

func (n *Node) savedPasswordFor(rawID string) string {
	trimmed := strings.TrimSpace(rawID)
	bareHost := strings.Trim(trimmed, "[]")
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		bareHost = strings.Trim(h, "[]")
	}
	devID := NormalizeDeviceID(trimmed)

	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, kp := range n.cfg.KnownPeers {
		if devID != "" && !isDirectTarget(trimmed) && NormalizeDeviceID(kp.DeviceID) == devID {
			return kp.SavedPassword
		}
		if bareHost != "" {
			if strings.EqualFold(kp.VPNIP, bareHost) {
				return kp.SavedPassword
			}
			if h, _, err := net.SplitHostPort(kp.QUICAddr); err == nil && strings.EqualFold(strings.Trim(h, "[]"), bareHost) {
				return kp.SavedPassword
			}
		}
	}
	return ""
}

// isDirectTarget reports whether input is a direct IP/host/URL (e.g. "192.168.1.50", "10.4.88.86:4433",
// "pc01.local", "::1", "wss://...") rather than a 9-digit APN Device ID.
func isDirectTarget(input string) bool {
	s := strings.TrimSpace(input)
	if s == "" {
		return false
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://") ||
		strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return true
	}
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return true
	}
	if strings.Contains(s, ":") {
		return true
	}
	// Dotted local/FQDN hostname (e.g. "server.local", "pc01.office.lan")
	if strings.Contains(s, ".") && !strings.ContainsAny(s, " \t") {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	return false
}

// normalizeDirectTarget resolves a direct target into a QUIC UDP host:port and optional TCP WS fallback.
// Bare IPs/hostnames without a port (like "192.168.1.50") automatically default to QUIC :4433 with WS :8444 fallback.
func normalizeDirectTarget(target string) (quicAddr, wsFallback string) {
	s := strings.TrimSpace(target)
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, ""
	}
	host := strings.Trim(s, "[]")
	return net.JoinHostPort(host, "4433"), "ws://" + net.JoinHostPort(host, "8444") + "/ws/peer"
}

func (n *Node) savePeerPassword(devID, password string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			n.cfg.KnownPeers[i].SavedPassword = password
			n.persistConfigLocked()
			return
		}
	}
}

// RemoveSavedPeer deletes a device from the Saved Peer History in peer.json.
func (n *Node) RemoveSavedPeer(rawID string) error {
	devID := NormalizeDeviceID(rawID)
	if devID == "" {
		return errors.New("invalid device_id")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	idx := -1
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("ไม่พบเครื่องนี้ในประวัติ")
	}
	n.cfg.KnownPeers = append(n.cfg.KnownPeers[:idx], n.cfg.KnownPeers[idx+1:]...)
	delete(n.presence, devID)
	n.persistConfigLocked()
	return nil
}

// ClearSavedPeerPassword forgets the saved password for a device in history.
func (n *Node) ClearSavedPeerPassword(rawID string) error {
	devID := NormalizeDeviceID(rawID)
	if devID == "" {
		return errors.New("invalid device_id")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			n.cfg.KnownPeers[i].SavedPassword = ""
			n.persistConfigLocked()
			return nil
		}
	}
	return errors.New("ไม่พบเครื่องนี้ในประวัติ")
}

// RenameSavedPeer assigns a custom display name to a remembered peer.
func (n *Node) RenameSavedPeer(rawID, newName string) error {
	devID := NormalizeDeviceID(rawID)
	newName = strings.TrimSpace(newName)
	if devID == "" || newName == "" {
		return errors.New("กรุณาระบุชื่อเครื่อง")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			n.cfg.KnownPeers[i].Name = newName
			n.cfg.KnownPeers[i].CustomName = true
			n.persistConfigLocked()
			return nil
		}
	}
	return errors.New("ไม่พบเครื่องนี้ในประวัติ")
}

func normalizeGroupName(raw string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	runes := []rune(s)
	if len(runes) > 48 {
		s = string(runes[:48])
	}
	return s
}

// SetSavedPeerGroup assigns (or clears, when empty) a group/folder name for a remembered peer.
func (n *Node) SetSavedPeerGroup(rawID, group string) error {
	devID := NormalizeDeviceID(rawID)
	if devID == "" {
		return errors.New("invalid device_id")
	}
	group = normalizeGroupName(group)
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			n.cfg.KnownPeers[i].Group = group
			n.persistConfigLocked()
			return nil
		}
	}
	return errors.New("ไม่พบเครื่องนี้ในประวัติ")
}

// RenameGroup renames all remembered peers in oldGroup to newGroup.
// If newGroup is empty, the group is dissolved and its devices become ungrouped (never deleted).
func (n *Node) RenameGroup(oldGroup, newGroup string) (int, error) {
	oldGroup = normalizeGroupName(oldGroup)
	newGroup = normalizeGroupName(newGroup)
	if oldGroup == "" {
		return 0, errors.New("กรุณาระบุชื่อกลุ่มเดิม")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	updated := 0
	for i := range n.cfg.KnownPeers {
		if normalizeGroupName(n.cfg.KnownPeers[i].Group) == oldGroup {
			n.cfg.KnownPeers[i].Group = newGroup
			updated++
		}
	}
	if updated == 0 {
		return 0, errors.New("ไม่พบกลุ่มนี้ในประวัติ")
	}
	n.persistConfigLocked()
	return updated, nil
}

// ProbeTarget checks whether a 9-digit ID, direct IP/host, or ticket is reachable and gathers
// display metadata (name, OS, saved password flag) before prompting the user for a password.
func (n *Node) ProbeTarget(ctx context.Context, input string) (ProbeResult, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return ProbeResult{}, errors.New("กรุณากรอกรหัสเครื่อง 9 หลัก หรือ IP ปลายทาง")
	}

	// 1. Peer Ticket (already embeds credentials)
	if strings.HasPrefix(input, ticketPrefix) {
		ticket, err := DecodeTicket(input)
		if err != nil {
			return ProbeResult{}, err
		}
		if ticket.PeerID == n.cfg.PeerID {
			return ProbeResult{}, errors.New("ไม่สามารถเชื่อมต่อเข้าเครื่องตัวเองได้")
		}
		return ProbeResult{
			Target:           input,
			Kind:             "ticket",
			Name:             ticket.Name,
			Reachable:        true,
			Via:              "ticket",
			HasSavedPassword: true,
		}, nil
	}

	// 2. Direct IP / Hostname / WS URL
	if isDirectTarget(input) {
		low := strings.ToLower(input)
		isURL := strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://") ||
			strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
		bareHost := ""
		if !isURL {
			bareHost = strings.Trim(input, "[]")
			if h, _, err := net.SplitHostPort(input); err == nil {
				bareHost = strings.Trim(h, "[]")
			}
			if bareHost != "" && n.vpnIP != "" && strings.EqualFold(bareHost, n.vpnIP) {
				return ProbeResult{}, errors.New("ไม่สามารถเชื่อมต่อเข้าเครื่องตัวเองได้")
			}
		}
		res := ProbeResult{
			Target:    input,
			Kind:      "direct",
			Name:      input,
			Reachable: true,
			Via:       "direct",
		}

		// Check already-connected peers matching this host/VPN IP
		n.mu.RLock()
		for _, p := range n.peers {
			rHost := ""
			if h, _, err := net.SplitHostPort(p.remoteAddr); err == nil {
				rHost = strings.Trim(h, "[]")
			}
			if bareHost != "" && (strings.EqualFold(p.vpnIP, bareHost) || strings.EqualFold(rHost, bareHost)) {
				info := p.info()
				res.AlreadyConnected = true
				res.Via = "connected"
				res.DeviceID = info.DeviceID
				res.Name = info.Name
				res.OS = info.OS
				res.Peer = &info
				n.mu.RUnlock()
				return res, nil
			}
		}
		// Enrich from KnownPeers (custom name, OS, saved password)
		for _, kp := range n.cfg.KnownPeers {
			kpHost := ""
			if h, _, err := net.SplitHostPort(kp.QUICAddr); err == nil {
				kpHost = strings.Trim(h, "[]")
			}
			if bareHost != "" && (strings.EqualFold(kp.VPNIP, bareHost) || strings.EqualFold(kpHost, bareHost)) {
				res.DeviceID = NormalizeDeviceID(kp.DeviceID)
				if kp.Name != "" {
					res.Name = kp.Name
				}
				res.OS = kp.OS
				res.HasSavedPassword = kp.SavedPassword != ""
				break
			}
		}
		n.mu.RUnlock()

		// Enrich from LAN auto-discovery if host matches
		if n.lanDisc != nil && bareHost != "" {
			for _, dp := range n.lanDisc.list() {
				if h, _, err := net.SplitHostPort(dp.QUICAddr); err == nil && strings.EqualFold(strings.Trim(h, "[]"), bareHost) {
					if res.DeviceID == "" {
						res.DeviceID = NormalizeDeviceID(dp.DeviceID)
					}
					if res.Name == input && dp.Name != "" {
						res.Name = dp.Name
					}
					if res.OS == "" {
						res.OS = dp.OS
					}
					res.Via = "lan"
					break
				}
			}
		}

		// Fast non-intrusive /healthz ping for bare IP/host (never blocks UDP-only targets if filtered)
		if !isURL && bareHost != "" && !strings.Contains(bareHost, "/") {
			probeCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			healthURL := fmt.Sprintf("http://%s/healthz", net.JoinHostPort(bareHost, "8444"))
			if req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil); err == nil {
				hc := &http.Client{Timeout: 1200 * time.Millisecond}
				if resp, err := hc.Do(req); err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusOK && res.Via == "direct" {
						res.Via = "lan"
					}
				}
			}
		}
		return res, nil
	}

	// 3. 9-digit Device ID
	devID := NormalizeDeviceID(input)
	if len(devID) != 9 {
		return ProbeResult{}, errors.New("รหัสเครื่องไม่ถูกต้อง (กรุณากรอกเลข 9 หลัก หรือ IP เช่น 192.168.1.50)")
	}
	if devID == n.cfg.DeviceID {
		return ProbeResult{}, errors.New("ไม่สามารถเชื่อมต่อเข้าเครื่องตัวเองได้")
	}

	res := ProbeResult{
		Target:   devID,
		Kind:     "id",
		DeviceID: devID,
		Name:     FormatDeviceID(devID),
	}

	var (
		hasCustomName bool
		hasKnownAddr  bool
		rdvURL        string
		hc            *http.Client
	)
	n.mu.RLock()
	for _, p := range n.peers {
		if NormalizeDeviceID(p.deviceID) == devID || p.id == devID {
			info := p.info()
			res.AlreadyConnected = true
			res.Reachable = true
			res.Via = "connected"
			res.Name = info.Name
			res.OS = info.OS
			res.Peer = &info
			for _, kp := range n.cfg.KnownPeers {
				if NormalizeDeviceID(kp.DeviceID) == devID {
					if kp.CustomName && kp.Name != "" {
						res.Name = kp.Name
					}
					res.HasSavedPassword = kp.SavedPassword != ""
					break
				}
			}
			n.mu.RUnlock()
			return res, nil
		}
	}
	for _, kp := range n.cfg.KnownPeers {
		if NormalizeDeviceID(kp.DeviceID) == devID {
			if kp.Name != "" {
				res.Name = kp.Name
				hasCustomName = kp.CustomName
			}
			res.OS = kp.OS
			res.HasSavedPassword = kp.SavedPassword != ""
			hasKnownAddr = kp.QUICAddr != "" || kp.WSURL != ""
			break
		}
	}
	rdvURL = n.rendezvousURL
	hc = n.rdvClient
	n.mu.RUnlock()

	// Check LAN auto-discovery first (instant, zero-server)
	if n.lanDisc != nil {
		if dp, ok := n.lanDisc.findByDeviceID(devID); ok {
			res.Reachable = true
			res.Via = "lan"
			if !hasCustomName && dp.Name != "" {
				res.Name = dp.Name
			}
			if res.OS == "" {
				res.OS = dp.OS
			}
			return res, nil
		}
	}

	// Read-only presence check via Rendezvous directory (0 KV writes, never triggers auth rate limit)
	if rdvURL != "" && hc != nil {
		reqCtx, cancel := context.WithTimeout(ctx, 4500*time.Millisecond)
		defer cancel()
		body, _ := json.Marshal(map[string]any{"ids": []string{devID}})
		if req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, rdvURL+"/api/rendezvous/presence", bytes.NewReader(body)); err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := hc.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var out struct {
						OK    bool `json:"ok"`
						Peers map[string]struct {
							Online bool   `json:"online"`
							Name   string `json:"name"`
							OS     string `json:"os"`
						} `json:"peers"`
					}
					if json.NewDecoder(resp.Body).Decode(&out) == nil && out.OK {
						st := out.Peers[devID]
						now := time.Now().UTC()
						n.mu.Lock()
						n.presence[devID] = peerPresence{
							online:    st.Online,
							name:      st.Name,
							osInfo:    st.OS,
							checkedAt: now,
						}
						n.mu.Unlock()
						if st.Online {
							res.Reachable = true
							res.Via = "cloud"
							if !hasCustomName && st.Name != "" {
								res.Name = st.Name
							}
							if res.OS == "" && st.OS != "" {
								res.OS = st.OS
							}
							return res, nil
						}
						res.Reachable = false
						res.Message = fmt.Sprintf("ไม่พบเครื่อง %s ออนไลน์อยู่ในขณะนี้ (กรุณาตรวจสอบว่าเปิด APN และเชื่อมต่ออินเทอร์เน็ตที่เครื่องปลายทางแล้ว)", FormatDeviceID(devID))
						return res, nil
					}
				}
			}
		}
	}

	// If Rendezvous is unconfigured or temporarily unreachable, still allow connecting via known peer address
	if hasKnownAddr {
		res.Reachable = true
		res.Via = "known"
		return res, nil
	}
	res.Reachable = false
	res.Message = fmt.Sprintf("ไม่พบเครื่อง %s ออนไลน์อยู่ตอนนี้ (ตรวจสอบเลข 9 หลักหรือเครือข่าย)", FormatDeviceID(devID))
	return res, nil
}

// ConnectByID resolves a 9-digit Device ID via LAN Auto-Discovery first, then Rendezvous Server.
func (n *Node) ConnectByID(ctx context.Context, rawID, password string) (PeerInfo, error) {
	devID := NormalizeDeviceID(rawID)
	if devID == "" {
		return PeerInfo{}, errors.New("รหัสเครื่องไม่ถูกต้อง (ควรเป็นตัวเลข 9 หลัก เช่น 482 917 305)")
	}
	if devID == n.cfg.DeviceID {
		return PeerInfo{}, errors.New("ไม่สามารถเชื่อมต่อเข้าเครื่องตัวเองได้")
	}

	// Already connected? Return immediately!
	n.mu.RLock()
	for _, p := range n.peers {
		if p.deviceID == devID || p.id == devID {
			info := p.info()
			n.mu.RUnlock()
			return info, nil
		}
	}
	rdvURL := n.rendezvousURL
	hc := n.rdvClient
	n.mu.RUnlock()

	// Each path that fails falls through to the next one. Only a rejection by the host
	// (wrong password, owner declined) stops early, so the owner is not prompted again.
	var errs []string

	// 1. Check LAN Auto-Discovery (instant, zero-server!)
	if n.lanDisc != nil {
		if dp, ok := n.lanDisc.findByDeviceID(devID); ok && dp.QUICAddr != "" {
			info, err := n.dialQUICPeerTimeout(ctx, dp.QUICAddr, n.pinnedFingerprint(devID, dp.Fingerprint), password, lanDialTimeout)
			if err == nil {
				return info, nil
			}
			if isPeerRejected(err) || ctx.Err() != nil {
				return PeerInfo{}, err
			}
			n.logger.Warn("LAN dial failed, trying other paths", "device_id", devID, "addr", dp.QUICAddr, "err", err)
			errs = append(errs, fmt.Sprintf("LAN %s: %v", dp.QUICAddr, err))
		}
	}

	// 2. Query Rendezvous Directory (for cross-internet 9-digit ID lookup + simultaneous UDP punch)
	if rdvURL != "" {
		info, err := n.connectViaRendezvous(ctx, rdvURL, hc, devID, password)
		if err == nil {
			return info, nil
		}
		if isPeerRejected(err) || ctx.Err() != nil {
			return PeerInfo{}, err
		}
		errs = append(errs, err.Error())
	}

	// 3. Fallback to KnownPeers address book (remembered from earlier connections!).
	// Also used when the Rendezvous service is unreachable or over its quota.
	n.mu.RLock()
	var known *config.KnownPeer
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			kp := n.cfg.KnownPeers[i]
			known = &kp
			break
		}
	}
	n.mu.RUnlock()
	if known != nil {
		if known.QUICAddr != "" {
			info, err := n.dialQUICPeer(ctx, known.QUICAddr, known.Fingerprint, password)
			if err == nil {
				return info, nil
			}
			if isPeerRejected(err) || ctx.Err() != nil {
				return PeerInfo{}, err
			}
		}
		if known.WSURL != "" {
			info, err := n.dialWSPeer(ctx, known.WSURL, password, true)
			if err == nil {
				return info, nil
			}
			if isPeerRejected(err) || ctx.Err() != nil {
				return PeerInfo{}, err
			}
		}
	}

	if len(errs) > 0 {
		return PeerInfo{}, errors.New(strings.Join(errs, "; "))
	}
	return PeerInfo{}, fmt.Errorf("ไม่พบเครื่อง %s ในวง LAN เดียวกัน — หากอยู่คนละเครือข่าย ให้กรอก IP:4433 (เช่น 26.x.x.x:4433), ตั้งค่า Rendezvous URL หรือวาง Peer Ticket ในส่วน 'ตั้งค่าขั้นสูง'", FormatDeviceID(devID))
}

// pinnedFingerprint returns the certificate fingerprint to pin when dialing devID: the one
// remembered from an earlier successful connection (trust on first use) when there is one,
// otherwise the advertised one. A directory entry or LAN beacon that claims the device with
// another certificate then fails the TLS handshake instead of receiving the password.
func (n *Node) pinnedFingerprint(devID, advertised string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, kp := range n.cfg.KnownPeers {
		if NormalizeDeviceID(kp.DeviceID) == devID && kp.Fingerprint != "" {
			if !strings.EqualFold(kp.Fingerprint, advertised) {
				n.logger.Warn("advertised fingerprint differs from the remembered device; pinning the remembered one",
					"device_id", devID, "remembered", kp.Fingerprint, "advertised", advertised)
			}
			return kp.Fingerprint
		}
	}
	return advertised
}

// lanDialTimeout bounds a QUIC dial to a LAN-discovered peer; a LAN handshake normally takes milliseconds.
const lanDialTimeout = 2500 * time.Millisecond

// peerRejectedError is returned when the host answered the hello but refused the connection
// (wrong password, owner declined). Retrying other network paths would not help.
type peerRejectedError struct{ msg string }

func (e *peerRejectedError) Error() string { return e.msg }

func isPeerRejected(err error) bool {
	var rej *peerRejectedError
	return errors.As(err, &rej)
}

// connectViaRendezvous looks the device up in the Rendezvous directory and tries its
// direct UDP addresses, then its WSS/443 bridge URL.
func (n *Node) connectViaRendezvous(ctx context.Context, rdvURL string, hc *http.Client, devID, password string) (PeerInfo, error) {
	{
		callerBody, _ := json.Marshal(map[string]any{
			"from_device_id": n.cfg.DeviceID,
			"udp_addrs":      n.candidateUDPAddrs(),
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rdvURL+"/api/rendezvous/lookup/"+devID, bytes.NewReader(callerBody))
		if err != nil {
			return PeerInfo{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return PeerInfo{}, fmt.Errorf("ติดต่อ Rendezvous Server ไม่ได้: %w", err)
		}
		defer resp.Body.Close()

		var lookup struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
			Entry struct {
				DeviceID    string   `json:"device_id"`
				Fingerprint string   `json:"fingerprint"`
				UDPAddrs    []string `json:"udp_addrs"`
				WSURL       string   `json:"ws_url"`
			} `json:"entry"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&lookup); err != nil {
			return PeerInfo{}, fmt.Errorf("อ่านผลลัพธ์จาก Rendezvous ไม่ได้ (HTTP %d): %w", resp.StatusCode, err)
		}
		if !lookup.OK {
			return PeerInfo{}, errors.New(lookup.Error)
		}

		var errs []string
		pinnedFP := n.pinnedFingerprint(devID, lookup.Entry.Fingerprint)
		if !strings.EqualFold(pinnedFP, lookup.Entry.Fingerprint) {
			errs = append(errs, "ลายนิ้วมือ (fingerprint) ของเครื่องปลายทางไม่ตรงกับที่เคยเชื่อมต่อ — ถ้าเครื่องนั้นเพิ่งติดตั้งใหม่ ให้ลบออกจากประวัติแล้วเชื่อมต่อใหม่")
		}
		if len(lookup.Entry.UDPAddrs) > 0 {
			if info, err := n.raceQUICAddrs(ctx, lookup.Entry.UDPAddrs, pinnedFP, password); err == nil {
				return info, nil
			} else if isPeerRejected(err) {
				return PeerInfo{}, err
			} else {
				errs = append(errs, err.Error())
			}
		}
		if lookup.Entry.WSURL != "" {
			info, err := n.dialWSPeer(ctx, lookup.Entry.WSURL, password, true)
			if err == nil {
				return info, nil
			}
			if isPeerRejected(err) {
				return PeerInfo{}, err
			}
			// If a quick tunnel returned HTTP 530/502/503/504 (stale/restarting tunnel),
			// wait briefly and re-query Rendezvous ONCE in case the host just rotated to a fresh 443 tunnel!
			errLower := strings.ToLower(err.Error())
			if strings.Contains(strings.ToLower(lookup.Entry.WSURL), ".trycloudflare.com") &&
				(strings.Contains(errLower, "530") || strings.Contains(errLower, "502") || strings.Contains(errLower, "503") || strings.Contains(errLower, "504")) {
				select {
				case <-ctx.Done():
				case <-time.After(2200 * time.Millisecond):
					if freshReq, ferr := http.NewRequestWithContext(ctx, http.MethodPost, rdvURL+"/api/rendezvous/lookup/"+devID, bytes.NewReader(callerBody)); ferr == nil {
						freshReq.Header.Set("Content-Type", "application/json")
						if freshResp, fdoErr := hc.Do(freshReq); fdoErr == nil {
							var freshLookup struct {
								OK    bool `json:"ok"`
								Entry struct {
									WSURL string `json:"ws_url"`
								} `json:"entry"`
							}
							_ = json.NewDecoder(freshResp.Body).Decode(&freshLookup)
							_ = freshResp.Body.Close()
							if freshLookup.OK && freshLookup.Entry.WSURL != "" {
								if info2, err2 := n.dialWSPeer(ctx, freshLookup.Entry.WSURL, password, true); err2 == nil {
									return info2, nil
								} else {
									err = err2
									lookup.Entry.WSURL = freshLookup.Entry.WSURL
									errLower = strings.ToLower(err2.Error())
								}
							}
						}
					}
				}
			}
			if strings.Contains(errLower, "530") {
				errs = append(errs, "ท่อเชื่อมข้ามเน็ต 443 ของเครื่องปลายทางหลุดชั่วคราว (HTTP 530 — อาจเพิ่งรีสตาร์ทหรือปิดเครื่องอยู่) กรุณารอ 5–10 วินาทีแล้วลองใหม่")
			} else {
				errs = append(errs, fmt.Sprintf("ws(%s): %v", lookup.Entry.WSURL, err))
			}
		}
		return PeerInfo{}, fmt.Errorf("พบเครื่อง %s แต่เชื่อมต่อไม่สำเร็จ: %s", FormatDeviceID(devID), strings.Join(errs, "; "))
	}
}

// ConnectByTicket decodes a PeerTicket and races direct QUIC UDP Hole Punching (2.5s)
// before seamlessly falling back to HTTPS Port 443 WebSocket (Cloudflare Tunnel) if behind strict NAT.
func (n *Node) ConnectByTicket(ctx context.Context, ticketStr string) (PeerInfo, error) {
	ticket, err := DecodeTicket(ticketStr)
	if err != nil {
		return PeerInfo{}, err
	}
	if ticket.PeerID == n.cfg.PeerID {
		return PeerInfo{}, errors.New("ไม่สามารถเชื่อมต่อเข้าเครื่องตัวเองได้")
	}

	var errs []string
	if len(ticket.UDPAddrs) > 0 {
		if info, err := n.raceQUICAddrs(ctx, ticket.UDPAddrs, ticket.Fingerprint, ticket.PairSecret); err == nil {
			return info, nil
		} else {
			errs = append(errs, err.Error())
		}
	}
	if ticket.WSURL != "" {
		info, err := n.dialWSPeer(ctx, ticket.WSURL, ticket.PairSecret, true)
		if err == nil {
			return info, nil
		}
		errs = append(errs, fmt.Sprintf("ws(%s): %v", ticket.WSURL, err))
	}
	if len(errs) == 0 {
		return PeerInfo{}, errors.New("ticket ไม่มีที่อยู่ปลายทางที่เชื่อมต่อได้")
	}
	return PeerInfo{}, fmt.Errorf("เชื่อมต่อ P2P ไม่สำเร็จ: %s", strings.Join(errs, "; "))
}

// raceQUICAddrs tries all direct candidate UDP endpoints concurrently with a fast 2.5s budget so
// direct LAN/STUN connects in milliseconds while slow IPv6 relays (Teredo/6to4/ULA) never hijack
// traffic away from direct IPv4 or low-latency Cloudflare 443 WSS.
func (n *Node) raceQUICAddrs(ctx context.Context, addrs []string, expectedFP, pairSecret string) (PeerInfo, error) {
	filtered := make([]string, 0, len(addrs))
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(strings.TrimSpace(a))
		if err == nil {
			if ip := net.ParseIP(host); ip != nil && IsSlowOverlayIP(ip) {
				continue
			}
		}
		filtered = append(filtered, a)
	}
	if len(filtered) == 0 {
		return PeerInfo{}, errors.New("no direct UDP endpoints available")
	}

	// Race only the QUIC dials. The first connection wins and the hello handshake runs once on it,
	// so slower candidates never register a duplicate session or trigger a second approval prompt,
	// and the owner's approval is not cut off by the 2.5s race window.
	raceCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	type res struct {
		sess MuxSession
		err  error
	}
	ch := make(chan res, len(filtered))
	for _, a := range filtered {
		addrStr := a
		go func() {
			sess, err := n.dialQUICSession(raceCtx, addrStr, expectedFP, 2500*time.Millisecond)
			ch <- res{sess: sess, err: err}
		}()
	}

	var winner MuxSession
	var lastErr error
	received := 0
	for received < len(filtered) && winner == nil {
		r := <-ch
		received++
		if r.err == nil {
			winner = r.sess
		} else {
			lastErr = r.err
		}
	}
	cancel()
	if remaining := len(filtered) - received; remaining > 0 {
		// Close any losing connections that still complete after the winner.
		go func() {
			for i := 0; i < remaining; i++ {
				if r := <-ch; r.err == nil && r.sess != nil {
					_ = r.sess.Close()
				}
			}
		}()
	}
	if winner == nil {
		if lastErr == nil {
			lastErr = errors.New("no UDP endpoints reachable")
		}
		return PeerInfo{}, lastErr
	}
	return n.completeOutboundHandshake(ctx, winner, pairSecret, false)
}

// ConnectDirect connects to a peer via a bare IP/hostname (auto-using QUIC :4433 with TCP WS :8444 fallback),
// an explicit UDP host:port (QUIC), or a ws:// / wss:// URL.
func (n *Node) ConnectDirect(ctx context.Context, target, pairSecret, expectedFingerprint string) (PeerInfo, error) {
	target = strings.TrimSpace(target)
	pairSecret = strings.TrimSpace(pairSecret)
	if target == "" {
		return PeerInfo{}, errors.New("กรุณาระบุที่อยู่ปลายทาง")
	}
	if strings.HasPrefix(target, ticketPrefix) {
		return n.ConnectByTicket(ctx, target)
	}
	if strings.HasPrefix(target, "ws://") || strings.HasPrefix(target, "wss://") ||
		strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if strings.HasPrefix(target, "https://") {
			target = "wss://" + strings.TrimPrefix(target, "https://")
		} else if strings.HasPrefix(target, "http://") {
			target = "ws://" + strings.TrimPrefix(target, "http://")
		}
		if !strings.HasSuffix(target, "/ws/peer") {
			target = strings.TrimRight(target, "/") + "/ws/peer"
		}
		return n.dialWSPeer(ctx, target, pairSecret, false)
	}

	quicAddr, wsFallback := normalizeDirectTarget(target)
	dialTimeout := 6 * time.Second
	if wsFallback != "" {
		dialTimeout = 3500 * time.Millisecond
	}
	info, err := n.dialQUICPeerTimeout(ctx, quicAddr, expectedFingerprint, pairSecret, dialTimeout)
	if err == nil || wsFallback == "" || isPeerRejected(err) || ctx.Err() != nil {
		return info, err
	}
	// Bare IP/host UDP :4433 blocked by LAN firewall -> seamlessly try direct TCP WebSocket :8444!
	infoWS, errWS := n.dialWSPeer(ctx, wsFallback, pairSecret, false)
	if errWS == nil {
		return infoWS, nil
	}
	if isPeerRejected(errWS) {
		return PeerInfo{}, errWS
	}
	return PeerInfo{}, fmt.Errorf("เชื่อมต่อ IP %s ไม่สำเร็จ (UDP :4433: %v; TCP :8444: %v)", target, err, errWS)
}

func (n *Node) dialQUICPeer(ctx context.Context, addrStr, expectedFP, pairSecret string) (PeerInfo, error) {
	return n.dialQUICPeerTimeout(ctx, addrStr, expectedFP, pairSecret, 6*time.Second)
}

// dialQUICPeerTimeout dials like dialQUICPeer but bounds only the QUIC dial itself, not the
// hello handshake that follows (which may wait up to 40s for the owner to approve).
func (n *Node) dialQUICPeerTimeout(ctx context.Context, addrStr, expectedFP, pairSecret string, dialTimeout time.Duration) (PeerInfo, error) {
	sess, err := n.dialQUICSession(ctx, addrStr, expectedFP, dialTimeout)
	if err != nil {
		return PeerInfo{}, err
	}
	return n.completeOutboundHandshake(ctx, sess, pairSecret, false)
}

// dialQUICSession punches toward addrStr and opens a QUIC connection, without the hello handshake.
func (n *Node) dialQUICSession(ctx context.Context, addrStr, expectedFP string, dialTimeout time.Duration) (MuxSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}

	punchPkt := []byte("RVPN-PUNCH")
	for i := 0; i < 3; i++ {
		_, _ = n.quicTr.WriteTo(punchPkt, udpAddr)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := n.quicTr.Dial(dialCtx, udpAddr, n.identity.ClientTLSConfig(expectedFP), defaultQUICConfig())
	if err != nil {
		return nil, err
	}
	return WrapQUIC(conn), nil
}

func (n *Node) dialWSPeer(ctx context.Context, wsURL, pairSecret string, tryQUICUpgrade bool) (PeerInfo, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext:       resilientDialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13},
			ForceAttemptHTTP2: false,
		},
	}

	wsConn, resp, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			return PeerInfo{}, fmt.Errorf("ws dial HTTP %d: %w", resp.StatusCode, err)
		}
		return PeerInfo{}, err
	}
	wsConn.SetReadLimit(4 << 20)

	sessCtx := n.rootCtx
	if sessCtx == nil {
		sessCtx = context.Background()
	}
	netConn := websocket.NetConn(sessCtx, wsConn, websocket.MessageBinary)
	ym, err := yamux.Client(netConn, protocol.NewYamuxConfig())
	if err != nil {
		_ = netConn.Close()
		return PeerInfo{}, err
	}

	transport := "WSS/443 (TLS 1.3)"
	if strings.HasPrefix(wsURL, "ws://") {
		transport = "WS/TCP"
	}
	return n.completeOutboundHandshake(ctx, WrapYamux(ym, wsURL, transport), pairSecret, tryQUICUpgrade)
}

func (n *Node) acceptQUICLoop(ctx context.Context) {
	for {
		conn, err := n.quicListener.Accept(ctx)
		if err != nil {
			return
		}
		go n.handleIncomingSession(WrapQUIC(conn))
	}
}

func (n *Node) handleIncomingWS(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	wsConn.SetReadLimit(4 << 20)

	sessCtx := n.rootCtx
	if sessCtx == nil {
		sessCtx = context.Background()
	}
	netConn := websocket.NetConn(sessCtx, wsConn, websocket.MessageBinary)
	ym, err := yamux.Server(netConn, protocol.NewYamuxConfig())
	if err != nil {
		_ = netConn.Close()
		return
	}

	// Forwarding headers are trusted only from a proxy on this machine (cloudflared connects
	// from loopback); a direct client could otherwise fake its address to dodge rate limits.
	remoteAddr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if cf := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); cf != "" {
				remoteAddr = cf
			} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				remoteAddr = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	transport := "WSS/ReverseProxy"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		transport = "WS/TCP"
	}
	n.handleIncomingSession(WrapYamux(ym, remoteAddr, transport))
}

func (n *Node) myHello(pairSecret string) peerHello {
	targets := make([]protocol.TargetInfo, 0, len(n.cfg.AllowedTargets))
	for _, t := range n.cfg.AllowedTargets {
		targets = append(targets, protocol.TargetInfo{Name: t.Name, Address: t.Address})
	}
	return peerHello{
		DeviceID:    n.cfg.DeviceID,
		PeerID:      n.cfg.PeerID,
		Name:        n.cfg.Name,
		OS:          fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Version:     version.Version,
		VPNIP:       n.vpnIP,
		Fingerprint: n.identity.Fingerprint,
		PairSecret:  pairSecret,
		UDPAddrs:    n.candidateUDPAddrs(),
		Targets:     targets,
		Capabilities: protocol.AgentCapabilities{
			AllowScreen: n.cfg.AllowScreen,
			AllowInput:  n.cfg.AllowInput,
			AllowShell:  n.cfg.AllowShell,
			AllowFiles:  true,
			HasFFmpeg:   bootstrap.HasFFmpeg(),
		},
	}
}

func (n *Node) sendUDPPunches(addrs []string, duration time.Duration) {
	if n.quicTr == nil || len(addrs) == 0 {
		return
	}
	resolved := make([]*net.UDPAddr, 0, len(addrs))
	for _, a := range addrs {
		if ua, err := net.ResolveUDPAddr("udp", a); err == nil {
			resolved = append(resolved, ua)
		}
	}
	if len(resolved) == 0 {
		return
	}
	punch := []byte("RVPN-PUNCH")
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if n.rootCtx != nil && n.rootCtx.Err() != nil {
			return
		}
		for _, ua := range resolved {
			_, _ = n.quicTr.WriteTo(punch, ua)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (n *Node) completeOutboundHandshake(ctx context.Context, sess MuxSession, pairSecret string, tryQUICUpgrade bool) (PeerInfo, error) {
	hsCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(hsCtx)
	if err != nil {
		_ = sess.Close()
		return PeerInfo{}, fmt.Errorf("open handshake stream: %w", err)
	}
	if err := protocol.WriteMessage(stream, n.myHello(pairSecret)); err != nil {
		_ = stream.Close()
		_ = sess.Close()
		return PeerInfo{}, fmt.Errorf("write hello: %w", err)
	}
	var resp peerHelloResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		_ = stream.Close()
		_ = sess.Close()
		return PeerInfo{}, fmt.Errorf("read hello response: %w", err)
	}
	_ = stream.Close()
	if !resp.OK {
		_ = sess.Close()
		return PeerInfo{}, &peerRejectedError{msg: resp.Error}
	}

	p := n.registerPeer(sess, resp.Peer, true)

	// Simultaneous UDP hole-punch upgrade: when connected over Cloudflare WSS/443, the host just started
	// punching back toward our STUN UDP addr at the exact same millisecond. Give direct QUIC/UDP 1.4s to
	// punch through NAT so we get 10-20ms direct P2P with zero Cloudflare detour!
	if tryQUICUpgrade && !strings.HasPrefix(sess.TransportName(), "QUIC") && len(resp.Peer.UDPAddrs) > 0 && n.quicTr != nil {
		upCtx, upCancel := context.WithTimeout(ctx, 1400*time.Millisecond)
		defer upCancel()
		if qInfo, err := n.raceQUICAddrs(upCtx, resp.Peer.UDPAddrs, resp.Peer.Fingerprint, pairSecret); err == nil {
			n.logger.Info("upgraded peer from WSS/443 to direct QUIC/UDP P2P!", "peer_id", qInfo.ID, "remote", qInfo.RemoteAddr)
			return qInfo, nil
		}
	}

	return p.info(), nil
}

func (n *Node) verifyIncomingAuth(presented string) (passwordMatched bool, requireApproval bool) {
	n.mu.RLock()
	pin := n.tempPIN
	permHash := n.cfg.PermanentPasswordHash
	legacySec := n.cfg.PairSecret
	reqApproval := n.cfg.RequireApproval
	n.mu.RUnlock()

	if security.VerifyToken(presented, pin) ||
		(permHash != "" && security.VerifyToken(presented, permHash)) ||
		security.VerifyToken(presented, legacySec) {
		return true, reqApproval
	}
	return false, reqApproval
}

func (n *Node) requestOwnerApproval(hello peerHello, remoteAddr string) bool {
	reqID := fmt.Sprintf("apr-%d", n.appSeq.Add(1))
	now := time.Now().UTC()
	w := &approvalWaiter{
		info: PendingApproval{
			ID:          reqID,
			DeviceID:    hello.DeviceID,
			PeerID:      hello.PeerID,
			Name:        hello.Name,
			OS:          hello.OS,
			RemoteAddr:  remoteAddr,
			RequestedAt: now,
			ExpiresAt:   now.Add(ApprovalTimeout),
		},
		ch: make(chan bool, 1),
	}

	n.mu.Lock()
	// Never stack up more than a few prompts: anyone can request approval with an empty password.
	if len(n.approvals) >= maxPendingAsk {
		n.mu.Unlock()
		return false
	}
	n.approvals[reqID] = w
	notify := n.onApproval
	n.mu.Unlock()
	if notify != nil {
		go notify(w.info)
	}

	defer func() {
		n.mu.Lock()
		delete(n.approvals, reqID)
		n.mu.Unlock()
	}()

	timer := time.NewTimer(ApprovalTimeout)
	defer timer.Stop()

	select {
	case allowed := <-w.ch:
		return allowed
	case <-timer.C:
		return false
	}
}

func (n *Node) handleIncomingSession(sess MuxSession) {
	hsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := sess.AcceptStream(hsCtx)
	cancel()
	if err != nil {
		_ = sess.Close()
		return
	}

	var hello peerHello
	if err := protocol.ReadMessage(stream, &hello); err != nil {
		_ = stream.Close()
		_ = sess.Close()
		return
	}

	key := authKey(sess.RemoteAddr())
	if wait := n.authLimit.wait(key); wait > 0 {
		time.Sleep(authFailDelay)
		_ = protocol.WriteMessage(stream, peerHelloResponse{
			OK:    false,
			Error: "ใส่รหัสผิดหลายครั้งเกินไป กรุณารอ " + waitText(wait) + " แล้วลองใหม่",
		})
		_ = stream.Close()
		// Let the reply reach the caller before tearing the session down.
		time.AfterFunc(500*time.Millisecond, func() { _ = sess.Close() })
		n.logger.Warn("p2p login refused: too many failed attempts", "remote", sess.RemoteAddr())
		return
	}

	matched, reqApproval := n.verifyIncomingAuth(hello.PairSecret)
	authorized := matched
	// A wrong password counts as a guess. (An empty password in approval mode is a request for
	// the owner to decide, not a guess.)
	if !matched && (hello.PairSecret != "" || !reqApproval) {
		if n.authLimit.fail(key) {
			if pin, err := n.RotateTempPIN(); err == nil && pin != "" {
				n.logger.Warn("rotated the temporary PIN after repeated failed logins")
			}
		}
		time.Sleep(authFailDelay)
	} else if matched {
		n.authLimit.success(key)
	}

	if reqApproval {
		// When interactive approval mode is ON, ask the device owner on the Dashboard.
		// (If a wrong non-empty password was supplied, still reject immediately.)
		if hello.PairSecret != "" && !matched {
			authorized = false
		} else {
			authorized = n.requestOwnerApproval(hello, sess.RemoteAddr())
		}
	}

	if !authorized {
		errMsg := "PIN หรือรหัสผ่านไม่ถูกต้อง"
		if reqApproval && (hello.PairSecret == "" || matched) {
			errMsg = "เจ้าของเครื่องปลายทางปฏิเสธหรือไม่ได้กดยืนยันภายในเวลาที่กำหนด"
		}
		_ = protocol.WriteMessage(stream, peerHelloResponse{
			OK:    false,
			Error: errMsg,
		})
		_ = stream.Close()
		_ = sess.Close()
		n.logger.Warn("rejected p2p peer connection", "peer_id", hello.PeerID, "remote", sess.RemoteAddr())
		return
	}

	if err := protocol.WriteMessage(stream, peerHelloResponse{
		OK:   true,
		Peer: n.myHello(""),
	}); err != nil {
		_ = stream.Close()
		_ = sess.Close()
		return
	}
	_ = stream.Close()

	// If incoming peer arrived over WSS/443, immediately punch UDP back toward its live STUN addrs
	// so its simultaneous QUIC upgrade attempt punches through NAT in <300ms!
	if !strings.HasPrefix(sess.TransportName(), "QUIC") && len(hello.UDPAddrs) > 0 && n.quicTr != nil {
		go n.sendUDPPunches(hello.UDPAddrs, 2500*time.Millisecond)
	}

	n.registerPeer(sess, hello, false)
}

func (n *Node) registerPeer(sess MuxSession, remotePeer peerHello, outbound bool) *connectedPeer {
	parent := n.rootCtx
	if parent == nil {
		parent = context.Background()
	}
	peerCtx, cancel := context.WithCancel(parent)

	p := &connectedPeer{
		deviceID:     remotePeer.DeviceID,
		id:           remotePeer.PeerID,
		name:         remotePeer.Name,
		osInfo:       remotePeer.OS,
		appVersion:   remotePeer.Version,
		vpnIP:        remotePeer.VPNIP,
		fingerprint:  remotePeer.Fingerprint,
		remoteAddr:   sess.RemoteAddr(),
		transport:    sess.TransportName(),
		connectedAt:  time.Now().UTC(),
		targets:      slices.Clone(remotePeer.Targets),
		capabilities: remotePeer.Capabilities,
		session:      sess,
		cancel:       cancel,
		outbound:     outbound,
	}

	n.mu.Lock()
	if prev, exists := n.peers[p.id]; exists {
		prev.cancel()
		_ = prev.session.Close()
	}
	n.peers[p.id] = p
	n.rememberPeerLocked(p)
	n.mu.Unlock()

	n.logger.Info("p2p peer connected (bidirectional)", "peer_id", p.id, "device_id", p.deviceID, "transport", p.transport)

	go n.servePeerStreams(peerCtx, p)
	if p.session.SupportsDatagrams() {
		go n.servePeerDatagrams(peerCtx, p)
	}
	return p
}

func (n *Node) servePeerDatagrams(ctx context.Context, p *connectedPeer) {
	for ctx.Err() == nil {
		pkt, err := p.session.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(pkt) < 20 {
			continue
		}
		n.totalRecv.Add(int64(len(pkt)))
		if !n.acceptVPNPacket(p, pkt) {
			continue
		}

		n.mu.RLock()
		sink := n.packetSink
		n.mu.RUnlock()
		if sink != nil {
			sink(append([]byte(nil), pkt...))
		}
		if n.vpnMgr != nil {
			_ = n.vpnMgr.InjectPacket(pkt)
		}
	}
}

func (n *Node) rememberPeerLocked(p *connectedPeer) {
	devID := NormalizeDeviceID(p.deviceID)
	if devID == "" {
		return
	}
	kp := config.KnownPeer{
		DeviceID:      devID,
		Name:          p.name,
		OS:            p.osInfo,
		VPNIP:         p.vpnIP,
		Fingerprint:   p.fingerprint,
		LastConnected: time.Now().UTC().Format(time.RFC3339),
	}
	if strings.HasPrefix(p.transport, "QUIC") && p.remoteAddr != "" {
		if h, _, err := net.SplitHostPort(p.remoteAddr); err != nil || !IsSlowOverlayIP(net.ParseIP(h)) {
			kp.QUICAddr = p.remoteAddr
		}
	} else if (strings.HasPrefix(p.remoteAddr, "ws://") || strings.HasPrefix(p.remoteAddr, "wss://")) &&
		!strings.Contains(strings.ToLower(p.remoteAddr), ".trycloudflare.com") {
		kp.WSURL = p.remoteAddr
	}
	updated := false
	for i := range n.cfg.KnownPeers {
		if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == devID {
			prev := n.cfg.KnownPeers[i]
			// A name the user set wins over the remote hostname sent on every (re)connect.
			if prev.CustomName && prev.Name != "" {
				kp.Name = prev.Name
				kp.CustomName = true
			} else if kp.Name == "" {
				kp.Name = prev.Name
			}
			if kp.OS == "" {
				kp.OS = prev.OS
			}
			if kp.VPNIP == "" {
				kp.VPNIP = prev.VPNIP
			}
			if kp.QUICAddr == "" && prev.QUICAddr != "" {
				if h, _, err := net.SplitHostPort(prev.QUICAddr); err != nil || !IsSlowOverlayIP(net.ParseIP(h)) {
					kp.QUICAddr = prev.QUICAddr
				}
			}
			if kp.WSURL == "" && !strings.Contains(strings.ToLower(prev.WSURL), ".trycloudflare.com") {
				kp.WSURL = prev.WSURL
			}
			kp.SavedPassword = prev.SavedPassword
			kp.Group = prev.Group
			n.cfg.KnownPeers[i] = kp
			updated = true
			break
		}
	}
	if !updated {
		n.cfg.KnownPeers = append(n.cfg.KnownPeers, kp)
	}
	n.persistConfigLocked()
}

func (n *Node) servePeerStreams(ctx context.Context, p *connectedPeer) {
	defer func() {
		p.cancel()
		_ = p.session.Close()
		n.mu.Lock()
		if cur, ok := n.peers[p.id]; ok && cur == p {
			delete(n.peers, p.id)
		}
		n.mu.Unlock()
		n.logger.Info("p2p peer disconnected", "peer_id", p.id)
	}()

	for {
		stream, err := p.session.AcceptStream(ctx)
		if err != nil {
			return
		}
		go n.handleIncomingRemoteStream(ctx, p, stream)
	}
}

func (n *Node) handleIncomingRemoteStream(ctx context.Context, p *connectedPeer, stream io.ReadWriteCloser) {
	var req protocol.StreamOpenRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		_ = stream.Close()
		return
	}

	n.mu.RLock()
	paused := n.paused
	n.mu.RUnlock()
	if paused {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote access is paused by device owner",
		})
		_ = stream.Close()
		return
	}

	// A peer we connected to never proved it knows OUR password, so it gets no access to this
	// machine unless the owner allowed reverse access. Only the VPN stream is let through while
	// the VPN is enabled (it carries packets for the tunnel this side set up).
	if p.outbound && !n.cfg.AllowReverseAccess && !(req.Mode == protocol.ModeTUN && n.cfg.EnableVPN) {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "this device connected to you; it does not accept remote access back (allow_reverse_access is off)",
		})
		_ = stream.Close()
		return
	}

	switch req.Mode {
	case protocol.ModeTCP:
		n.serveIncomingTCP(p, stream, req)
	case protocol.ModeScreen:
		n.serveIncomingScreen(p, stream, req)
	case protocol.ModeShell:
		n.serveIncomingShell(ctx, p, stream)
	case protocol.ModeFiles:
		n.serveIncomingFiles(p, stream)
	case protocol.ModeClipboard:
		n.serveIncomingClipboard(p, stream)
	case protocol.ModeTUN:
		n.serveIncomingTUN(p, stream)
	default:
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "unsupported stream mode",
		})
		_ = stream.Close()
	}
}

func (n *Node) serveIncomingClipboard(p *connectedPeer, stream io.ReadWriteCloser) {
	if !n.cfg.AllowInput {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: false, Error: "remote clipboard is disabled by host"})
		_ = stream.Close()
		return
	}
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = stream.Close()
		return
	}
	_ = remote.ServeClipboardStream(stream)
}

func (n *Node) serveIncomingFiles(p *connectedPeer, stream io.ReadWriteCloser) {
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = stream.Close()
		return
	}
	ls := n.trackSession(p.id, "files://p2p", func() {
		_ = stream.Close()
	})
	p.activeConns.Add(1)
	defer func() {
		p.activeConns.Add(-1)
		n.untrackSession(ls)
	}()
	_ = remote.ServeFileStream(stream, &ls.sent, &ls.recv)
}

func (n *Node) serveIncomingTUN(p *connectedPeer, stream io.ReadWriteCloser) {
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = stream.Close()
		return
	}
	defer stream.Close()

	ls := n.trackSession(p.id, "vpn://"+p.vpnIP, func() {
		_ = stream.Close()
	})
	p.activeConns.Add(1)
	defer func() {
		p.activeConns.Add(-1)
		n.untrackSession(ls)
	}()

	buf := make([]byte, vpn.DefaultMTU+128)
	for {
		pkt, err := vpn.ReadIPPacket(stream, buf)
		if err != nil {
			return
		}
		ls.recv.Add(int64(len(pkt)))
		n.totalRecv.Add(int64(len(pkt)))
		if !n.acceptVPNPacket(p, pkt) {
			continue
		}

		n.mu.RLock()
		sink := n.packetSink
		n.mu.RUnlock()
		if sink != nil {
			sink(append([]byte(nil), pkt...))
		}
		if n.vpnMgr != nil {
			_ = n.vpnMgr.InjectPacket(pkt)
		}
	}
}

func (n *Node) serveIncomingTCP(p *connectedPeer, stream io.ReadWriteCloser, req protocol.StreamOpenRequest) {
	if !n.isTargetAllowed(req.TargetAddr) {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "target is not in peer allowed_targets list",
		})
		_ = stream.Close()
		return
	}
	targetConn, err := net.DialTimeout("tcp", req.TargetAddr, 10*time.Second)
	if err != nil {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: fmt.Sprintf("dial local target %s failed: %v", req.TargetAddr, err),
		})
		_ = stream.Close()
		return
	}
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = targetConn.Close()
		_ = stream.Close()
		return
	}

	ls := n.trackSession(p.id, req.TargetAddr, func() {
		_ = targetConn.Close()
		_ = stream.Close()
	})
	p.activeConns.Add(1)
	defer func() {
		p.activeConns.Add(-1)
		n.untrackSession(ls)
	}()

	protocol.PipeBidirectional(targetConn, stream, &ls.sent, &ls.recv)
}

func (n *Node) serveIncomingScreen(p *connectedPeer, stream io.ReadWriteCloser, req protocol.StreamOpenRequest) {
	if !n.cfg.AllowScreen {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote screen is disabled on this peer",
		})
		_ = stream.Close()
		return
	}
	w, h := remote.ScreenSize()
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{
		OK:           true,
		ScreenWidth:  w,
		ScreenHeight: h,
		AllowInput:   n.cfg.AllowInput,
	}); err != nil {
		_ = stream.Close()
		return
	}

	ls := n.trackSession(p.id, "screen://desktop", func() {
		_ = stream.Close()
	})
	p.activeConns.Add(1)
	defer func() {
		p.activeConns.Add(-1)
		n.untrackSession(ls)
		_ = stream.Close()
	}()

	_ = remote.ServeScreenSession(stream, remote.StreamOptions{
		InitialFPS:      req.FPS,
		InitialQuality:  req.Quality,
		InitialCodec:    req.Codec,
		InitialMaxWidth: req.MaxWidth,
		LocalCursor:     req.LocalCursor,
		AllowInput:      n.cfg.AllowInput,
		BytesSent:       &ls.sent,
		BytesRecv:       &ls.recv,
	})
}

func (n *Node) serveIncomingShell(ctx context.Context, p *connectedPeer, stream io.ReadWriteCloser) {
	if !n.cfg.AllowShell {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote shell is disabled on this peer",
		})
		_ = stream.Close()
		return
	}
	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = stream.Close()
		return
	}
	shellCtx, cancel := context.WithCancel(ctx)
	ls := n.trackSession(p.id, "shell://terminal", func() {
		cancel()
		_ = stream.Close()
	})
	p.activeConns.Add(1)
	defer func() {
		cancel()
		p.activeConns.Add(-1)
		n.untrackSession(ls)
	}()

	_ = remote.ServeShellSession(shellCtx, stream, &ls.sent, &ls.recv)
}

// OpenPeerStream opens an outbound Screen, Shell, or TCP stream to a connected P2P peer.
func (n *Node) OpenPeerStream(ctx context.Context, peerID string, req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, error) {
	n.mu.RLock()
	p, ok := n.peers[peerID]
	if !ok {
		norm := NormalizeDeviceID(peerID)
		for _, candidate := range n.peers {
			if candidate.deviceID == norm && norm != "" {
				p = candidate
				ok = true
				break
			}
		}
	}
	n.mu.RUnlock()
	if !ok {
		return nil, protocol.StreamOpenResponse{}, fmt.Errorf("peer %q is not connected", peerID)
	}

	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stream, err := p.session.OpenStream(openCtx)
	if err != nil {
		return nil, protocol.StreamOpenResponse{}, err
	}
	if err := protocol.WriteMessage(stream, req); err != nil {
		_ = stream.Close()
		return nil, protocol.StreamOpenResponse{}, err
	}
	var resp protocol.StreamOpenResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		_ = stream.Close()
		return nil, protocol.StreamOpenResponse{}, err
	}
	if !resp.OK {
		_ = stream.Close()
		return nil, resp, errors.New(resp.Error)
	}
	return stream, resp, nil
}

// DisconnectPeer closes the P2P connection to a specific peer.
func (n *Node) DisconnectPeer(peerID string) error {
	n.mu.Lock()
	p, ok := n.peers[peerID]
	if ok {
		delete(n.peers, peerID)
	}
	n.mu.Unlock()
	if !ok {
		return errors.New("peer not found")
	}
	p.cancel()
	_ = p.session.Close()
	return nil
}

// SetPaused lets the device owner pause or resume accepting incoming remote access.
func (n *Node) SetPaused(paused bool) {
	n.mu.Lock()
	n.paused = paused
	n.mu.Unlock()
}

// DisconnectAllSessions immediately terminates all active incoming remote sessions.
func (n *Node) DisconnectAllSessions() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	count := len(n.sessions)
	for _, ls := range n.sessions {
		ls.closeFn()
	}
	return count
}

// AddTunnel binds a local TCP port to an allowed service on a connected P2P peer.
func (n *Node) AddTunnel(name, localAddr, peerID, targetAddr string, enable bool) (TunnelStatus, error) {
	localAddr = strings.TrimSpace(localAddr)
	peerID = strings.TrimSpace(peerID)
	targetAddr = strings.TrimSpace(targetAddr)
	if localAddr == "" || peerID == "" || targetAddr == "" {
		return TunnelStatus{}, errors.New("local_addr, peer_id, and target_addr are required")
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("%s -> %s", peerID, targetAddr)
	}
	id := fmt.Sprintf("ptun-%d", n.tunSeq.Add(1))
	t := &managedTunnel{
		id:         id,
		name:       name,
		localAddr:  localAddr,
		peerID:     peerID,
		targetAddr: targetAddr,
	}
	n.mu.Lock()
	n.tunnels[id] = t
	n.tunnelOrder = append(n.tunnelOrder, id)
	n.mu.Unlock()

	if enable {
		if err := n.startTunnel(t); err != nil {
			return t.status(), err
		}
	}
	return t.status(), nil
}

// ToggleTunnel starts or stops a P2P local TCP tunnel.
func (n *Node) ToggleTunnel(id string, enable bool) (TunnelStatus, error) {
	n.mu.RLock()
	t, ok := n.tunnels[id]
	n.mu.RUnlock()
	if !ok {
		return TunnelStatus{}, errors.New("tunnel not found")
	}
	if enable {
		err := n.startTunnel(t)
		return t.status(), err
	}
	n.stopTunnel(t)
	return t.status(), nil
}

// RemoveTunnel stops and removes a P2P local TCP tunnel.
func (n *Node) RemoveTunnel(id string) error {
	n.mu.Lock()
	t, ok := n.tunnels[id]
	if !ok {
		n.mu.Unlock()
		return errors.New("tunnel not found")
	}
	delete(n.tunnels, id)
	n.tunnelOrder = slices.DeleteFunc(n.tunnelOrder, func(s string) bool { return s == id })
	n.mu.Unlock()
	n.stopTunnel(t)
	return nil
}

func (n *Node) startTunnel(t *managedTunnel) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}
	ln, err := net.Listen("tcp", t.localAddr)
	if err != nil {
		t.lastError = err.Error()
		return err
	}
	t.localAddr = ln.Addr().String()
	t.listener = ln
	t.running = true
	t.lastError = ""
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go n.forwardTunnelConn(t, conn)
		}
	}()
	return nil
}

func (n *Node) stopTunnel(t *managedTunnel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	t.running = false
}

func (n *Node) stopAllTunnels() {
	n.mu.RLock()
	list := make([]*managedTunnel, 0, len(n.tunnels))
	for _, t := range n.tunnels {
		list = append(list, t)
	}
	n.mu.RUnlock()
	for _, t := range list {
		n.stopTunnel(t)
	}
}

func (n *Node) forwardTunnelConn(t *managedTunnel, localConn net.Conn) {
	ctx := n.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	stream, _, err := n.OpenPeerStream(ctx, t.peerID, protocol.StreamOpenRequest{
		Mode:       protocol.ModeTCP,
		TargetAddr: t.targetAddr,
	})
	if err != nil {
		t.mu.Lock()
		t.lastError = err.Error()
		t.mu.Unlock()
		_ = localConn.Close()
		return
	}
	t.mu.Lock()
	t.lastError = ""
	t.mu.Unlock()

	t.activeConns.Add(1)
	defer t.activeConns.Add(-1)
	protocol.PipeBidirectional(localConn, stream, &t.bytesSent, &t.bytesRecv)
}

func (t *managedTunnel) status() TunnelStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelStatus{
		ID:          t.id,
		Name:        t.name,
		LocalAddr:   t.localAddr,
		PeerID:      t.peerID,
		TargetAddr:  t.targetAddr,
		Running:     t.running,
		LastError:   t.lastError,
		ActiveConns: t.activeConns.Load(),
		BytesSent:   t.bytesSent.Load(),
		BytesRecv:   t.bytesRecv.Load(),
	}
}

func (p *connectedPeer) info() PeerInfo {
	return PeerInfo{
		DeviceID:     p.deviceID,
		ID:           p.id,
		Name:         p.name,
		OS:           p.osInfo,
		Version:      p.appVersion,
		VPNIP:        p.vpnIP,
		Fingerprint:  p.fingerprint,
		RemoteAddr:   p.remoteAddr,
		Transport:    p.transport,
		ConnectedAt:  p.connectedAt,
		Targets:      slices.Clone(p.targets),
		Capabilities: p.capabilities,
		ActiveConns:  p.activeConns.Load(),
	}
}

func (n *Node) trackSession(peerID, target string, closeFn func()) *liveSession {
	id := fmt.Sprintf("psess-%d", n.seq.Add(1))
	ls := &liveSession{
		id:         id,
		peerID:     peerID,
		targetAddr: target,
		startedAt:  time.Now().UTC(),
		closeFn:    closeFn,
	}
	n.mu.Lock()
	n.sessions[id] = ls
	n.mu.Unlock()
	return ls
}

func (n *Node) untrackSession(ls *liveSession) {
	n.mu.Lock()
	delete(n.sessions, ls.id)
	n.mu.Unlock()
	n.totalSent.Add(ls.sent.Load())
	n.totalRecv.Add(ls.recv.Load())
}

func (n *Node) isTargetAllowed(target string) bool {
	norm := strings.ToLower(strings.TrimSpace(target))
	for _, a := range n.cfg.AllowedTargets {
		if strings.ToLower(strings.TrimSpace(a.Address)) == norm {
			return true
		}
	}
	return false
}

// Snapshot returns live Unified P2P Node status for the Web Dashboard.
func (n *Node) Snapshot() NodeSnapshot {
	n.mu.RLock()
	peers := make([]PeerInfo, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p.info())
	}
	approvals := make([]PendingApproval, 0, len(n.approvals))
	for _, w := range n.approvals {
		approvals = append(approvals, w.info)
	}
	var liveSent, liveRecv int64
	sessions := make([]ActiveSession, 0, len(n.sessions))
	for _, ls := range n.sessions {
		s := ls.sent.Load()
		r := ls.recv.Load()
		liveSent += s
		liveRecv += r
		sessions = append(sessions, ActiveSession{
			ID:         ls.id,
			PeerID:     ls.peerID,
			TargetAddr: ls.targetAddr,
			StartedAt:  ls.startedAt,
			BytesSent:  s,
			BytesRecv:  r,
		})
	}
	tunnels := make([]TunnelStatus, 0, len(n.tunnelOrder))
	for _, id := range n.tunnelOrder {
		if t, ok := n.tunnels[id]; ok {
			tunnels = append(tunnels, t.status())
		}
	}
	tempPIN := n.tempPIN
	hasPerm := n.cfg.PermanentPasswordHash != ""
	reqApproval := n.cfg.RequireApproval
	rdvURL := n.rendezvousURL
	rdvStatus := n.rendezvousStatus
	pubUDP := n.publicUDPAddr
	stunErr := n.stunErr
	pubWS := n.publicWSURL
	paused := n.paused
	knownCopy := make([]config.KnownPeer, len(n.cfg.KnownPeers))
	copy(knownCopy, n.cfg.KnownPeers)
	presenceCopy := make(map[string]peerPresence, len(n.presence))
	for k, v := range n.presence {
		presenceCopy[k] = v
	}
	n.mu.RUnlock()

	var discovered []DiscoveredPeer
	if n.lanDisc != nil {
		discovered = n.lanDisc.list()
	}

	connectedByDev := make(map[string]PeerInfo, len(peers))
	for _, p := range peers {
		if id := NormalizeDeviceID(p.DeviceID); id != "" {
			connectedByDev[id] = p
		}
	}
	lanByDev := make(map[string]DiscoveredPeer, len(discovered))
	for _, dp := range discovered {
		if id := NormalizeDeviceID(dp.DeviceID); id != "" {
			lanByDev[id] = dp
		}
	}

	savedPeers := make([]SavedPeerInfo, 0, len(knownCopy))
	for _, kp := range knownCopy {
		id := NormalizeDeviceID(kp.DeviceID)
		if id == "" || id == n.cfg.DeviceID {
			continue
		}
		sp := SavedPeerInfo{
			DeviceID:         id,
			Name:             kp.Name,
			Group:            kp.Group,
			OS:               kp.OS,
			VPNIP:            kp.VPNIP,
			HasSavedPassword: kp.SavedPassword != "",
			LastConnected:    kp.LastConnected,
		}
		if cp, ok := connectedByDev[id]; ok {
			sp.Connected = true
			sp.Online = true
			sp.OnlineVia = "connected"
			sp.Version = cp.Version
			if sp.Name == "" {
				sp.Name = cp.Name
			}
			if sp.OS == "" {
				sp.OS = cp.OS
			}
			if sp.VPNIP == "" {
				sp.VPNIP = cp.VPNIP
			}
		} else if dp, ok := lanByDev[id]; ok {
			sp.Online = true
			sp.OnlineVia = "lan"
			if sp.Name == "" {
				sp.Name = dp.Name
			}
			if sp.OS == "" {
				sp.OS = dp.OS
			}
		} else if pr, ok := presenceCopy[id]; ok && pr.online {
			sp.Online = true
			sp.OnlineVia = "cloud"
			if sp.Name == "" && pr.name != "" {
				sp.Name = pr.name
			}
			if sp.OS == "" && pr.osInfo != "" {
				sp.OS = pr.osInfo
			}
		}
		if sp.Name == "" {
			sp.Name = FormatDeviceID(id)
		}
		savedPeers = append(savedPeers, sp)
	}
	slices.SortFunc(savedPeers, func(a, b SavedPeerInfo) int {
		rank := func(s SavedPeerInfo) int {
			if s.Connected {
				return 0
			}
			if s.Online {
				return 1
			}
			return 2
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		if a.LastConnected != b.LastConnected {
			if a.LastConnected > b.LastConnected {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})

	targets := make([]config.AllowedTarget, len(n.cfg.AllowedTargets))
	copy(targets, n.cfg.AllowedTargets)

	return NodeSnapshot{
		DeviceID:             n.cfg.DeviceID,
		TempPIN:              tempPIN,
		HasPermanentPassword: hasPerm,
		RequireApproval:      reqApproval,
		RendezvousURL:        rdvURL,
		RendezvousStatus:     rdvStatus,
		PeerID:               n.cfg.PeerID,
		Name:                 n.cfg.Name,
		OS:                   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Fingerprint:          n.identity.Fingerprint,
		PairSecret:           n.cfg.PairSecret,
		QUICListenAddr:       n.quicAddrStr,
		WSListenAddr:         n.wsAddrStr,
		PublicUDPAddr:        pubUDP,
		STUNError:            stunErr,
		PublicWSURL:          pubWS,
		Ticket:               n.MyTicket(),
		Paused:               paused,
		VPN:                  n.vpnMgr.Status(),
		Bridge:               n.bridge.Status(),
		Deps:                 n.depsMgr.Status(),
		Install:              installer.GetStatus(),
		Update:               n.updMgr.Status(),
		Capabilities: protocol.AgentCapabilities{
			AllowScreen: n.cfg.AllowScreen,
			AllowInput:  n.cfg.AllowInput,
			AllowShell:  n.cfg.AllowShell,
			AllowFiles:  true,
			HasFFmpeg:   bootstrap.HasFFmpeg(),
		},
		AllowedTargets:   targets,
		PendingApprovals: approvals,
		ConnectedPeers:   peers,
		SavedPeers:       savedPeers,
		Account:          n.accountStatusLocked(),
		DiscoveredPeers:  discovered,
		ActiveSessions:   sessions,
		Tunnels:          tunnels,
		TotalBytesSent:   n.totalSent.Load() + liveSent,
		TotalBytesRecv:   n.totalRecv.Load() + liveRecv,
	}
}

// NormalizeDeviceID keeps only digits from a 9-digit Device ID string.
func NormalizeDeviceID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FormatDeviceID formats "482917305" as "482 917 305".
func FormatDeviceID(id string) string {
	digits := NormalizeDeviceID(id)
	if len(digits) != 9 {
		return id
	}
	return digits[0:3] + " " + digits[3:6] + " " + digits[6:9]
}

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true, // RFC 9221 Unreliable Datagrams for zero-HoL L3 VPN!
		// 5s keepalive / 20s idle: a dead path (Wi-Fi switch, sleep, NAT timeout) is detected in
		// about 20s instead of 60s so the viewer reconnects quickly, and NAT mappings stay open.
		KeepAlivePeriod:                5 * time.Second,
		MaxIdleTimeout:                 20 * time.Second,
		InitialStreamReceiveWindow:     4 << 20,  // 4 MiB for smooth 1080p keyframes
		MaxStreamReceiveWindow:         16 << 20, // 16 MiB
		InitialConnectionReceiveWindow: 8 << 20,  // 8 MiB
		MaxConnectionReceiveWindow:     32 << 20, // 32 MiB
	}
}
