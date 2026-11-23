package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"relayvpn/internal/config"
	"relayvpn/internal/protocol"
	"relayvpn/internal/security"
)

// TunnelStatus describes a configured local TCP port-forward tunnel.
type TunnelStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LocalAddr   string `json:"local_addr"`
	AgentID     string `json:"agent_id"`
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
	agentID    string
	targetAddr string

	mu        sync.Mutex
	running   bool
	lastError string
	listener  net.Listener

	activeConns atomic.Int64
	bytesSent   atomic.Int64
	bytesRecv   atomic.Int64
}

// Snapshot holds the live Client state for the Web UI.
type Snapshot struct {
	ClientID    string               `json:"client_id"`
	ServerURL   string               `json:"server_url"`
	State       string               `json:"state"`
	LastError   string               `json:"last_error,omitempty"`
	ConnectedAt *time.Time           `json:"connected_at,omitempty"`
	Agents      []protocol.AgentInfo `json:"agents"`
	Tunnels     []TunnelStatus       `json:"tunnels"`
}

// Client connects outbound over TLS 1.3 + WSS to the Relay Server and manages local port-forwards.
type Client struct {
	cfg    *config.ClientConfig
	logger *slog.Logger
	tlsCfg *tls.Config

	mu          sync.RWMutex
	state       string
	lastErr     string
	connectedAt *time.Time
	session     *yamux.Session
	agents      []protocol.AgentInfo
	tunnels     map[string]*managedTunnel
	tunnelOrder []string

	seq atomic.Uint64
}

// New creates a Client with initial tunnels loaded from config.
func New(cfg *config.ClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("client config is nil")
	}
	tlsCfg, err := security.ClientTLSConfig(cfg.CAFile, cfg.ServerName)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	c := &Client{
		cfg:     cfg,
		logger:  logger,
		tlsCfg:  tlsCfg,
		state:   "starting",
		tunnels: make(map[string]*managedTunnel),
	}

	for _, rule := range cfg.Tunnels {
		t := c.registerTunnelLocked(rule)
		if rule.Enabled {
			if err := c.startTunnel(t); err != nil {
				c.logger.Warn("failed to start configured tunnel", "name", rule.Name, "err", err)
			}
		}
	}

	return c, nil
}

// Run maintains the outbound WSS 443 connection to the Relay Server until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	defer c.stopAllTunnels()

	for {
		if ctx.Err() != nil {
			c.setState("stopped", "", nil, nil)
			return nil
		}

		c.setState("connecting", "", nil, nil)
		connectedDuration, err := c.connectAndMaintain(ctx)
		if ctx.Err() != nil {
			c.setState("stopped", "", nil, nil)
			return nil
		}

		if connectedDuration > 15*time.Second {
			backoff = time.Second
		}

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		c.setState("reconnecting", errMsg, nil, nil)
		c.logger.Warn("client disconnected from relay; reconnecting", "backoff", backoff, "err", err)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.setState("stopped", "", nil, nil)
			return nil
		case <-timer.C:
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) connectAndMaintain(ctx context.Context) (time.Duration, error) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, err := protocol.DialSession(sessCtx, protocol.DialOptions{
		ServerURL: c.cfg.ServerURL,
		Token:     c.cfg.Token,
		Role:      protocol.RoleClient,
		PeerID:    c.cfg.ClientID,
		PeerOS:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		TLSConfig: c.tlsCfg,
		AsServer:  false, // Client initiates streams toward Relay Server
	})
	if err != nil {
		return 0, err
	}
	defer session.Close()

	now := time.Now().UTC()
	c.setState("connected", "", &now, session)
	c.logger.Info("client connected to relay", "server", c.cfg.ServerURL, "client_id", c.cfg.ClientID)

	_, _ = c.RefreshAgents(ctx)

	// Periodically refresh online agents list while connected.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return time.Since(now), nil
		case <-session.CloseChan():
			return time.Since(now), errors.New("relay session closed")
		case <-ticker.C:
			_, _ = c.RefreshAgents(ctx)
		}
	}
}

// RefreshAgents queries the Relay Server for all online Agents this Client is permitted to access.
func (c *Client) RefreshAgents(ctx context.Context) ([]protocol.AgentInfo, error) {
	session := c.getSession()
	if session == nil {
		return nil, errors.New("client is not connected to relay server")
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	}

	req := protocol.StreamOpenRequest{
		Mode:   protocol.ModeControl,
		Action: "list_agents",
	}
	if err := protocol.WriteMessage(stream, req); err != nil {
		return nil, err
	}
	var resp protocol.StreamOpenResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}

	c.mu.Lock()
	c.agents = slices.Clone(resp.Agents)
	c.mu.Unlock()
	return resp.Agents, nil
}

// OpenScreenStream opens a multiplexed live Remote Desktop stream to an online Agent.
func (c *Client) OpenScreenStream(agentID string, fps, quality int) (*yamux.Stream, protocol.StreamOpenResponse, error) {
	return c.OpenScreenStreamRequest(protocol.StreamOpenRequest{
		Mode:    protocol.ModeScreen,
		AgentID: agentID,
		FPS:     fps,
		Quality: quality,
	})
}

// OpenScreenStreamRequest opens a live Remote Desktop stream with full codec/resolution options.
func (c *Client) OpenScreenStreamRequest(req protocol.StreamOpenRequest) (*yamux.Stream, protocol.StreamOpenResponse, error) {
	req.Mode = protocol.ModeScreen
	return c.openRemoteStream(req)
}

// OpenShellStream opens an interactive Remote Terminal stream to an online Agent.
func (c *Client) OpenShellStream(agentID string) (*yamux.Stream, protocol.StreamOpenResponse, error) {
	return c.openRemoteStream(protocol.StreamOpenRequest{
		Mode:    protocol.ModeShell,
		AgentID: agentID,
	})
}

func (c *Client) openRemoteStream(req protocol.StreamOpenRequest) (*yamux.Stream, protocol.StreamOpenResponse, error) {
	session := c.getSession()
	if session == nil {
		return nil, protocol.StreamOpenResponse{}, errors.New("client is not connected to relay server")
	}

	stream, err := session.OpenStream()
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

// AddTunnel registers a new local port-forward tunnel and optionally starts listening immediately.
func (c *Client) AddTunnel(rule config.TunnelRule) (TunnelStatus, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.LocalAddr = strings.TrimSpace(rule.LocalAddr)
	rule.AgentID = strings.TrimSpace(rule.AgentID)
	rule.TargetAddr = strings.TrimSpace(rule.TargetAddr)

	if rule.LocalAddr == "" || rule.AgentID == "" || rule.TargetAddr == "" {
		return TunnelStatus{}, errors.New("local_addr, agent_id, and target_addr are required")
	}
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("%s -> %s", rule.AgentID, rule.TargetAddr)
	}

	c.mu.Lock()
	t := c.registerTunnelLocked(rule)
	c.mu.Unlock()

	if rule.Enabled {
		if err := c.startTunnel(t); err != nil {
			return t.status(), err
		}
	}
	return t.status(), nil
}

// ToggleTunnel starts or stops a tunnel by ID.
func (c *Client) ToggleTunnel(id string, enable bool) (TunnelStatus, error) {
	c.mu.RLock()
	t, ok := c.tunnels[id]
	c.mu.RUnlock()
	if !ok {
		return TunnelStatus{}, errors.New("tunnel not found")
	}

	if enable {
		err := c.startTunnel(t)
		return t.status(), err
	}
	c.stopTunnel(t)
	return t.status(), nil
}

// RemoveTunnel stops and deletes a tunnel by ID.
func (c *Client) RemoveTunnel(id string) error {
	c.mu.Lock()
	t, ok := c.tunnels[id]
	if !ok {
		c.mu.Unlock()
		return errors.New("tunnel not found")
	}
	delete(c.tunnels, id)
	c.tunnelOrder = slices.DeleteFunc(c.tunnelOrder, func(s string) bool { return s == id })
	c.mu.Unlock()

	c.stopTunnel(t)
	return nil
}

func (c *Client) registerTunnelLocked(rule config.TunnelRule) *managedTunnel {
	id := fmt.Sprintf("tun-%d", c.seq.Add(1))
	t := &managedTunnel{
		id:         id,
		name:       rule.Name,
		localAddr:  rule.LocalAddr,
		agentID:    rule.AgentID,
		targetAddr: rule.TargetAddr,
	}
	c.tunnels[id] = t
	c.tunnelOrder = append(c.tunnelOrder, id)
	return t
}

func (c *Client) startTunnel(t *managedTunnel) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}

	ln, err := net.Listen("tcp", t.localAddr)
	if err != nil {
		t.lastError = err.Error()
		return fmt.Errorf("listen %s: %w", t.localAddr, err)
	}

	t.localAddr = ln.Addr().String()
	t.listener = ln
	t.running = true
	t.lastError = ""
	c.logger.Info("local tunnel listening", "name", t.name, "local", t.localAddr, "agent", t.agentID, "target", t.targetAddr)

	go c.acceptLoop(t, ln)
	return nil
}

func (c *Client) stopTunnel(t *managedTunnel) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	t.running = false
}

func (c *Client) stopAllTunnels() {
	c.mu.RLock()
	list := make([]*managedTunnel, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		list = append(list, t)
	}
	c.mu.RUnlock()
	for _, t := range list {
		c.stopTunnel(t)
	}
}

func (c *Client) acceptLoop(t *managedTunnel, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.forwardConn(t, conn)
	}
}

func (c *Client) forwardConn(t *managedTunnel, localConn net.Conn) {
	session := c.getSession()
	if session == nil {
		t.setLastError("not connected to relay server")
		_ = localConn.Close()
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		t.setLastError(err.Error())
		_ = localConn.Close()
		return
	}

	req := protocol.StreamOpenRequest{
		Mode:       protocol.ModeTCP,
		AgentID:    t.agentID,
		TargetAddr: t.targetAddr,
	}
	if err := protocol.WriteMessage(stream, req); err != nil {
		t.setLastError(err.Error())
		_ = stream.Close()
		_ = localConn.Close()
		return
	}

	var resp protocol.StreamOpenResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		t.setLastError(err.Error())
		_ = stream.Close()
		_ = localConn.Close()
		return
	}
	if !resp.OK {
		t.setLastError(resp.Error)
		c.logger.Warn("remote tunnel stream rejected", "tunnel", t.name, "err", resp.Error)
		_ = stream.Close()
		_ = localConn.Close()
		return
	}

	t.setLastError("")
	t.activeConns.Add(1)
	defer t.activeConns.Add(-1)

	protocol.PipeBidirectional(localConn, stream, &t.bytesSent, &t.bytesRecv)
}

func (t *managedTunnel) setLastError(msg string) {
	t.mu.Lock()
	t.lastError = msg
	t.mu.Unlock()
}

func (t *managedTunnel) status() TunnelStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelStatus{
		ID:          t.id,
		Name:        t.name,
		LocalAddr:   t.localAddr,
		AgentID:     t.agentID,
		TargetAddr:  t.targetAddr,
		Running:     t.running,
		LastError:   t.lastError,
		ActiveConns: t.activeConns.Load(),
		BytesSent:   t.bytesSent.Load(),
		BytesRecv:   t.bytesRecv.Load(),
	}
}

func (c *Client) getSession() *yamux.Session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session
}

func (c *Client) setState(state, errMsg string, connectedAt *time.Time, session *yamux.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
	c.lastErr = errMsg
	c.session = session
	if connectedAt != nil {
		t := *connectedAt
		c.connectedAt = &t
	} else if state != "connected" {
		c.connectedAt = nil
	}
}

// Snapshot returns live Client status for the Web UI.
func (c *Client) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tunnels := make([]TunnelStatus, 0, len(c.tunnelOrder))
	for _, id := range c.tunnelOrder {
		if t, ok := c.tunnels[id]; ok {
			tunnels = append(tunnels, t.status())
		}
	}

	var connCopy *time.Time
	if c.connectedAt != nil {
		t := *c.connectedAt
		connCopy = &t
	}

	return Snapshot{
		ClientID:    c.cfg.ClientID,
		ServerURL:   c.cfg.ServerURL,
		State:       c.state,
		LastError:   c.lastErr,
		ConnectedAt: connCopy,
		Agents:      slices.Clone(c.agents),
		Tunnels:     tunnels,
	}
}
