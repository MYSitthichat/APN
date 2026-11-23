package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/config"
	"relayvpn/internal/protocol"
	"relayvpn/internal/remote"
	"relayvpn/internal/security"
)

// ActiveSession tracks a live remote session (TCP tunnel, Screen, or Shell) on this Agent.
type ActiveSession struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"client_id"`
	TargetAddr string    `json:"target_addr"`
	StartedAt  time.Time `json:"started_at"`
	BytesSent  int64     `json:"bytes_sent"`
	BytesRecv  int64     `json:"bytes_recv"`
}

type liveSession struct {
	id         string
	clientID   string
	targetAddr string
	startedAt  time.Time
	sent       atomic.Int64
	recv       atomic.Int64
	closeFn    func()
}

// Snapshot describes the live Agent status for the local Web UI.
type Snapshot struct {
	AgentID        string                     `json:"agent_id"`
	Name           string                     `json:"name"`
	ServerURL      string                     `json:"server_url"`
	State          string                     `json:"state"`
	LastError      string                     `json:"last_error,omitempty"`
	Paused         bool                       `json:"paused"`
	ConnectedAt    *time.Time                 `json:"connected_at,omitempty"`
	Capabilities   protocol.AgentCapabilities `json:"capabilities"`
	AllowedTargets []config.AllowedTarget     `json:"allowed_targets"`
	ActiveSessions []ActiveSession            `json:"active_sessions"`
	TotalBytesSent int64                      `json:"total_bytes_sent"`
	TotalBytesRecv int64                      `json:"total_bytes_recv"`
}

// Agent runs on the target host and maintains an outbound TLS 1.3 + WSS connection to the Relay Server.
type Agent struct {
	cfg    *config.AgentConfig
	logger *slog.Logger
	tlsCfg *tls.Config

	mu          sync.RWMutex
	state       string
	lastErr     string
	connectedAt *time.Time
	paused      bool
	sessions    map[string]*liveSession

	seq       atomic.Uint64
	totalSent atomic.Int64
	totalRecv atomic.Int64
}

// New creates a configured Agent instance.
func New(cfg *config.AgentConfig, logger *slog.Logger) (*Agent, error) {
	if cfg == nil {
		return nil, errors.New("agent config is nil")
	}
	tlsCfg, err := security.ClientTLSConfig(cfg.CAFile, cfg.ServerName)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg:      cfg,
		logger:   logger,
		tlsCfg:   tlsCfg,
		state:    "starting",
		sessions: make(map[string]*liveSession),
	}, nil
}

// Run maintains a resilient outbound connection to the Relay Server with automatic exponential backoff.
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			a.setState("stopped", "", nil)
			return nil
		}

		a.setState("connecting", "", nil)
		connectedDuration, err := a.connectAndServe(ctx)
		if ctx.Err() != nil {
			a.setState("stopped", "", nil)
			return nil
		}

		if connectedDuration > 15*time.Second {
			backoff = time.Second
		}

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		a.setState("reconnecting", errMsg, nil)
		a.logger.Warn("agent disconnected from relay; reconnecting", "backoff", backoff, "err", err)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			a.setState("stopped", "", nil)
			return nil
		case <-timer.C:
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (a *Agent) connectAndServe(ctx context.Context) (time.Duration, error) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, err := protocol.DialSession(sessCtx, protocol.DialOptions{
		ServerURL: a.cfg.ServerURL,
		Token:     a.cfg.Token,
		Role:      protocol.RoleAgent,
		PeerID:    a.cfg.AgentID,
		PeerName:  a.cfg.Name,
		PeerOS:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		TLSConfig: a.tlsCfg,
		AsServer:  true,
	})
	if err != nil {
		return 0, err
	}
	defer session.Close()

	now := time.Now().UTC()
	a.setState("connected", "", &now)
	a.logger.Info("agent connected to relay", "server", a.cfg.ServerURL, "agent_id", a.cfg.AgentID)

	if err := a.advertiseTargets(session); err != nil {
		a.logger.Warn("failed to advertise targets", "err", err)
	}

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return time.Since(now), err
		}
		go a.handleStream(sessCtx, stream)
	}
}

func (a *Agent) advertiseTargets(session *yamux.Session) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	targets := make([]protocol.TargetInfo, 0, len(a.cfg.AllowedTargets))
	for _, t := range a.cfg.AllowedTargets {
		targets = append(targets, protocol.TargetInfo{
			Name:    t.Name,
			Address: t.Address,
		})
	}

	req := protocol.StreamOpenRequest{
		Mode:    protocol.ModeControl,
		Action:  "register_targets",
		Targets: targets,
		Capabilities: &protocol.AgentCapabilities{
			AllowScreen: a.cfg.AllowScreen,
			AllowInput:  a.cfg.AllowInput,
			AllowShell:  a.cfg.AllowShell,
			HasFFmpeg:   bootstrap.HasFFmpeg(),
		},
	}
	if err := protocol.WriteMessage(stream, req); err != nil {
		return err
	}
	var resp protocol.StreamOpenResponse
	if err := protocol.ReadMessage(stream, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}

func (a *Agent) handleStream(ctx context.Context, stream *yamux.Stream) {
	var req protocol.StreamOpenRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		_ = stream.Close()
		return
	}

	a.mu.RLock()
	paused := a.paused
	a.mu.RUnlock()
	if paused {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote access is paused by device owner",
		})
		_ = stream.Close()
		return
	}

	switch req.Mode {
	case protocol.ModeTCP:
		a.handleTCPStream(stream, req)
	case protocol.ModeScreen:
		a.handleScreenStream(stream, req)
	case protocol.ModeShell:
		a.handleShellStream(ctx, stream, req)
	default:
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "unsupported stream mode on agent",
		})
		_ = stream.Close()
	}
}

func (a *Agent) handleTCPStream(stream *yamux.Stream, req protocol.StreamOpenRequest) {
	if !a.isTargetAllowed(req.TargetAddr) {
		a.logger.Warn("blocked disallowed target access", "client_id", req.ClientID, "target", req.TargetAddr)
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "target is not in agent allowed_targets list",
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

	ls := a.trackSession(req.ClientID, req.TargetAddr, func() {
		_ = targetConn.Close()
		_ = stream.Close()
	})
	defer a.untrackSession(ls)

	protocol.PipeBidirectional(readWriteCloserWrap{targetConn}, stream, &ls.sent, &ls.recv)
}

func (a *Agent) handleScreenStream(stream *yamux.Stream, req protocol.StreamOpenRequest) {
	if !a.cfg.AllowScreen {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote screen is disabled in agent.json (set allow_screen: true)",
		})
		_ = stream.Close()
		return
	}

	w, h := remote.ScreenSize()
	resp := protocol.StreamOpenResponse{
		OK:           true,
		ScreenWidth:  w,
		ScreenHeight: h,
		AllowInput:   a.cfg.AllowInput,
	}
	if err := protocol.WriteMessage(stream, resp); err != nil {
		_ = stream.Close()
		return
	}

	ls := a.trackSession(req.ClientID, "screen://desktop", func() {
		_ = stream.Close()
	})
	defer a.untrackSession(ls)
	defer stream.Close()

	_ = remote.ServeScreenSession(stream, remote.StreamOptions{
		InitialFPS:      req.FPS,
		InitialQuality:  req.Quality,
		InitialCodec:    req.Codec,
		InitialMaxWidth: req.MaxWidth,
		AllowInput:      a.cfg.AllowInput,
		BytesSent:       &ls.sent,
		BytesRecv:       &ls.recv,
	})
}

func (a *Agent) handleShellStream(ctx context.Context, stream *yamux.Stream, req protocol.StreamOpenRequest) {
	if !a.cfg.AllowShell {
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "remote shell is disabled in agent.json (set allow_shell: true)",
		})
		_ = stream.Close()
		return
	}

	if err := protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true}); err != nil {
		_ = stream.Close()
		return
	}

	shellCtx, cancel := context.WithCancel(ctx)
	ls := a.trackSession(req.ClientID, "shell://terminal", func() {
		cancel()
		_ = stream.Close()
	})
	defer func() {
		cancel()
		a.untrackSession(ls)
	}()

	_ = remote.ServeShellSession(shellCtx, stream, &ls.sent, &ls.recv)
}

func (a *Agent) trackSession(clientID, target string, closeFn func()) *liveSession {
	sessID := fmt.Sprintf("sess-%d", a.seq.Add(1))
	ls := &liveSession{
		id:         sessID,
		clientID:   clientID,
		targetAddr: target,
		startedAt:  time.Now().UTC(),
		closeFn:    closeFn,
	}
	a.mu.Lock()
	a.sessions[sessID] = ls
	a.mu.Unlock()
	a.logger.Info("remote session opened", "session_id", sessID, "client_id", clientID, "target", target)
	return ls
}

func (a *Agent) untrackSession(ls *liveSession) {
	a.mu.Lock()
	delete(a.sessions, ls.id)
	a.mu.Unlock()
	a.totalSent.Add(ls.sent.Load())
	a.totalRecv.Add(ls.recv.Load())
	a.logger.Info("remote session closed", "session_id", ls.id, "target", ls.targetAddr)
}

type readWriteCloserWrap struct {
	io.ReadWriteCloser
}

func (a *Agent) isTargetAllowed(target string) bool {
	normalized := strings.ToLower(strings.TrimSpace(target))
	for _, allowed := range a.cfg.AllowedTargets {
		if strings.ToLower(strings.TrimSpace(allowed.Address)) == normalized {
			return true
		}
	}
	return false
}

// SetPaused lets the device owner pause or resume accepting new remote sessions.
func (a *Agent) SetPaused(paused bool) {
	a.mu.Lock()
	a.paused = paused
	a.mu.Unlock()
	a.logger.Info("agent pause state updated", "paused", paused)
}

// DisconnectAllSessions immediately terminates all active remote sessions on this device.
func (a *Agent) DisconnectAllSessions() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := len(a.sessions)
	for _, ls := range a.sessions {
		ls.closeFn()
	}
	return count
}

func (a *Agent) setState(state, errMsg string, connectedAt *time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = state
	a.lastErr = errMsg
	if connectedAt != nil {
		t := *connectedAt
		a.connectedAt = &t
	} else if state != "connected" {
		a.connectedAt = nil
	}
}

// Snapshot returns current Agent status for the Web UI.
func (a *Agent) Snapshot() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	active := make([]ActiveSession, 0, len(a.sessions))
	var liveSent, liveRecv int64
	for _, ls := range a.sessions {
		s := ls.sent.Load()
		r := ls.recv.Load()
		liveSent += s
		liveRecv += r
		active = append(active, ActiveSession{
			ID:         ls.id,
			ClientID:   ls.clientID,
			TargetAddr: ls.targetAddr,
			StartedAt:  ls.startedAt,
			BytesSent:  s,
			BytesRecv:  r,
		})
	}

	var connCopy *time.Time
	if a.connectedAt != nil {
		t := *a.connectedAt
		connCopy = &t
	}

	targets := make([]config.AllowedTarget, len(a.cfg.AllowedTargets))
	copy(targets, a.cfg.AllowedTargets)

	return Snapshot{
		AgentID:     a.cfg.AgentID,
		Name:        a.cfg.Name,
		ServerURL:   a.cfg.ServerURL,
		State:       a.state,
		LastError:   a.lastErr,
		Paused:      a.paused,
		ConnectedAt: connCopy,
		Capabilities: protocol.AgentCapabilities{
			AllowScreen: a.cfg.AllowScreen,
			AllowInput:  a.cfg.AllowInput,
			AllowShell:  a.cfg.AllowShell,
		},
		AllowedTargets: targets,
		ActiveSessions: active,
		TotalBytesSent: a.totalSent.Load() + liveSent,
		TotalBytesRecv: a.totalRecv.Load() + liveRecv,
	}
}
