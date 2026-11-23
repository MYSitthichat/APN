package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

type connectedAgent struct {
	auth        config.AgentAuth
	displayName string
	osInfo      string
	remoteAddr  string
	connectedAt time.Time
	session     *yamux.Session
	cancel      context.CancelFunc

	mu           sync.RWMutex
	targets      []protocol.TargetInfo
	capabilities protocol.AgentCapabilities
	activeConns  atomic.Int64
}

type connectedClient struct {
	auth        config.ClientAuth
	osInfo      string
	remoteAddr  string
	connectedAt time.Time
	session     *yamux.Session
	cancel      context.CancelFunc
}

// ClientSummary summarizes an online Client for the Server Web UI.
type ClientSummary struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OS          string    `json:"os"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
}

// Snapshot holds live Relay Server metrics for the dashboard API.
type Snapshot struct {
	ListenAddr     string               `json:"listen_addr"`
	StartedAt      time.Time            `json:"started_at"`
	Agents         []protocol.AgentInfo `json:"agents"`
	Clients        []ClientSummary      `json:"clients"`
	ActiveStreams  int64                `json:"active_streams"`
	TotalBytesSent int64                `json:"total_bytes_sent"`
	TotalBytesRecv int64                `json:"total_bytes_recv"`
}

// Server is the TLS 1.3 + WebSocket + Yamux Relay Server listening on port 443.
type Server struct {
	cfg       *config.ServerConfig
	logger    *slog.Logger
	tlsCfg    *tls.Config
	startedAt time.Time

	mu            sync.RWMutex
	agents        map[string]*connectedAgent
	clients       map[string]*connectedClient
	portalHandler http.Handler
	rendezvous    *rendezvousDirectory

	activeStreams atomic.Int64
	totalSent     atomic.Int64
	totalRecv     atomic.Int64

	httpServer *http.Server
	boundAddr  string
}

// New creates a new Relay Server from configuration.
func New(cfg *config.ServerConfig, logger *slog.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server config is nil")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":443"
	}
	tlsCfg, err := security.ServerTLSConfig(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:        cfg,
		logger:     logger,
		tlsCfg:     tlsCfg,
		startedAt:  time.Now().UTC(),
		agents:     make(map[string]*connectedAgent),
		clients:    make(map[string]*connectedClient),
		rendezvous: newRendezvousDirectory(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/rendezvous/register", s.rendezvous.handleRegister)
	mux.HandleFunc("POST /api/rendezvous/unregister", s.rendezvous.handleUnregister)
	mux.HandleFunc("POST /api/rendezvous/presence", s.rendezvous.handlePresence)
	mux.HandleFunc("POST /api/rendezvous/lookup/{id}", s.rendezvous.handleLookup)
	mux.HandleFunc("GET /api/rendezvous/lookup/{id}", s.rendezvous.handleLookup)
	mux.HandleFunc("/ws/tunnel", s.handleTunnel)
	mux.HandleFunc("/", s.handlePortalFallback)

	s.httpServer = &http.Server{
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// SetPortalHandler attaches an optional authenticated HTTPS Web Remote Portal handler on port 443.
func (s *Server) SetPortalHandler(h http.Handler) {
	s.mu.Lock()
	s.portalHandler = h
	s.mu.Unlock()
}

func (s *Server) handlePortalFallback(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.portalHandler
	s.mu.RUnlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

// StartAsync binds the TLS listener and begins serving in the background.
// Returns the bound network address (useful when ListenAddr uses port 0).
func (s *Server) StartAsync(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	tlsLn := tls.NewListener(ln, s.tlsCfg)
	s.boundAddr = ln.Addr().String()
	s.logger.Info("relay server listening (TLS 1.3 / WSS)", "addr", s.boundAddr, "web_portal", s.cfg.EnableWebPortal)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		s.closeAllSessions()
	}()

	go func() {
		if err := s.httpServer.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("relay server stopped with error", "err", err)
		}
	}()

	return s.boundAddr, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if _, err := s.StartAsync(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func (s *Server) closeAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ag := range s.agents {
		ag.cancel()
		_ = ag.session.Close()
		delete(s.agents, id)
	}
	for id, cl := range s.clients {
		cl.cancel()
		_ = cl.session.Close()
		delete(s.clients, id)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"uptime": time.Since(s.startedAt).Round(time.Second).String(),
	})
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	role := strings.ToLower(strings.TrimSpace(r.Header.Get(protocol.HeaderRole)))
	peerID := strings.TrimSpace(r.Header.Get(protocol.HeaderPeerID))
	peerName := strings.TrimSpace(r.Header.Get(protocol.HeaderPeerName))
	peerOS := strings.TrimSpace(r.Header.Get(protocol.HeaderPeerOS))

	if token == "" || peerID == "" {
		http.Error(w, "missing authentication headers", http.StatusUnauthorized)
		return
	}

	switch role {
	case protocol.RoleAgent:
		auth, ok := s.authenticateAgent(peerID, token)
		if !ok {
			s.logger.Warn("agent authentication failed", "agent_id", peerID, "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.serveAgent(w, r, auth, peerName, peerOS)

	case protocol.RoleClient:
		auth, ok := s.AuthenticateClient(peerID, token)
		if !ok {
			s.logger.Warn("client authentication failed", "client_id", peerID, "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.serveClient(w, r, auth, peerOS)

	default:
		http.Error(w, "invalid peer role", http.StatusBadRequest)
	}
}

func (s *Server) serveAgent(w http.ResponseWriter, r *http.Request, auth config.AgentAuth, peerName, peerOS string) {
	sessCtx, cancel := context.WithCancel(context.Background())
	session, err := protocol.AcceptSession(sessCtx, w, r, true)
	if err != nil {
		cancel()
		s.logger.Warn("accept agent websocket failed", "agent_id", auth.ID, "err", err)
		return
	}

	displayName := peerName
	if displayName == "" {
		displayName = auth.Name
	}

	ag := &connectedAgent{
		auth:        auth,
		displayName: displayName,
		osInfo:      peerOS,
		remoteAddr:  r.RemoteAddr,
		connectedAt: time.Now().UTC(),
		session:     session,
		cancel:      cancel,
	}

	s.mu.Lock()
	if prev, exists := s.agents[auth.ID]; exists {
		s.logger.Info("replacing stale agent session", "agent_id", auth.ID)
		prev.cancel()
		_ = prev.session.Close()
	}
	s.agents[auth.ID] = ag
	s.mu.Unlock()

	s.logger.Info("agent connected", "agent_id", auth.ID, "os", peerOS, "remote", r.RemoteAddr)

	defer func() {
		cancel()
		_ = session.Close()
		s.mu.Lock()
		if cur, ok := s.agents[auth.ID]; ok && cur == ag {
			delete(s.agents, auth.ID)
		}
		s.mu.Unlock()
		s.logger.Info("agent disconnected", "agent_id", auth.ID)
	}()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go s.handleAgentControlStream(ag, stream)
	}
}

func (s *Server) handleAgentControlStream(ag *connectedAgent, stream *yamux.Stream) {
	defer stream.Close()
	var req protocol.StreamOpenRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		return
	}
	if req.Mode == protocol.ModeControl && req.Action == "register_targets" {
		ag.mu.Lock()
		ag.targets = slices.Clone(req.Targets)
		if req.Capabilities != nil {
			ag.capabilities = *req.Capabilities
		}
		ag.mu.Unlock()
		_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{OK: true})
		return
	}
	_ = protocol.WriteMessage(stream, protocol.StreamOpenResponse{
		OK:    false,
		Error: "unsupported agent control request",
	})
}

func (s *Server) serveClient(w http.ResponseWriter, r *http.Request, auth config.ClientAuth, peerOS string) {
	sessCtx, cancel := context.WithCancel(context.Background())
	session, err := protocol.AcceptSession(sessCtx, w, r, false)
	if err != nil {
		cancel()
		s.logger.Warn("accept client websocket failed", "client_id", auth.ID, "err", err)
		return
	}

	cl := &connectedClient{
		auth:        auth,
		osInfo:      peerOS,
		remoteAddr:  r.RemoteAddr,
		connectedAt: time.Now().UTC(),
		session:     session,
		cancel:      cancel,
	}

	connKey := fmt.Sprintf("%s@%s", auth.ID, r.RemoteAddr)
	s.mu.Lock()
	s.clients[connKey] = cl
	s.mu.Unlock()

	s.logger.Info("client connected", "client_id", auth.ID, "os", peerOS, "remote", r.RemoteAddr)

	defer func() {
		cancel()
		_ = session.Close()
		s.mu.Lock()
		delete(s.clients, connKey)
		s.mu.Unlock()
		s.logger.Info("client disconnected", "client_id", auth.ID)
	}()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go s.handleClientStream(cl, stream)
	}
}

func (s *Server) handleClientStream(cl *connectedClient, clientStream *yamux.Stream) {
	var req protocol.StreamOpenRequest
	if err := protocol.ReadMessage(clientStream, &req); err != nil {
		_ = clientStream.Close()
		return
	}

	switch req.Mode {
	case protocol.ModeControl:
		defer clientStream.Close()
		if req.Action == "list_agents" {
			_ = protocol.WriteMessage(clientStream, protocol.StreamOpenResponse{
				OK:     true,
				Agents: s.ListAgentsForClient(cl.auth),
			})
			return
		}
		_ = protocol.WriteMessage(clientStream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "unknown control action",
		})

	case protocol.ModeTCP, protocol.ModeScreen, protocol.ModeShell:
		s.relayAgentStream(cl.auth, clientStream, req)

	case protocol.ModeTUN:
		defer clientStream.Close()
		_ = protocol.WriteMessage(clientStream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "L3 TUN mode is planned for Phase 2",
		})

	default:
		defer clientStream.Close()
		_ = protocol.WriteMessage(clientStream, protocol.StreamOpenResponse{
			OK:    false,
			Error: "unsupported stream mode",
		})
	}
}

// OpenAgentStream opens an authorized remote stream directly to an online Agent.
// Used by both Yamux relay forwarding and the optional HTTPS Web Remote Portal.
func (s *Server) OpenAgentStream(cl config.ClientAuth, req protocol.StreamOpenRequest) (*yamux.Stream, protocol.StreamOpenResponse, func(), error) {
	if !isClientAllowedAgent(cl, req.AgentID) {
		resp := protocol.StreamOpenResponse{OK: false, Error: "access denied for requested agent"}
		return nil, resp, nil, errors.New(resp.Error)
	}

	s.mu.RLock()
	ag, ok := s.agents[req.AgentID]
	s.mu.RUnlock()
	if !ok {
		resp := protocol.StreamOpenResponse{OK: false, Error: "agent is offline"}
		return nil, resp, nil, errors.New(resp.Error)
	}

	agentStream, err := ag.session.OpenStream()
	if err != nil {
		resp := protocol.StreamOpenResponse{OK: false, Error: fmt.Sprintf("open stream to agent: %v", err)}
		return nil, resp, nil, err
	}

	agentReq := protocol.StreamOpenRequest{
		Mode:       req.Mode,
		AgentID:    req.AgentID,
		TargetAddr: req.TargetAddr,
		ClientID:   cl.ID,
		FPS:        req.FPS,
		Quality:    req.Quality,
		Codec:      req.Codec,
		MaxWidth:   req.MaxWidth,
	}
	if err := protocol.WriteMessage(agentStream, agentReq); err != nil {
		_ = agentStream.Close()
		resp := protocol.StreamOpenResponse{OK: false, Error: "failed to forward request to agent"}
		return nil, resp, nil, err
	}

	var agentResp protocol.StreamOpenResponse
	if err := protocol.ReadMessage(agentStream, &agentResp); err != nil {
		_ = agentStream.Close()
		resp := protocol.StreamOpenResponse{OK: false, Error: "failed to read response from agent"}
		return nil, resp, nil, err
	}
	if !agentResp.OK {
		_ = agentStream.Close()
		return nil, agentResp, nil, errors.New(agentResp.Error)
	}

	s.activeStreams.Add(1)
	ag.activeConns.Add(1)
	var once sync.Once
	release := func() {
		once.Do(func() {
			s.activeStreams.Add(-1)
			ag.activeConns.Add(-1)
		})
	}
	return agentStream, agentResp, release, nil
}

func (s *Server) relayAgentStream(cl config.ClientAuth, clientStream *yamux.Stream, req protocol.StreamOpenRequest) {
	agentStream, agentResp, release, err := s.OpenAgentStream(cl, req)
	if err != nil {
		_ = protocol.WriteMessage(clientStream, agentResp)
		_ = clientStream.Close()
		return
	}
	defer release()

	if err := protocol.WriteMessage(clientStream, agentResp); err != nil {
		_ = agentStream.Close()
		_ = clientStream.Close()
		return
	}

	protocol.PipeBidirectional(clientStream, agentStream, &s.totalSent, &s.totalRecv)
}

func (s *Server) authenticateAgent(id, token string) (config.AgentAuth, bool) {
	for _, a := range s.cfg.Agents {
		if a.ID == id && security.VerifyToken(token, a.TokenHash) {
			return a, true
		}
	}
	return config.AgentAuth{}, false
}

// AuthenticateClient validates a client ID and raw bearer token against hashed server config.
func (s *Server) AuthenticateClient(id, token string) (config.ClientAuth, bool) {
	for _, c := range s.cfg.Clients {
		if c.ID == id && security.VerifyToken(token, c.TokenHash) {
			return c, true
		}
	}
	return config.ClientAuth{}, false
}

func isClientAllowedAgent(cl config.ClientAuth, agentID string) bool {
	for _, allowed := range cl.AllowedAgents {
		if allowed == "*" || allowed == agentID {
			return true
		}
	}
	return false
}

// ListAgentsForClient returns online Agents visible to a given authenticated Client.
func (s *Server) ListAgentsForClient(cl config.ClientAuth) []protocol.AgentInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]protocol.AgentInfo, 0, len(s.agents))
	for _, ag := range s.agents {
		if !isClientAllowedAgent(cl, ag.auth.ID) {
			continue
		}
		ag.mu.RLock()
		targets := slices.Clone(ag.targets)
		caps := ag.capabilities
		ag.mu.RUnlock()
		out = append(out, protocol.AgentInfo{
			ID:           ag.auth.ID,
			Name:         ag.displayName,
			OS:           ag.osInfo,
			ConnectedAt:  ag.connectedAt,
			Targets:      targets,
			Capabilities: caps,
			ActiveConns:  int(ag.activeConns.Load()),
		})
	}
	return out
}

// Snapshot returns current server state for the local admin Web UI.
func (s *Server) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]protocol.AgentInfo, 0, len(s.agents))
	for _, ag := range s.agents {
		ag.mu.RLock()
		targets := slices.Clone(ag.targets)
		caps := ag.capabilities
		ag.mu.RUnlock()
		agents = append(agents, protocol.AgentInfo{
			ID:           ag.auth.ID,
			Name:         ag.displayName,
			OS:           ag.osInfo,
			RemoteAddr:   ag.remoteAddr,
			ConnectedAt:  ag.connectedAt,
			Targets:      targets,
			Capabilities: caps,
			ActiveConns:  int(ag.activeConns.Load()),
		})
	}

	clients := make([]ClientSummary, 0, len(s.clients))
	for _, cl := range s.clients {
		clients = append(clients, ClientSummary{
			ID:          cl.auth.ID,
			Name:        cl.auth.Name,
			OS:          cl.osInfo,
			RemoteAddr:  cl.remoteAddr,
			ConnectedAt: cl.connectedAt,
		})
	}

	addr := s.boundAddr
	if addr == "" {
		addr = s.cfg.ListenAddr
	}
	return Snapshot{
		ListenAddr:     addr,
		StartedAt:      s.startedAt,
		Agents:         agents,
		Clients:        clients,
		ActiveStreams:  s.activeStreams.Load(),
		TotalBytesSent: s.totalSent.Load(),
		TotalBytesRecv: s.totalRecv.Load(),
	}
}

func extractBearerToken(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}
