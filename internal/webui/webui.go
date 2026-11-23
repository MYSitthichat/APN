package webui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"relayvpn/internal/agent"
	"relayvpn/internal/client"
	"relayvpn/internal/config"
	"relayvpn/internal/installer"
	"relayvpn/internal/p2p"
	"relayvpn/internal/protocol"
	"relayvpn/internal/security"
	"relayvpn/internal/server"
	"relayvpn/internal/version"
)

//go:embed static/index.html static/logo.png static/logo-192.png static/favicon.ico
var staticFS embed.FS

// Options binds the embedded Web UI to Server, Agent, Client, or Unified P2P Peer.
type Options struct {
	Addr   string
	Mode   string // "server", "agent", "client", "peer"
	Server *server.Server
	Agent  *agent.Agent
	Client *client.Client
	Peer   *p2p.Node
	Logger *slog.Logger
}

type streamOpener func(req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, func(), error)

// Start runs the local Web UI HTTP server until ctx is cancelled.
func Start(ctx context.Context, opts Options) error {
	if opts.Addr == "" {
		return nil
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveIndex)
	mux.HandleFunc("GET /manifest.json", servePWAManifest)
	mux.HandleFunc("GET /logo.png", serveStaticAsset("static/logo.png", "image/png"))
	mux.HandleFunc("GET /logo-192.png", serveStaticAsset("static/logo-192.png", "image/png"))
	mux.HandleFunc("GET /favicon.ico", serveStaticAsset("static/favicon.ico", "image/x-icon"))
	mux.HandleFunc("GET /icon.svg", servePWAIcon)

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]any{
			"mode":    opts.Mode,
			"version": version.Version,
		}
		switch opts.Mode {
		case "server":
			payload["data"] = opts.Server.Snapshot()
		case "agent":
			payload["data"] = opts.Agent.Snapshot()
		case "client":
			payload["data"] = opts.Client.Snapshot()
		case "peer":
			payload["data"] = opts.Peer.Snapshot()
		}
		writeJSON(w, http.StatusOK, payload)
	})

	if opts.Mode == "agent" && opts.Agent != nil {
		mux.HandleFunc("POST /api/agent/pause", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Paused bool `json:"paused"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			opts.Agent.SetPaused(body.Paused)
			writeJSON(w, http.StatusOK, opts.Agent.Snapshot())
		}))

		mux.HandleFunc("POST /api/agent/disconnect-all", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			closed := opts.Agent.DisconnectAllSessions()
			writeJSON(w, http.StatusOK, map[string]any{
				"closed":   closed,
				"snapshot": opts.Agent.Snapshot(),
			})
		}))
	}

	if opts.Mode == "client" && opts.Client != nil {
		mux.HandleFunc("POST /api/client/refresh", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			refreshCtx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			if _, err := opts.Client.RefreshAgents(refreshCtx); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Client.Snapshot())
		}))

		mux.HandleFunc("POST /api/client/tunnels", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var rule config.TunnelRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			status, err := opts.Client.AddTunnel(rule)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "tunnel": status})
				return
			}
			writeJSON(w, http.StatusCreated, status)
		}))

		mux.HandleFunc("POST /api/client/tunnels/{id}/toggle", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			status, err := opts.Client.ToggleTunnel(id, body.Enabled)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "tunnel": status})
				return
			}
			writeJSON(w, http.StatusOK, status)
		}))

		mux.HandleFunc("DELETE /api/client/tunnels/{id}", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := opts.Client.RemoveTunnel(id); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		}))

		clientOpener := func(req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, func(), error) {
			var (
				st   io.ReadWriteCloser
				resp protocol.StreamOpenResponse
				err  error
			)
			if req.Mode == protocol.ModeScreen {
				st, resp, err = opts.Client.OpenScreenStreamRequest(req)
			} else {
				st, resp, err = opts.Client.OpenShellStream(req.AgentID)
			}
			return st, resp, func() {}, err
		}
		mux.HandleFunc("GET /ws/remote/screen", func(w http.ResponseWriter, r *http.Request) {
			bridgeScreenWS(w, r, clientOpener)
		})
		mux.HandleFunc("GET /ws/remote/shell", func(w http.ResponseWriter, r *http.Request) {
			bridgeShellWS(w, r, clientOpener)
		})
	}

	if opts.Mode == "peer" && opts.Peer != nil {
		mux.HandleFunc("POST /api/peer/connect", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Ticket           string `json:"ticket"`
				Target           string `json:"target"`
				DeviceID         string `json:"device_id"`
				Password         string `json:"password"`
				PairSecret       string `json:"pair_secret"`
				Fingerprint      string `json:"fingerprint"`
				RememberPassword bool   `json:"remember_password"`
				UseSavedPassword bool   `json:"use_saved_password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			connCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()

			secret := strings.TrimSpace(body.Password)
			if secret == "" {
				secret = strings.TrimSpace(body.PairSecret)
			}

			var (
				info p2p.PeerInfo
				err  error
			)
			switch {
			case strings.TrimSpace(body.Ticket) != "":
				info, err = opts.Peer.ConnectByTicket(connCtx, body.Ticket)
			case strings.TrimSpace(body.DeviceID) != "":
				info, err = opts.Peer.ConnectSmartWithOptions(connCtx, body.DeviceID, secret, body.RememberPassword, body.UseSavedPassword)
			default:
				info, err = opts.Peer.ConnectSmartWithOptions(connCtx, body.Target, secret, body.RememberPassword, body.UseSavedPassword)
			}
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, info)
		}))

		mux.HandleFunc("POST /api/peer/saved/refresh", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			pCtx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			opts.Peer.RefreshPresence(pCtx)
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("DELETE /api/peer/saved/{id}", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := opts.Peer.RemoveSavedPeer(r.PathValue("id")); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/saved/{id}/clear-password", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := opts.Peer.ClearSavedPeerPassword(r.PathValue("id")); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/saved/{id}/rename", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.RenameSavedPeer(r.PathValue("id"), body.Name); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/pin/rotate", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			pin, err := opts.Peer.RotateTempPIN()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"temp_pin": pin})
		}))

		mux.HandleFunc("POST /api/peer/password", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.SetPermanentPassword(body.Password); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/approval-mode", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				RequireApproval bool `json:"require_approval"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			opts.Peer.SetRequireApproval(body.RequireApproval)
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/approvals/{id}", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Allow bool `json:"allow"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.ResolveApproval(r.PathValue("id"), body.Allow); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))

		mux.HandleFunc("POST /api/peer/rendezvous", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				URL string `json:"url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			opts.Peer.SetRendezvousURL(body.URL)
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/vpn", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.SetVPNEnabled(body.Enabled); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":    err.Error(),
					"snapshot": opts.Peer.Snapshot(),
				})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/bootstrap", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			started := opts.Peer.StartAutoDeps(ctx)
			writeJSON(w, http.StatusOK, map[string]any{
				"started":  started,
				"snapshot": opts.Peer.Snapshot(),
			})
		}))

		mux.HandleFunc("POST /api/peer/install", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			st, err := installer.Install()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "install": st})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "install": st, "snapshot": opts.Peer.Snapshot()})
		}))

		mux.HandleFunc("POST /api/peer/uninstall", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := installer.Uninstall(); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "snapshot": opts.Peer.Snapshot()})
		}))

		mux.HandleFunc("POST /api/peer/update/check", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			st := opts.Peer.CheckUpdate(r.Context())
			writeJSON(w, http.StatusOK, map[string]any{"update": st, "snapshot": opts.Peer.Snapshot()})
		}))

		mux.HandleFunc("POST /api/peer/update/apply", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := opts.Peer.ApplyUpdate(ctx); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "snapshot": opts.Peer.Snapshot()})
		}))

		mux.HandleFunc("POST /api/peer/quit", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			go func() {
				time.Sleep(150 * time.Millisecond)
				opts.Peer.RequestQuit()
			}()
		}))

		mux.HandleFunc("POST /api/peer/bridge", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.SetBridgeEnabled(body.Enabled); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":    err.Error(),
					"snapshot": opts.Peer.Snapshot(),
				})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("DELETE /api/peer/peers/{id}", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := opts.Peer.DisconnectPeer(r.PathValue("id")); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
		}))

		mux.HandleFunc("POST /api/peer/stun", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			stunCtx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()
			addr, err := opts.Peer.RefreshSTUN(stunCtx)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"public_udp_addr": addr, "ticket": opts.Peer.MyTicket()})
		}))

		mux.HandleFunc("POST /api/peer/public-ws", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				URL string `json:"url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			opts.Peer.SetPublicWSURL(body.URL)
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/pause", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Paused bool `json:"paused"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			opts.Peer.SetPaused(body.Paused)
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/disconnect-all", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			closed := opts.Peer.DisconnectAllSessions()
			writeJSON(w, http.StatusOK, map[string]any{"closed": closed, "snapshot": opts.Peer.Snapshot()})
		}))

		mux.HandleFunc("POST /api/peer/tunnels", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Name       string `json:"name"`
				LocalAddr  string `json:"local_addr"`
				PeerID     string `json:"peer_id"`
				TargetAddr string `json:"target_addr"`
				Enabled    bool   `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			st, err := opts.Peer.AddTunnel(body.Name, body.LocalAddr, body.PeerID, body.TargetAddr, body.Enabled)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "tunnel": st})
				return
			}
			writeJSON(w, http.StatusCreated, st)
		}))

		mux.HandleFunc("POST /api/peer/tunnels/{id}/toggle", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			st, err := opts.Peer.ToggleTunnel(r.PathValue("id"), body.Enabled)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "tunnel": st})
				return
			}
			writeJSON(w, http.StatusOK, st)
		}))

		mux.HandleFunc("DELETE /api/peer/tunnels/{id}", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := opts.Peer.RemoveTunnel(r.PathValue("id")); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		}))

		peerOpener := func(req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, func(), error) {
			st, resp, err := opts.Peer.OpenPeerStream(context.Background(), req.AgentID, req)
			return st, resp, func() {}, err
		}
		mux.HandleFunc("GET /ws/remote/screen", func(w http.ResponseWriter, r *http.Request) {
			bridgeScreenWS(w, r, peerOpener)
		})
		mux.HandleFunc("GET /ws/remote/shell", func(w http.ResponseWriter, r *http.Request) {
			bridgeShellWS(w, r, peerOpener)
		})
	}

	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	opts.Logger.Info("web dashboard listening", "mode", opts.Mode, "url", "http://"+opts.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// NewPortalHandler returns an authenticated HTTPS 443 Web Remote Portal handler for the Relay Server.
// Allows any browser (including iOS/Android) to log in with a Client ID + Token and control online Agents.
func NewPortalHandler(srv *server.Server, logger *slog.Logger) http.Handler {
	const cookieName = "relayvpn_session"

	type portalSession struct {
		client    config.ClientAuth
		expiresAt time.Time
	}

	var mu sync.RWMutex
	sessions := make(map[string]portalSession)

	getSession := func(r *http.Request) (config.ClientAuth, bool) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			return config.ClientAuth{}, false
		}
		mu.RLock()
		s, ok := sessions[c.Value]
		mu.RUnlock()
		if !ok || time.Now().After(s.expiresAt) {
			return config.ClientAuth{}, false
		}
		return s.client, true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveIndex)
	mux.HandleFunc("GET /manifest.json", servePWAManifest)
	mux.HandleFunc("GET /logo.png", serveStaticAsset("static/logo.png", "image/png"))
	mux.HandleFunc("GET /logo-192.png", serveStaticAsset("static/logo-192.png", "image/png"))
	mux.HandleFunc("GET /favicon.ico", serveStaticAsset("static/favicon.ico", "image/x-icon"))
	mux.HandleFunc("GET /icon.svg", servePWAIcon)

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		cl, ok := getSession(r)
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"mode":    "portal_login",
				"version": version.Version,
				"data":    map[string]any{"authenticated": false},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":    "portal",
			"version": version.Version,
			"data": map[string]any{
				"client_id": cl.ID,
				"name":      cl.Name,
				"agents":    srv.ListAgentsForClient(cl),
			},
		})
	})

	mux.HandleFunc("POST /api/portal/login", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ClientID string `json:"client_id"`
			Token    string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		cl, ok := srv.AuthenticateClient(strings.TrimSpace(body.ClientID), strings.TrimSpace(body.Token))
		if !ok {
			if logger != nil {
				logger.Warn("web portal login failed", "client_id", body.ClientID, "remote", r.RemoteAddr)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Client ID หรือ Token ไม่ถูกต้อง"})
			return
		}
		sid, err := security.GenerateToken(32)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}
		mu.Lock()
		sessions[sid] = portalSession{
			client:    cl,
			expiresAt: time.Now().Add(12 * time.Hour),
		}
		mu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   12 * 3600,
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "client_id": cl.ID})
	}))

	mux.HandleFunc("POST /api/portal/logout", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			mu.Lock()
			delete(sessions, c.Value)
			mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	mux.HandleFunc("GET /ws/remote/screen", func(w http.ResponseWriter, r *http.Request) {
		cl, ok := getSession(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		bridgeScreenWS(w, r, func(req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, func(), error) {
			return srv.OpenAgentStream(cl, req)
		})
	})

	mux.HandleFunc("GET /ws/remote/shell", func(w http.ResponseWriter, r *http.Request) {
		cl, ok := getSession(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		bridgeShellWS(w, r, func(req protocol.StreamOpenRequest) (io.ReadWriteCloser, protocol.StreamOpenResponse, func(), error) {
			return srv.OpenAgentStream(cl, req)
		})
	})

	return mux
}

func bridgeScreenWS(w http.ResponseWriter, r *http.Request, opener streamOpener) {
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	fps, _ := strconv.Atoi(r.URL.Query().Get("fps"))
	quality, _ := strconv.Atoi(r.URL.Query().Get("quality"))
	codec := strings.TrimSpace(r.URL.Query().Get("codec"))
	maxWidth, _ := strconv.Atoi(r.URL.Query().Get("max_width"))

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "")
	wsConn.SetReadLimit(1 << 20)

	stream, resp, release, err := opener(protocol.StreamOpenRequest{
		Mode:     protocol.ModeScreen,
		AgentID:  agentID,
		FPS:      fps,
		Quality:  quality,
		Codec:    codec,
		MaxWidth: maxWidth,
	})
	if err != nil {
		msg, _ := json.Marshal(map[string]any{"type": "error", "error": err.Error()})
		_ = wsConn.Write(r.Context(), websocket.MessageText, msg)
		return
	}
	defer release()
	defer stream.Close()

	initMsg, _ := json.Marshal(map[string]any{
		"type":        "init",
		"width":       resp.ScreenWidth,
		"height":      resp.ScreenHeight,
		"allow_input": resp.AllowInput,
	})
	if err := wsConn.Write(r.Context(), websocket.MessageText, initMsg); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Browser -> Agent (Input, ACK & config JSON events)
	go func() {
		defer cancel()
		defer stream.Close()
		for {
			_, data, err := wsConn.Read(ctx)
			if err != nil {
				return
			}
			if err := protocol.WriteTypedFrame(stream, protocol.FrameTypeInput, data); err != nil {
				return
			}
		}
	}()

	// Agent -> Browser (TileBatch, H264, JPEG, Info & Errors)
	var taggedBuf []byte
	for {
		fType, payload, err := protocol.ReadTypedFrame(stream)
		if err != nil {
			return
		}
		switch fType {
		case protocol.FrameTypeJPEG, protocol.FrameTypeTileBatch, protocol.FrameTypeH264:
			needed := 1 + len(payload)
			if cap(taggedBuf) < needed {
				taggedBuf = make([]byte, needed)
			} else {
				taggedBuf = taggedBuf[:needed]
			}
			taggedBuf[0] = fType
			copy(taggedBuf[1:], payload)
			if err := wsConn.Write(ctx, websocket.MessageBinary, taggedBuf); err != nil {
				return
			}
		case protocol.FrameTypeInfo:
			var info map[string]any
			if json.Unmarshal(payload, &info) == nil {
				info["type"] = "info"
				msg, _ := json.Marshal(info)
				if err := wsConn.Write(ctx, websocket.MessageText, msg); err != nil {
					return
				}
			}
		case protocol.FrameTypeError:
			errMsg, _ := json.Marshal(map[string]any{"type": "error", "error": string(payload)})
			if err := wsConn.Write(ctx, websocket.MessageText, errMsg); err != nil {
				return
			}
		}
	}
}

func bridgeShellWS(w http.ResponseWriter, r *http.Request, opener streamOpener) {
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "")
	wsConn.SetReadLimit(1 << 20)

	stream, _, release, err := opener(protocol.StreamOpenRequest{
		Mode:    protocol.ModeShell,
		AgentID: agentID,
	})
	if err != nil {
		_ = wsConn.Write(r.Context(), websocket.MessageText, []byte("[Error] "+err.Error()+"\r\n"))
		return
	}
	defer release()
	defer stream.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Browser -> Agent shell stdin
	go func() {
		defer cancel()
		defer stream.Close()
		for {
			_, data, err := wsConn.Read(ctx)
			if err != nil {
				return
			}
			if _, err := stream.Write(data); err != nil {
				return
			}
		}
	}()

	// Agent shell stdout/stderr -> Browser
	buf := make([]byte, 8192)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			if werr := wsConn.Write(ctx, websocket.MessageText, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "ui asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = w.Write(data)
}

func serveStaticAsset(assetPath, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		data, err := staticFS.ReadFile(assetPath)
		if err != nil {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}

func servePWAManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":             "APN Remote & VPN",
		"short_name":       "APN",
		"description":      "Cross-Platform 60 FPS P2P Remote Desktop & Encrypted L3 VPN",
		"start_url":        "/",
		"display":          "standalone",
		"background_color": "#070b14",
		"theme_color":      "#0b1026",
		"icons": []map[string]string{
			{"src": "/logo-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
			{"src": "/logo.png", "sizes": "256x256", "type": "image/png", "purpose": "any maskable"},
			{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"},
		},
	})
}

func servePWAIcon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#172447"/><stop offset="100%" stop-color="#070d20"/></linearGradient><linearGradient id="arc" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#38bdf8"/><stop offset="100%" stop-color="#6366f1"/></linearGradient></defs><rect x="3" y="3" width="122" height="122" rx="28" fill="url(#bg)" stroke="#38bdf8" stroke-width="3"/><path d="M64 22l32 13v26c0 23-14 39-32 45-18-6-32-22-32-45V35l32-13z" fill="rgba(56,189,248,0.08)" stroke="#93c5fd" stroke-width="3" stroke-linejoin="round"/><path d="M75 37c-18 2-31 15-31 31 0 6 2 11 5 15 3-13 13-24 27-27 6-1 11-1 15 1-3-12-9-19-16-20z" fill="url(#arc)"/><path d="M53 91c18-2 31-15 31-31 0-6-2-11-5-15-3 13-13 24-27 27-6 1-11 1-15-1 3 12 9 19 16 20z" fill="url(#arc)"/><circle cx="64" cy="64" r="10" fill="#e0f2fe" stroke="#38bdf8" stroke-width="3"/></svg>`))
}

func requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request blocked"})
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
