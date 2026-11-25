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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"relayvpn/internal/agent"
	"relayvpn/internal/bootstrap"
	"relayvpn/internal/client"
	"relayvpn/internal/config"
	"relayvpn/internal/installer"
	"relayvpn/internal/p2p"
	"relayvpn/internal/protocol"
	"relayvpn/internal/remote"
	"relayvpn/internal/security"
	"relayvpn/internal/server"
	"relayvpn/internal/service"
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

// approvalPollAt is when an open dashboard page last polled for connection requests.
var approvalPollAt atomic.Int64

// ApprovalPageActive reports whether an open dashboard page polled for connection requests within
// d, i.e. whether a new request will already be shown on screen without opening another window.
func ApprovalPageActive(d time.Duration) bool {
	at := approvalPollAt.Load()
	return at != 0 && time.Since(time.Unix(0, at)) < d
}

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

		mux.HandleFunc("POST /api/peer/probe", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Target string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			probeCtx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()
			res, err := opts.Peer.ProbeTarget(probeCtx, body.Target)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, res)
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

		mux.HandleFunc("POST /api/peer/saved/{id}/group", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Group string `json:"group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := opts.Peer.SetSavedPeerGroup(r.PathValue("id"), body.Group); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, opts.Peer.Snapshot())
		}))

		mux.HandleFunc("POST /api/peer/groups/rename", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				OldName string `json:"old_name"`
				NewName string `json:"new_name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			updated, err := opts.Peer.RenameGroup(body.OldName, body.NewName)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"updated":  updated,
				"snapshot": opts.Peer.Snapshot(),
			})
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

		mux.HandleFunc("GET /api/peer/approvals", func(w http.ResponseWriter, r *http.Request) {
			approvalPollAt.Store(time.Now().UnixNano())
			writeJSON(w, http.StatusOK, map[string]any{"approvals": opts.Peer.PendingApprovals(), "now": time.Now().UTC()})
		})
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

		mux.HandleFunc("POST /api/peer/service/install", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			info, err := service.InstallSystemService(installer.DefaultConfigPath(), bootstrap.BinDir())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "service": info})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": info, "snapshot": opts.Peer.Snapshot()})
			// If we were running as a user-mode process and the new System Service is now running,
			// cleanly exit user-mode so the System Service owns the persistent port & connections!
			if info.Running && os.Getenv("APN_SERVICE_WORKER") != "1" {
				go func() {
					time.Sleep(450 * time.Millisecond)
					opts.Peer.RequestQuit()
				}()
			}
		}))

		mux.HandleFunc("POST /api/peer/service/uninstall", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			if err := service.UninstallSystemService(); err != nil {
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

		// ---- Bidirectional Native OS Clipboard Sync (Screenshots + Text, Zero Browser Permissions!) ----
		mux.HandleFunc("POST /api/peer/clipboard/push", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID    string `json:"peer_id"`
				AutoPaste bool   `json:"auto_paste"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			kind, data, err := remote.ReadClipboard()
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			peerID := strings.TrimSpace(body.PeerID)
			if status, msg := pushClipboardToPeer(r.Context(), opts.Peer, peerID, kind, data, body.AutoPaste); status != 0 {
				writeJSON(w, status, map[string]string{"error": msg})
				return
			}
			clipSync.remember(peerID, kind, data)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kind": kind, "bytes": len(data)})
		}))

		// Automatic clipboard sync (viewer -> host): called when the remote window gets focus, the
		// mouse enters the remote screen or the user right-clicks it. Sends the local clipboard
		// without pasting, so right-click -> Paste on the remote machine has it, but only when it
		// changed since this peer last got it (never echoes a pulled clipboard back).
		mux.HandleFunc("POST /api/peer/clipboard/sync", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID string `json:"peer_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			peerID := strings.TrimSpace(body.PeerID)
			seq := remote.ClipboardSeq()
			if clipSync.unchangedSeq(peerID, seq) {
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pushed": false})
				return
			}
			kind, data, err := remote.ReadClipboard()
			if err != nil || len(data) == 0 || len(data) > 16*1024*1024 {
				clipSync.rememberSeq(peerID, seq)
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pushed": false})
				return
			}
			if clipSync.same(peerID, kind, data) {
				clipSync.rememberSeq(peerID, seq)
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pushed": false})
				return
			}
			if status, msg := pushClipboardToPeer(r.Context(), opts.Peer, peerID, kind, data, false); status != 0 {
				writeJSON(w, status, map[string]string{"error": msg})
				return
			}
			clipSync.remember(peerID, kind, data)
			clipSync.rememberSeq(peerID, seq)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pushed": true, "kind": kind, "bytes": len(data)})
		}))

		mux.HandleFunc("POST /api/peer/clipboard/pull", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID string `json:"peer_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), strings.TrimSpace(body.PeerID), protocol.StreamOpenRequest{Mode: protocol.ModeClipboard})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyClipboardErr(err)})
				return
			}
			defer st.Close()
			if err := protocol.WriteMessage(st, remote.ClipboardRequest{Action: "get"}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var hdr remote.ClipboardResponse
			if err := protocol.ReadMessage(st, &hdr); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !hdr.OK {
				writeJSON(w, http.StatusBadRequest, hdr)
				return
			}
			data := make([]byte, hdr.Size)
			if hdr.Size > 0 {
				if _, err := io.ReadFull(st, data); err != nil {
					writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
					return
				}
			}
			peerID := strings.TrimSpace(body.PeerID)
			if clipSync.same(peerID, hdr.Kind, data) && remote.ClipboardSeq() != 0 && clipSync.unchangedSeq(peerID, remote.ClipboardSeq()) {
				// Already on this machine's clipboard (e.g. the echo of our own push).
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kind": hdr.Kind, "bytes": len(data), "unchanged": true})
				return
			}
			if err := remote.ApplyClipboardPayload(hdr.Kind, data); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			// Remember it so the next focus sync does not push it straight back to the host.
			clipSync.remember(peerID, hdr.Kind, data)
			clipSync.rememberSeq(peerID, remote.ClipboardSeq())
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kind": hdr.Kind, "bytes": len(data)})
		}))

		// ---- Local File Browser & Direct P2P Dual-Pane Transfer (TeamViewer-Style) ----
		mux.HandleFunc("GET /api/local/files/list", func(w http.ResponseWriter, r *http.Request) {
			resp := remote.ListLocalFiles(r.URL.Query().Get("path"))
			if !resp.OK {
				writeJSON(w, http.StatusBadRequest, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("POST /api/local/files/mkdir", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Path string `json:"path"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			p, err := remote.MkdirLocal(body.Path, body.Name)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": p})
		}))

		mux.HandleFunc("POST /api/local/files/delete", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			if err := remote.DeleteLocal(body.Path); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))

		mux.HandleFunc("GET /api/peer/files/progress", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, getFileTransferProgress())
		})

		mux.HandleFunc("POST /api/peer/files/push", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID    string `json:"peer_id"`
				LocalPath string `json:"local_path"`
				RemoteDir string `json:"remote_dir"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			src, err := os.Open(filepath.Clean(body.LocalPath))
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			defer src.Close()
			stInfo, err := src.Stat()
			if err != nil || stInfo.IsDir() {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "กรุณาเลือกไฟล์ (ไม่ใช่โฟลเดอร์)"})
				return
			}

			stream, _, err := opts.Peer.OpenPeerStream(r.Context(), strings.TrimSpace(body.PeerID), protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer stream.Close()

			if err := protocol.WriteMessage(stream, remote.FileRequest{
				Action: "upload",
				Path:   body.RemoteDir,
				Name:   stInfo.Name(),
				Size:   stInfo.Size(),
			}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var ready remote.FileResponse
			if err := protocol.ReadMessage(stream, &ready); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !ready.OK {
				writeJSON(w, http.StatusBadRequest, ready)
				return
			}

			startFileTransferProgress("push", stInfo.Name(), stInfo.Size())
			defer finishFileTransferProgress()

			buf := make([]byte, 256*1024)
			if _, err := copyWithProgress(stream, src, buf); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var done remote.FileResponse
			if err := protocol.ReadMessage(stream, &done); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !done.OK {
				writeJSON(w, http.StatusBadRequest, done)
				return
			}
			writeJSON(w, http.StatusOK, done)
		}))

		mux.HandleFunc("POST /api/peer/files/pull", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID     string `json:"peer_id"`
				RemotePath string `json:"remote_path"`
				LocalDir   string `json:"local_dir"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			localDir := strings.TrimSpace(body.LocalDir)
			if localDir == "" || localDir == "__roots__" {
				if home, err := os.UserHomeDir(); err == nil && home != "" {
					localDir = filepath.Join(home, "Downloads")
				} else {
					localDir = os.TempDir()
				}
			}
			if err := os.MkdirAll(localDir, 0o755); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}

			stream, _, err := opts.Peer.OpenPeerStream(r.Context(), strings.TrimSpace(body.PeerID), protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer stream.Close()

			if err := protocol.WriteMessage(stream, remote.FileRequest{Action: "download", Path: body.RemotePath}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var hdr remote.FileResponse
			if err := protocol.ReadMessage(stream, &hdr); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !hdr.OK {
				writeJSON(w, http.StatusBadRequest, hdr)
				return
			}

			finalPath := filepath.Join(localDir, filepath.Base(hdr.Name))
			tmpPath := finalPath + ".apnpart"
			out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}

			startFileTransferProgress("pull", hdr.Name, hdr.Size)
			defer finishFileTransferProgress()

			buf := make([]byte, 256*1024)
			written, copyErr := copyWithProgress(out, io.LimitReader(stream, hdr.Size), buf)
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil || written != hdr.Size {
				_ = os.Remove(tmpPath)
				if copyErr == nil && closeErr != nil {
					copyErr = closeErr
				}
				if copyErr == nil {
					copyErr = errors.New("ดาวน์โหลดไฟล์ไม่ครบถ้วน")
				}
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": copyErr.Error()})
				return
			}
			if err := os.Rename(tmpPath, finalPath); err != nil {
				_ = os.Remove(tmpPath)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": finalPath, "name": hdr.Name, "bytes": written})
		}))

		// ---- Encrypted Zero-Cost P2P File Transfer Endpoints (ModeFiles) ----
		mux.HandleFunc("GET /api/peer/files/list", func(w http.ResponseWriter, r *http.Request) {
			peerID := strings.TrimSpace(r.URL.Query().Get("peer_id"))
			dirPath := r.URL.Query().Get("path")
			if peerID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer_id is required"})
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), peerID, protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer st.Close()
			if err := protocol.WriteMessage(st, remote.FileRequest{Action: "list", Path: dirPath}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var resp remote.FileResponse
			if err := protocol.ReadMessage(st, &resp); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !resp.OK {
				writeJSON(w, http.StatusBadRequest, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		})

		mux.HandleFunc("GET /api/peer/files/download", func(w http.ResponseWriter, r *http.Request) {
			peerID := strings.TrimSpace(r.URL.Query().Get("peer_id"))
			filePath := r.URL.Query().Get("path")
			if peerID == "" || strings.TrimSpace(filePath) == "" {
				http.Error(w, "peer_id and path are required", http.StatusBadRequest)
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), peerID, protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				http.Error(w, friendlyFileStreamErr(err), http.StatusBadGateway)
				return
			}
			defer st.Close()
			if err := protocol.WriteMessage(st, remote.FileRequest{Action: "download", Path: filePath}); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			var hdr remote.FileResponse
			if err := protocol.ReadMessage(st, &hdr); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			if !hdr.OK {
				http.Error(w, hdr.Error, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(hdr.Name, `"`, `_`)+`"; filename*=UTF-8''`+url.PathEscape(hdr.Name))
			if hdr.Size >= 0 {
				w.Header().Set("Content-Length", strconv.FormatInt(hdr.Size, 10))
			}
			buf := make([]byte, 256*1024)
			_, _ = io.CopyBuffer(w, io.LimitReader(st, hdr.Size), buf)
		})

		mux.HandleFunc("POST /api/peer/files/upload", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			peerID := strings.TrimSpace(r.URL.Query().Get("peer_id"))
			dirPath := r.URL.Query().Get("dir")
			fileName := strings.TrimSpace(r.URL.Query().Get("name"))
			if peerID == "" || fileName == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "peer_id and name are required"})
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), peerID, protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer st.Close()

			size := r.ContentLength
			if err := protocol.WriteMessage(st, remote.FileRequest{
				Action: "upload",
				Path:   dirPath,
				Name:   fileName,
				Size:   size,
			}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var ready remote.FileResponse
			if err := protocol.ReadMessage(st, &ready); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !ready.OK {
				writeJSON(w, http.StatusBadRequest, ready)
				return
			}

			buf := make([]byte, 256*1024)
			if _, err := io.CopyBuffer(st, r.Body, buf); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ส่งไฟล์ไม่สำเร็จ: " + err.Error()})
				return
			}
			if size < 0 {
				if cw, ok := st.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}
			var done remote.FileResponse
			if err := protocol.ReadMessage(st, &done); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !done.OK {
				writeJSON(w, http.StatusBadRequest, done)
				return
			}
			writeJSON(w, http.StatusOK, done)
		}))

		mux.HandleFunc("POST /api/peer/files/mkdir", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID string `json:"peer_id"`
				Path   string `json:"path"`
				Name   string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), strings.TrimSpace(body.PeerID), protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer st.Close()
			if err := protocol.WriteMessage(st, remote.FileRequest{Action: "mkdir", Path: body.Path, Name: body.Name}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var resp remote.FileResponse
			if err := protocol.ReadMessage(st, &resp); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !resp.OK {
				writeJSON(w, http.StatusBadRequest, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))

		mux.HandleFunc("POST /api/peer/files/delete", requireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				PeerID string `json:"peer_id"`
				Path   string `json:"path"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			st, _, err := opts.Peer.OpenPeerStream(r.Context(), strings.TrimSpace(body.PeerID), protocol.StreamOpenRequest{Mode: protocol.ModeFiles})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": friendlyFileStreamErr(err)})
				return
			}
			defer st.Close()
			if err := protocol.WriteMessage(st, remote.FileRequest{Action: "delete", Path: body.Path}); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			var resp remote.FileResponse
			if err := protocol.ReadMessage(st, &resp); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			if !resp.OK {
				writeJSON(w, http.StatusBadRequest, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
		}))
	}

	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           localGuard(mux, opts.Logger),
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
	localCursor := r.URL.Query().Get("local_cursor") == "1"

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer wsConn.Close(websocket.StatusNormalClosure, "")
	wsConn.SetReadLimit(16 << 20) // 16 MiB so 4K PNG screenshots paste cleanly over clipboard!

	stream, resp, release, err := opener(protocol.StreamOpenRequest{
		Mode:     protocol.ModeScreen,
		AgentID:  agentID,
		FPS:      fps,
		Quality:  quality,
		Codec:    codec,
		MaxWidth:    maxWidth,
		LocalCursor: localCursor,
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

	var streamWriteMu sync.Mutex
	writeTypedFrame := func(frameType byte, payload []byte) error {
		streamWriteMu.Lock()
		err := protocol.WriteTypedFrame(stream, frameType, payload)
		streamWriteMu.Unlock()
		return err
	}

	// On Windows, capture Win+Space natively while the APN Remote Desktop window is focused
	// (even in Windowed mode!) so Win+Space switches the REMOTE PC's language without triggering local Windows!
	if resp.AllowInput {
		stopLangHook := registerRemoteLangHook(func() {
			if ctx.Err() != nil {
				return
			}
			_ = writeTypedFrame(protocol.FrameTypeInput, []byte(`{"type":"switch_lang"}`))
		})
		defer stopLangHook()
	}

	// Browser -> Agent (Input JSON + Binary Clipboard Image/Text frames)
	go func() {
		defer cancel()
		defer stream.Close()
		for {
			msgType, data, err := wsConn.Read(ctx)
			if err != nil {
				return
			}
			if msgType == websocket.MessageBinary && len(data) > 2 && data[0] == protocol.FrameTypeClipboard {
				if err := writeTypedFrame(protocol.FrameTypeClipboard, data[1:]); err != nil {
					return
				}
				continue
			}
			if err := writeTypedFrame(protocol.FrameTypeInput, data); err != nil {
				return
			}
		}
	}()

	// Agent -> Browser (TileBatch, H264, JPEG, Info & Errors)
	// Decouple remote stream reads from local WebSocket writes via a small buffered queue so
	// reading from QUIC/WSS never stalls on local browser frame scheduling.
	type wsOutMsg struct {
		msgType websocket.MessageType
		data    []byte
	}
	outCh := make(chan wsOutMsg, 32)
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-outCh:
				if !ok {
					return
				}
				if err := wsConn.Write(ctx, m.msgType, m.data); err != nil {
					return
				}
			}
		}
	}()
	defer close(outCh)

	for {
		fType, payload, err := protocol.ReadTypedFrame(stream)
		if err != nil {
			return
		}
		switch fType {
		case protocol.FrameTypeJPEG, protocol.FrameTypeTileBatch, protocol.FrameTypeH264, protocol.FrameTypeHEVC:
			tagged := make([]byte, 1+len(payload))
			tagged[0] = fType
			copy(tagged[1:], payload)
			select {
			case outCh <- wsOutMsg{msgType: websocket.MessageBinary, data: tagged}:
			case <-ctx.Done():
				return
			}
		case protocol.FrameTypeInfo, protocol.FrameTypeStats, protocol.FrameTypeCursor:
			var info map[string]any
			if json.Unmarshal(payload, &info) == nil {
				info["type"] = map[byte]string{protocol.FrameTypeInfo: "info", protocol.FrameTypeStats: "stats", protocol.FrameTypeCursor: "cursor"}[fType]
				msg, _ := json.Marshal(info)
				select {
				case outCh <- wsOutMsg{msgType: websocket.MessageText, data: msg}:
				case <-ctx.Done():
					return
				}
			}
		case protocol.FrameTypeClipboardChanged:
			select {
			case outCh <- wsOutMsg{msgType: websocket.MessageText, data: []byte(`{"type":"clipboard_changed"}`)}:
			case <-ctx.Done():
				return
			}
		case protocol.FrameTypeError:
			errMsg, _ := json.Marshal(map[string]any{"type": "error", "error": string(payload)})
			select {
			case outCh <- wsOutMsg{msgType: websocket.MessageText, data: errMsg}:
			case <-ctx.Done():
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
	wsConn.SetReadLimit(16 << 20) // 16 MiB so 4K PNG screenshots paste cleanly over clipboard!

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

type fileTransferProgress struct {
	Active       bool    `json:"active"`
	Direction    string  `json:"direction,omitempty"` // "push" or "pull"
	Name         string  `json:"name,omitempty"`
	Bytes        int64   `json:"bytes"`
	Total        int64   `json:"total"`
	BytesPerSec  float64 `json:"bytes_per_sec"`
	startedAt    time.Time
}

var (
	ftProgMu sync.Mutex
	ftProg   fileTransferProgress
)

func startFileTransferProgress(dir, name string, total int64) {
	ftProgMu.Lock()
	ftProg = fileTransferProgress{
		Active:    true,
		Direction: dir,
		Name:      name,
		Bytes:     0,
		Total:     total,
		startedAt: time.Now(),
	}
	ftProgMu.Unlock()
}

func addFileTransferBytes(n int64) {
	ftProgMu.Lock()
	ftProg.Bytes += n
	if el := time.Since(ftProg.startedAt).Seconds(); el > 0.05 {
		ftProg.BytesPerSec = float64(ftProg.Bytes) / el
	}
	ftProgMu.Unlock()
}

func finishFileTransferProgress() {
	ftProgMu.Lock()
	ftProg.Active = false
	ftProgMu.Unlock()
}

func getFileTransferProgress() fileTransferProgress {
	ftProgMu.Lock()
	defer ftProgMu.Unlock()
	return ftProg
}

func copyWithProgress(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				addFileTransferBytes(int64(nw))
			}
			if werr != nil {
				return total, werr
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// clipSyncState remembers, per remote peer, which clipboard content it already has, so automatic
// sync sends only real changes and never bounces a pulled clipboard back to its host.
type clipSyncState struct {
	mu   sync.Mutex
	hash map[string]string
	seq  map[string]uint32
}

var clipSync = &clipSyncState{hash: map[string]string{}, seq: map[string]uint32{}}

func (c *clipSyncState) remember(peerID string, kind byte, data []byte) {
	h := remote.ClipboardHash(kind, data)
	c.mu.Lock()
	c.hash[peerID] = h
	c.mu.Unlock()
}

func (c *clipSyncState) same(peerID string, kind byte, data []byte) bool {
	h := remote.ClipboardHash(kind, data)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hash[peerID] == h
}

// rememberSeq/unchangedSeq use the OS clipboard sequence number (Windows) to skip reading the
// clipboard at all when nothing was copied since the last sync. seq 0 means "not available".
func (c *clipSyncState) rememberSeq(peerID string, seq uint32) {
	if seq == 0 {
		return
	}
	c.mu.Lock()
	c.seq[peerID] = seq
	c.mu.Unlock()
}

func (c *clipSyncState) unchangedSeq(peerID string, seq uint32) bool {
	if seq == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	last, ok := c.seq[peerID]
	return ok && last == seq
}

// pushClipboardToPeer sets the remote peer's clipboard over a ModeClipboard stream.
// It returns 0 on success, otherwise an HTTP status and message.
func pushClipboardToPeer(ctx context.Context, peer *p2p.Node, peerID string, kind byte, data []byte, autoPaste bool) (int, string) {
	st, _, err := peer.OpenPeerStream(ctx, peerID, protocol.StreamOpenRequest{Mode: protocol.ModeClipboard})
	if err != nil {
		return http.StatusBadGateway, friendlyClipboardErr(err)
	}
	defer st.Close()
	if err := protocol.WriteMessage(st, remote.ClipboardRequest{
		Action:    "set",
		Kind:      kind,
		AutoPaste: autoPaste,
		Size:      int64(len(data)),
	}); err != nil {
		return http.StatusBadGateway, err.Error()
	}
	var ready remote.ClipboardResponse
	if err := protocol.ReadMessage(st, &ready); err != nil || !ready.OK {
		errMsg := "เครื่องปลายทางไม่พร้อมรับคลิปบอร์ด"
		if err != nil {
			errMsg = err.Error()
		} else if ready.Error != "" {
			errMsg = ready.Error
		}
		return http.StatusBadGateway, errMsg
	}
	if _, err := st.Write(data); err != nil {
		return http.StatusBadGateway, err.Error()
	}
	var done remote.ClipboardResponse
	if err := protocol.ReadMessage(st, &done); err != nil || !done.OK {
		errMsg := "วางคลิปบอร์ดที่เครื่องปลายทางไม่สำเร็จ"
		if err != nil {
			errMsg = err.Error()
		} else if done.Error != "" {
			errMsg = done.Error
		}
		return http.StatusBadGateway, errMsg
	}
	return 0, ""
}

func friendlyClipboardErr(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(strings.ToLower(err.Error()), "unsupported stream mode") {
		return "เครื่องปลายทางยังเป็นเวอร์ชันเก่ากว่า v1.2.10 — กรุณาอัปเดตทั้ง 2 ฝั่งเพื่อซิงค์คลิปบอร์ดรูป/ข้อความ"
	}
	return err.Error()
}

func friendlyFileStreamErr(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(strings.ToLower(err.Error()), "unsupported stream mode") {
		return "เครื่องปลายทางยังเป็น APN เวอร์ชันเก่ากว่า v1.2.7 — กรุณากดอัปเดตเครื่องปลายทางเพื่อใช้งานโอนไฟล์"
	}
	return err.Error()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
