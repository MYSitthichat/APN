package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/version"
)

const (
	numShards       = 64
	defaultTTL      = 5 * time.Minute
	releaseCacheTTL = 20 * time.Second
	maxBodyBytes    = 64 * 1024
)

// Options configures the self-hosted APN Rendezvous Directory Server.
type Options struct {
	ListenAddr   string        // e.g. "127.0.0.1:8787" or ":8787"
	SnapshotPath string        // optional JSON snapshot path for zero-gap restarts
	TTL          time.Duration // peer entry expiry TTL (default 5m)
	GitHubRepo   string        // repo for /api/releases/latest (default "MYSitthichat/APN")
	Logger       *slog.Logger
}

// PunchRequest is queued on a host entry when a caller looks up its 9-digit Device ID.
type PunchRequest struct {
	FromDeviceID string   `json:"from_device_id"`
	UDPAddrs     []string `json:"udp_addrs"`
}

// Entry represents one online APN peer in the Rendezvous Directory.
type Entry struct {
	DeviceID    string         `json:"device_id"`
	PeerID      string         `json:"peer_id"`
	Name        string         `json:"name"`
	OS          string         `json:"os"`
	Fingerprint string         `json:"fingerprint"`
	UDPAddrs    []string       `json:"udp_addrs"`
	WSURL       string         `json:"ws_url"`
	UpdatedAt   string         `json:"updated_at"`
	Punches     []PunchRequest `json:"punches,omitempty"`
	ExpiresAt   int64          `json:"expires_at"` // UnixMilli (ignored by clients, used for snapshot reload)
}

type shard struct {
	mu      sync.RWMutex
	entries map[string]*Entry
}

// Server is a lock-sharded in-memory Rendezvous Directory compatible with APN clients
// (drop-in replacement for cloudflare-worker/rendezvous-worker.js).
type Server struct {
	opts      Options
	logger    *slog.Logger
	startedAt time.Time
	shards    [numShards]shard
	dirty     atomic.Bool

	relMu     sync.Mutex
	relCached []byte
	relExp    time.Time
	relClient *http.Client
}

// NewServer creates a self-hosted Rendezvous Directory server and loads any valid snapshot entries.
func NewServer(opts Options) *Server {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:8787"
	}
	if opts.TTL <= 0 {
		opts.TTL = defaultTTL
	}
	if opts.GitHubRepo == "" {
		opts.GitHubRepo = "MYSitthichat/APN"
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	s := &Server{
		opts:      opts,
		logger:    opts.Logger,
		startedAt: time.Now(),
		relClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]*Entry, 64)
	}
	if opts.SnapshotPath != "" {
		if n, err := s.LoadSnapshot(opts.SnapshotPath); err == nil && n > 0 {
			s.logger.Info("loaded rendezvous snapshot into RAM", "peers", n, "path", opts.SnapshotPath)
		}
	}
	return s
}

func normalizeID(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func (s *Server) shardFor(id string) *shard {
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return &s.shards[h&(numShards-1)]
}

// Handler returns the HTTP handler serving all APN Rendezvous & release manifest endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/releases/latest", s.handleLatestRelease)
	mux.HandleFunc("POST /api/rendezvous/register", s.handleRegister)
	mux.HandleFunc("POST /api/rendezvous/unregister", s.handleUnregister)
	mux.HandleFunc("POST /api/rendezvous/presence", s.handlePresence)
	mux.HandleFunc("/api/rendezvous/lookup/", s.handleLookup)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("APN Self-Hosted Rendezvous Directory Ready"))
	})
	return mux
}

// Run starts the HTTP server, background TTL sweeper, and periodic disk snapshot loop until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.opts.ListenAddr, err)
	}

	httpSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	// Background expiry sweeper + periodic snapshot writer (zero-gap restarts)
	go s.maintenanceLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("APN Self-Hosted Rendezvous Server listening",
			"addr", ln.Addr().String(),
			"ttl", s.opts.TTL.String(),
			"snapshot", s.opts.SnapshotPath,
			"version", version.Version)
		if serr := httpSrv.Serve(ln); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		if s.opts.SnapshotPath != "" {
			if n, err := s.SaveSnapshot(s.opts.SnapshotPath); err == nil {
				s.logger.Info("saved rendezvous snapshot on shutdown", "peers", n, "path", s.opts.SnapshotPath)
			}
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SweepExpired()
			if s.opts.SnapshotPath != "" && s.dirty.Swap(false) {
				if _, err := s.SaveSnapshot(s.opts.SnapshotPath); err != nil {
					s.logger.Warn("periodic snapshot save failed", "err", err)
					s.dirty.Store(true)
				}
			}
		}
	}
}

// SweepExpired removes expired entries across all shards and returns the number removed.
func (s *Server) SweepExpired() int {
	nowMs := time.Now().UnixMilli()
	removed := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, v := range sh.entries {
			if v.ExpiresAt <= nowMs {
				delete(sh.entries, k)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.dirty.Store(true)
	}
	return removed
}

// OnlineCount returns the current number of non-expired online peers in RAM.
func (s *Server) OnlineCount() int {
	nowMs := time.Now().UnixMilli()
	total := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for _, v := range sh.entries {
			if v.ExpiresAt > nowMs {
				total++
			}
		}
		sh.mu.RUnlock()
	}
	return total
}

// SaveSnapshot atomically persists all non-expired peer entries to path.
func (s *Server) SaveSnapshot(path string) (int, error) {
	nowMs := time.Now().UnixMilli()
	var list []*Entry
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for _, v := range sh.entries {
			if v.ExpiresAt > nowMs {
				cp := *v
				cp.Punches = nil // punches are transient; no need to persist
				list = append(list, &cp)
			}
		}
		sh.mu.RUnlock()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	data, err := json.Marshal(list)
	if err != nil {
		return 0, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return len(list), nil
}

// LoadSnapshot restores non-expired peer entries from path into RAM.
func (s *Server) LoadSnapshot(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var list []*Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}
	nowMs := time.Now().UnixMilli()
	loaded := 0
	for _, e := range list {
		if e == nil || e.DeviceID == "" || e.ExpiresAt <= nowMs {
			continue
		}
		sh := s.shardFor(e.DeviceID)
		sh.mu.Lock()
		sh.entries[e.DeviceID] = e
		sh.mu.Unlock()
		loaded++
	}
	return loaded, nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"service":      "apn-rendezvous",
		"backend":      "self-hosted-go",
		"version":      version.Version,
		"online_peers": s.OnlineCount(),
		"uptime_sec":   int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID    string   `json:"device_id"`
		PeerID      string   `json:"peer_id"`
		Name        string   `json:"name"`
		OS          string   `json:"os"`
		Fingerprint string   `json:"fingerprint"`
		UDPAddrs    []string `json:"udp_addrs"`
		WSURL       string   `json:"ws_url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	id := normalizeID(body.DeviceID)
	if len(id) < 6 || len(id) > 16 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid device_id"})
		return
	}
	if len(body.UDPAddrs) > 16 {
		body.UDPAddrs = body.UDPAddrs[:16]
	}

	now := time.Now().UTC()
	entry := &Entry{
		DeviceID:    id,
		PeerID:      body.PeerID,
		Name:        body.Name,
		OS:          body.OS,
		Fingerprint: body.Fingerprint,
		UDPAddrs:    body.UDPAddrs,
		WSURL:       body.WSURL,
		UpdatedAt:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(s.opts.TTL).UnixMilli(),
	}

	sh := s.shardFor(id)
	sh.mu.Lock()
	var pendingPunches []PunchRequest
	if prev := sh.entries[id]; prev != nil && len(prev.Punches) > 0 {
		pendingPunches = prev.Punches
	}
	sh.entries[id] = entry
	sh.mu.Unlock()
	s.dirty.Store(true)

	if pendingPunches == nil {
		pendingPunches = []PunchRequest{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"punch_requests": pendingPunches,
	})
}

func (s *Server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body)
	id := normalizeID(body.DeviceID)
	if len(id) >= 6 && len(id) <= 16 {
		sh := s.shardFor(id)
		sh.mu.Lock()
		delete(sh.entries, id)
		sh.mu.Unlock()
		s.dirty.Store(true)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePresence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body)
	ids := body.IDs
	if len(ids) > 64 {
		ids = ids[:64]
	}

	nowMs := time.Now().UnixMilli()
	peers := make(map[string]any, len(ids))
	for _, raw := range ids {
		id := normalizeID(raw)
		if len(id) < 6 || len(id) > 16 {
			continue
		}
		sh := s.shardFor(id)
		sh.mu.RLock()
		e := sh.entries[id]
		if e != nil && e.ExpiresAt > nowMs {
			peers[id] = map[string]any{
				"online":     true,
				"name":       e.Name,
				"os":         e.OS,
				"updated_at": e.UpdatedAt,
			}
		} else {
			peers[id] = map[string]any{"online": false}
		}
		sh.mu.RUnlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "peers": peers})
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimPrefix(r.URL.Path, "/api/rendezvous/lookup/")
	id := normalizeID(rawID)
	if len(id) < 6 || len(id) > 16 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid device_id"})
		return
	}

	var caller PunchRequest
	hasPunch := false
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&caller); err == nil && len(caller.UDPAddrs) > 0 {
			if len(caller.UDPAddrs) > 16 {
				caller.UDPAddrs = caller.UDPAddrs[:16]
			}
			hasPunch = true
		}
	}

	nowMs := time.Now().UnixMilli()
	sh := s.shardFor(id)
	sh.mu.Lock()
	e := sh.entries[id]
	if e == nil || e.ExpiresAt <= nowMs {
		if e != nil {
			delete(sh.entries, id)
		}
		sh.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]any{
			"ok":    false,
			"error": "ไม่พบเครื่องหมายเลขนี้ในระบบ Rendezvous (อาจออฟไลน์อยู่)",
		})
		return
	}
	if hasPunch {
		if len(e.Punches) >= 5 {
			e.Punches = append(e.Punches[len(e.Punches)-4:], caller)
		} else {
			e.Punches = append(e.Punches, caller)
		}
	}
	cp := *e
	cp.Punches = nil
	sh.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"entry": cp,
	})
}

var ghTagRe = regexp.MustCompile(`/releases/tag/([^/?#]+)`)

func (s *Server) handleLatestRelease(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1"
	s.relMu.Lock()
	if !force && len(s.relCached) > 0 && time.Now().Before(s.relExp) {
		payload := append([]byte(nil), s.relCached...)
		s.relMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}
	s.relMu.Unlock()

	payload, err := s.fetchLatestReleaseJSON(r.Context())
	if err != nil {
		// Serve stale cache if GitHub is briefly unreachable
		s.relMu.Lock()
		stale := append([]byte(nil), s.relCached...)
		s.relMu.Unlock()
		if len(stale) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(stale)
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	s.relMu.Lock()
	s.relCached = payload
	s.relExp = time.Now().Add(releaseCacheTTL)
	s.relMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) fetchLatestReleaseJSON(ctx context.Context) ([]byte, error) {
	repo := s.opts.GitHubRepo
	tagURL := fmt.Sprintf("https://github.com/%s/releases/latest/download/latest.json", repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://github.com/%s/releases/latest?t=%d", repo, time.Now().UnixMilli()), nil)
	if err == nil {
		req.Header.Set("User-Agent", "APN-Rendezvous/"+version.Version)
		req.Header.Set("Cache-Control", "no-cache")
		if resp, derr := s.relClient.Do(req); derr == nil {
			loc := resp.Header.Get("Location")
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if m := ghTagRe.FindStringSubmatch(loc); len(m) == 2 {
				tagURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/latest.json", repo, m[1])
			}
		}
	}

	followClient := &http.Client{Timeout: 10 * time.Second}
	cdnReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tagURL, nil)
	if err != nil {
		return nil, err
	}
	cdnReq.Header.Set("User-Agent", "APN-Rendezvous/"+version.Version)
	cdnReq.Header.Set("Cache-Control", "no-cache")
	cdnResp, err := followClient.Do(cdnReq)
	if err != nil {
		return nil, err
	}
	defer cdnResp.Body.Close()
	if cdnResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github latest.json HTTP %d", cdnResp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(cdnResp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	// Strip UTF-8 BOM if present
	raw = []byte(strings.TrimPrefix(string(raw), "\uFEFF"))
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	parsed["repo"] = repo
	parsed["source"] = "self-hosted-rdv-github-cdn"
	return json.Marshal(parsed)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
