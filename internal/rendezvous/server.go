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
	maxBodyBytes    = 16 * 1024

	// Field limits: a public directory must not let one request store kilobytes of junk.
	maxNameLen     = 128
	maxShortLen    = 128 // peer_id, os
	maxFPLen       = 80
	maxWSURLLen    = 512
	maxUDPAddrs    = 16
	maxUDPAddrLen  = 64
	maxIDsPerQuery = 64

	defaultMaxEntries   = 2_000_000
	defaultRatePerMin   = 600 // per client IP; a NAT with ~100 APN devices stays below it
	defaultRateBurst    = 300
	forcedReleaseMinGap = 10 * time.Second
)

// Options configures the self-hosted APN Rendezvous Directory Server.
type Options struct {
	ListenAddr   string        // e.g. "127.0.0.1:8787" or ":8787"
	SnapshotPath string        // optional JSON snapshot path for zero-gap restarts
	TTL          time.Duration // peer entry expiry TTL (default 5m)
	GitHubRepo   string        // repo for /api/releases/latest (default "MYSitthichat/APN")
	Logger       *slog.Logger
	MaxEntries   int // cap on online entries kept in RAM (default 2,000,000)
	RatePerMin   int // per-IP request budget per minute (default 600; negative disables)
	RateBurst    int // per-IP burst (default 300)
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
	Signed      bool           `json:"signed,omitempty"`
}

// binding ties a device ID to the certificate fingerprint whose key signed for it.
type binding struct {
	FP    string `json:"fp"`
	Until int64  `json:"until"` // UnixMilli
}

type shard struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	bindings map[string]*binding
}

// snapshotFile is the on-disk snapshot format (v2). v1 snapshots were a bare []*Entry.
type snapshotFile struct {
	Entries  []*Entry            `json:"entries"`
	Bindings map[string]*binding `json:"bindings"`
}

// Server is a lock-sharded in-memory Rendezvous Directory compatible with APN clients
// (drop-in replacement for cloudflare-worker/rendezvous-worker.js).
type Server struct {
	opts      Options
	logger    *slog.Logger
	startedAt time.Time
	shards    [numShards]shard
	dirty     atomic.Bool
	count     atomic.Int64

	relMu      sync.Mutex
	relCached  []byte
	relExp     time.Time
	relFetched time.Time
	relFetchMu sync.Mutex
	relClient  *http.Client

	limiter *ipLimiter
	now     func() time.Time
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
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.RatePerMin == 0 {
		opts.RatePerMin = defaultRatePerMin
	}
	if opts.RateBurst <= 0 {
		opts.RateBurst = defaultRateBurst
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
		now: time.Now,
	}
	if opts.RatePerMin > 0 {
		s.limiter = newIPLimiter(opts.RatePerMin, opts.RateBurst)
	}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]*Entry, 64)
		s.shards[i].bindings = make(map[string]*binding, 64)
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
	if s.limiter == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !s.limiter.allow(clientIP(r), s.now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "too many requests"})
			return
		}
		mux.ServeHTTP(w, r)
	})
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
			if s.limiter != nil {
				s.limiter.prune(s.now())
			}
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
	nowMs := s.now().UnixMilli()
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
		for k, b := range sh.bindings {
			if b.Until <= nowMs {
				delete(sh.bindings, k)
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.count.Add(int64(-removed))
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
	nowMs := s.now().UnixMilli()
	snap := snapshotFile{Bindings: map[string]*binding{}}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for _, v := range sh.entries {
			if v.ExpiresAt > nowMs {
				cp := *v
				cp.Punches = nil // punches are transient; no need to persist
				snap.Entries = append(snap.Entries, &cp)
			}
		}
		for id, b := range sh.bindings {
			if b.Until > nowMs {
				cp := *b
				snap.Bindings[id] = &cp
			}
		}
		sh.mu.RUnlock()
	}
	list := snap.Entries

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	data, err := json.Marshal(snap)
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
	var snap snapshotFile
	if err := json.Unmarshal(data, &snap); err != nil {
		// v1 snapshot: a bare list of entries
		var list []*Entry
		if err2 := json.Unmarshal(data, &list); err2 != nil {
			return 0, err
		}
		snap.Entries = list
	}
	nowMs := s.now().UnixMilli()
	loaded := 0
	for _, e := range snap.Entries {
		if e == nil || e.DeviceID == "" || e.ExpiresAt <= nowMs {
			continue
		}
		sh := s.shardFor(e.DeviceID)
		sh.mu.Lock()
		if _, exists := sh.entries[e.DeviceID]; !exists {
			s.count.Add(1)
		}
		sh.entries[e.DeviceID] = e
		sh.mu.Unlock()
		loaded++
	}
	for id, b := range snap.Bindings {
		if b == nil || b.FP == "" || b.Until <= nowMs {
			continue
		}
		sh := s.shardFor(id)
		sh.mu.Lock()
		sh.bindings[id] = b
		sh.mu.Unlock()
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
		Ts          int64    `json:"ts"`
		Cert        string   `json:"cert"`
		Sig         string   `json:"sig"`
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
	if msg := checkRegisterFields(body.Fingerprint, body.WSURL, body.UDPAddrs); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": msg})
		return
	}
	body.Name = truncate(body.Name, maxNameLen)
	body.PeerID = truncate(body.PeerID, maxShortLen)
	body.OS = truncate(body.OS, maxShortLen)

	now := s.now().UTC()
	signed := false
	if body.Sig != "" || body.Cert != "" {
		msg := SignedMessage("register", id, body.Fingerprint, body.Ts, body.WSURL, body.UDPAddrs)
		if err := VerifySignature(body.Cert, body.Sig, body.Fingerprint, body.Ts, msg, now); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "signature rejected: " + err.Error()})
			return
		}
		signed = true
	}

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
		Signed:      signed,
	}

	nowMs := now.UnixMilli()
	sh := s.shardFor(id)
	sh.mu.Lock()
	prev := sh.entries[id]
	if prev != nil && prev.ExpiresAt <= nowMs {
		prev = nil
	}
	if status, msg := checkClaim(sh.bindings[id], prev, body.Fingerprint, signed, nowMs); status != 0 {
		sh.mu.Unlock()
		writeJSON(w, status, map[string]any{"ok": false, "error": msg})
		return
	}
	if sh.entries[id] == nil {
		if s.count.Load() >= int64(s.opts.MaxEntries) {
			sh.mu.Unlock()
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "directory full"})
			return
		}
		s.count.Add(1)
	}
	var pendingPunches []PunchRequest
	if prev != nil && len(prev.Punches) > 0 {
		pendingPunches = prev.Punches
	}
	// Persist only real changes; a plain heartbeat must not rewrite the whole snapshot.
	if prev == nil || prev.Fingerprint != entry.Fingerprint || prev.WSURL != entry.WSURL ||
		strings.Join(prev.UDPAddrs, ",") != strings.Join(entry.UDPAddrs, ",") || prev.Name != entry.Name {
		s.dirty.Store(true)
	}
	if signed {
		b := sh.bindings[id]
		if b == nil || b.FP != strings.ToLower(body.Fingerprint) {
			s.dirty.Store(true)
		}
		sh.bindings[id] = &binding{FP: strings.ToLower(body.Fingerprint), Until: now.Add(BindingTTL).UnixMilli()}
	}
	sh.entries[id] = entry
	sh.mu.Unlock()

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
		DeviceID    string `json:"device_id"`
		Fingerprint string `json:"fingerprint"`
		Ts          int64  `json:"ts"`
		Cert        string `json:"cert"`
		Sig         string `json:"sig"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body)
	id := normalizeID(body.DeviceID)
	if len(id) < 6 || len(id) > 16 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	now := s.now()
	signedFP := ""
	if body.Sig != "" || body.Cert != "" {
		msg := SignedMessage("unregister", id, body.Fingerprint, body.Ts, "", nil)
		if err := VerifySignature(body.Cert, body.Sig, body.Fingerprint, body.Ts, msg, now); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "signature rejected: " + err.Error()})
			return
		}
		signedFP = strings.ToLower(body.Fingerprint)
	}
	nowMs := now.UnixMilli()
	sh := s.shardFor(id)
	sh.mu.Lock()
	e := sh.entries[id]
	b := sh.bindings[id]
	// Only the device that owns the ID may take it offline: the bound key, or (for an unbound
	// legacy entry) a signature from the key of the live entry. An anonymous request cannot.
	allowed := false
	switch {
	case b != nil && b.Until > nowMs:
		allowed = signedFP != "" && signedFP == b.FP
	case e != nil:
		allowed = signedFP != "" && strings.EqualFold(signedFP, e.Fingerprint) ||
			(signedFP == "" && !e.Signed && body.Fingerprint != "" && strings.EqualFold(body.Fingerprint, e.Fingerprint))
	}
	if allowed && e != nil {
		delete(sh.entries, id)
		s.count.Add(-1)
		s.dirty.Store(true)
	}
	sh.mu.Unlock()
	if !allowed && e != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "not the owner of this device ID"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// checkClaim decides whether a register for an ID may replace what the directory holds.
// It returns 0 when allowed, or an HTTP status and message.
//
//   - An ID bound to a key (a signed register within BindingTTL) accepts only signed
//     registers from that same certificate.
//   - A live entry (not expired) accepts only the same fingerprint, so an attacker cannot take
//     over an online legacy device either; a legitimate certificate change waits for the TTL.
//   - Otherwise (no binding, nothing live) the first register wins, signed or not, so devices
//     that have not updated yet keep working.
func checkClaim(b *binding, live *Entry, fingerprint string, signed bool, nowMs int64) (int, string) {
	fp := strings.ToLower(fingerprint)
	if b != nil && b.Until > nowMs {
		if !signed {
			return http.StatusUnauthorized, "this device ID is bound to a signing key; unsigned registration refused (update APN)"
		}
		if b.FP != fp {
			return http.StatusConflict, "this device ID belongs to another device key"
		}
		return 0, ""
	}
	if live != nil && !strings.EqualFold(live.Fingerprint, fp) {
		return http.StatusConflict, "this device ID is online with another certificate"
	}
	return 0, ""
}

func checkRegisterFields(fingerprint, wsURL string, udpAddrs []string) string {
	if len(fingerprint) > maxFPLen {
		return "fingerprint too long"
	}
	if len(wsURL) > maxWSURLLen {
		return "ws_url too long"
	}
	if wsURL != "" && !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
		return "ws_url must be ws:// or wss://"
	}
	if len(udpAddrs) > maxUDPAddrs {
		return "too many udp_addrs"
	}
	for _, a := range udpAddrs {
		if len(a) > maxUDPAddrLen {
			return "udp_addr too long"
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) handlePresence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&body)
	ids := body.IDs
	if len(ids) > maxIDsPerQuery {
		ids = ids[:maxIDsPerQuery]
	}

	nowMs := s.now().UnixMilli()
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
			if len(caller.UDPAddrs) > maxUDPAddrs {
				caller.UDPAddrs = caller.UDPAddrs[:maxUDPAddrs]
			}
			addrs := caller.UDPAddrs[:0]
			for _, a := range caller.UDPAddrs {
				if len(a) <= maxUDPAddrLen {
					addrs = append(addrs, a)
				}
			}
			caller.UDPAddrs = addrs
			caller.FromDeviceID = truncate(normalizeID(caller.FromDeviceID), 16)
			hasPunch = len(caller.UDPAddrs) > 0
		}
	}

	nowMs := s.now().UnixMilli()
	sh := s.shardFor(id)
	sh.mu.Lock()
	e := sh.entries[id]
	if e == nil || e.ExpiresAt <= nowMs {
		if e != nil {
			delete(sh.entries, id)
			s.count.Add(-1)
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
	// Clients always send ?refresh=1, and anyone can. Honour it at most once per
	// forcedReleaseMinGap so request floods cannot hammer GitHub (and get this server's IP
	// rate-limited); concurrent misses share one fetch.
	force := r.URL.Query().Get("refresh") == "1"
	serveCached := func() bool {
		s.relMu.Lock()
		now := s.now()
		fresh := len(s.relCached) > 0 && now.Before(s.relExp)
		recent := len(s.relCached) > 0 && now.Sub(s.relFetched) < forcedReleaseMinGap
		if !(fresh && !force) && !recent {
			s.relMu.Unlock()
			return false
		}
		payload := append([]byte(nil), s.relCached...)
		s.relMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return true
	}
	if serveCached() {
		return
	}
	s.relFetchMu.Lock()
	defer s.relFetchMu.Unlock()
	if serveCached() { // another request fetched while we waited
		return
	}

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
	s.relFetched = s.now()
	s.relExp = s.relFetched.Add(releaseCacheTTL)
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
