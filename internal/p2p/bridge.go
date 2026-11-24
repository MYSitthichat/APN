package p2p

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/executil"
)

var tryCloudflareRe = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

// BridgeStatus describes the zero-VPS automatic HTTPS Port 443 Internet Bridge.
type BridgeStatus struct {
	Enabled   bool   `json:"enabled"`
	Ready     bool   `json:"ready"`
	PublicURL string `json:"public_url,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type internetBridge struct {
	logger *slog.Logger
	onURL  func(url string)

	mu        sync.Mutex
	enabled   bool
	running   bool
	publicURL string
	lastErr   string
	cancel    context.CancelFunc
}

func newInternetBridge(logger *slog.Logger, onURL func(string)) *internetBridge {
	return &internetBridge{
		logger: logger,
		onURL:  onURL,
	}
}

func (b *internetBridge) Start(parentCtx context.Context, wsPort int) error {
	if wsPort <= 0 {
		return errors.New("local WS peer port is not active")
	}

	b.mu.Lock()
	b.enabled = true
	if b.running {
		b.mu.Unlock()
		return nil
	}
	cfPath, ok := bootstrap.FindCloudflared()
	if !ok {
		b.lastErr = "กำลังรอติดตั้ง cloudflared อัตโนมัติ..."
		b.mu.Unlock()
		return nil
	}
	b.running = true
	b.lastErr = ""
	b.publicURL = ""
	ctx, cancel := context.WithCancel(parentCtx)
	b.cancel = cancel
	b.mu.Unlock()

	go b.supervisorLoop(ctx, cfPath, wsPort)
	return nil
}

func (b *internetBridge) Stop() {
	b.mu.Lock()
	b.enabled = false
	cancel := b.cancel
	b.cancel = nil
	b.running = false
	b.publicURL = ""
	b.lastErr = ""
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if b.onURL != nil {
		b.onURL("")
	}
}

func (b *internetBridge) supervisorLoop(ctx context.Context, cfPath string, wsPort int) {
	defer func() {
		b.mu.Lock()
		b.running = false
		b.publicURL = ""
		b.mu.Unlock()
		if b.onURL != nil {
			b.onURL("")
		}
	}()

	for ctx.Err() == nil {
		b.runOnce(ctx, cfPath, wsPort)
		if ctx.Err() != nil {
			return
		}
		// Clear dead quick-tunnel URL immediately so Rendezvous never advertises a stale 530 endpoint!
		b.mu.Lock()
		b.publicURL = ""
		b.mu.Unlock()
		if b.onURL != nil {
			b.onURL("")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (b *internetBridge) runOnce(ctx context.Context, cfPath string, wsPort int) {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	targetURL := "http://127.0.0.1:" + strconv.Itoa(wsPort)
	// Force --protocol http2 (TCP port 443) so cloudflared works reliably even behind firewalls that block UDP 7844!
	cmd := exec.CommandContext(runCtx, cfPath, "tunnel", "--no-autoupdate", "--protocol", "http2", "--url", targetURL)
	executil.HideWindow(cmd)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.setErr(err.Error())
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.setErr(err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		b.setErr(fmt.Sprintf("เปิด cloudflared ไม่สำเร็จ: %v", err))
		return
	}

	var publishOnce sync.Once
	var urlFound string
	var urlMu sync.Mutex

	publishLive := func(u string) {
		if u == "" || runCtx.Err() != nil {
			return
		}
		publishOnce.Do(func() {
			b.mu.Lock()
			b.publicURL = u
			b.lastErr = ""
			b.mu.Unlock()
			b.logger.Info("Internet Bridge (HTTPS 443 HTTP/2) live", "url", u)
			if b.onURL != nil {
				b.onURL(u)
			}
			go b.healthWatchdog(runCtx, u, cancelRun)
		})
	}

	scanPipe := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			if m := tryCloudflareRe.FindString(line); m != "" {
				urlMu.Lock()
				urlFound = m
				urlMu.Unlock()
				// Wait briefly for edge registration ("Registered tunnel connection") so callers
				// don't race into HTTP 530 during initial DNS/edge propagation!
				go func(candidate string) {
					select {
					case <-runCtx.Done():
						return
					case <-time.After(3500 * time.Millisecond):
						publishLive(candidate)
					}
				}(m)
			}
			// Once cloudflared confirms edge tunnel registration, publish immediately!
			if len(line) > 0 && containsRegistered(line) {
				urlMu.Lock()
				u := urlFound
				urlMu.Unlock()
				if u != "" {
					// Give Cloudflare edge ~1.2s to route the fresh quick-tunnel hostname cleanly
					go func(candidate string) {
						select {
						case <-runCtx.Done():
							return
						case <-time.After(1200 * time.Millisecond):
							publishLive(candidate)
						}
					}(u)
				}
			}
		}
	}

	go scanPipe(stdout)
	scanPipe(stderr)

	err = cmd.Wait()
	if ctx.Err() == nil && err != nil {
		b.setErr(fmt.Sprintf("กำลังเชื่อมต่อท่อ 443 ใหม่... (%v)", err))
	}
}

// healthWatchdog periodically verifies our own trycloudflare.com tunnel end-to-end via GET /healthz.
// Cloudflare Quick Tunnels can silently expire (returning HTTP 530 / Error 1033) without cloudflared
// exiting — this watchdog detects 530/502/504 immediately and recycles cloudflared to a fresh tunnel!
func (b *internetBridge) healthWatchdog(ctx context.Context, baseURL string, cancelRun context.CancelFunc) {
	hc := &http.Client{Timeout: 7 * time.Second}
	probe := func() (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err != nil {
			return 0, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}

	// Initial check 12s after start, then every 35s
	select {
	case <-ctx.Done():
		return
	case <-time.After(12 * time.Second):
	}

	ticker := time.NewTicker(35 * time.Second)
	defer ticker.Stop()

	for {
		code, err := probe()
		dead := err != nil || code == 530 || code == 502 || code == 503 || code == 504 || code == 404
		if dead && ctx.Err() == nil {
			// Quick 4s double-check to avoid false positives from a momentary 1s packet blip
			select {
			case <-ctx.Done():
				return
			case <-time.After(4 * time.Second):
			}
			code2, err2 := probe()
			dead2 := err2 != nil || code2 == 530 || code2 == 502 || code2 == 503 || code2 == 504 || code2 == 404
			if dead2 && ctx.Err() == nil {
				b.logger.Warn("Internet Bridge quick tunnel is stale/dead — recycling for a fresh 443 tunnel",
					"url", baseURL, "status", code2, "err", err2)
				b.setErr(fmt.Sprintf("ท่อ 443 เดิมหลุด (HTTP %d) กำลังสร้างท่อใหม่...", code2))
				cancelRun()
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func containsRegistered(line string) bool {
	for i := 0; i+10 <= len(line); i++ {
		if line[i] == 'R' && line[i:i+10] == "Registered" {
			return true
		}
	}
	return false
}

func (b *internetBridge) setErr(msg string) {
	b.mu.Lock()
	b.lastErr = msg
	b.mu.Unlock()
}

func (b *internetBridge) Status() BridgeStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return BridgeStatus{
		Enabled:   b.enabled,
		Ready:     b.running && b.publicURL != "",
		PublicURL: b.publicURL,
		LastError: b.lastErr,
	}
}
