package p2p

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	targetURL := "http://127.0.0.1:" + strconv.Itoa(wsPort)
	// Force --protocol http2 (TCP port 443) so cloudflared works reliably even behind firewalls that block UDP 7844!
	cmd := exec.CommandContext(ctx, cfPath, "tunnel", "--no-autoupdate", "--protocol", "http2", "--url", targetURL)
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

	var registeredOnce sync.Once
	var urlFound string
	var urlMu sync.Mutex

	notifyLive := func(u string) {
		b.mu.Lock()
		changed := b.publicURL != u
		b.publicURL = u
		b.lastErr = ""
		b.mu.Unlock()
		if changed {
			b.logger.Info("Internet Bridge (HTTPS 443 HTTP/2) live", "url", u)
			if b.onURL != nil {
				b.onURL(u)
			}
		}
	}

	scanPipe := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			if m := tryCloudflareRe.FindString(line); m != "" {
				urlMu.Lock()
				urlFound = m
				urlMu.Unlock()
				// Publish as soon as quick tunnel URL appears (or on Registered tunnel connection)
				notifyLive(m)
			}
			// Re-notify once tunnel registration confirms edge connection is active
			if len(line) > 0 && containsRegistered(line) {
				registeredOnce.Do(func() {
					urlMu.Lock()
					u := urlFound
					urlMu.Unlock()
					if u != "" {
						notifyLive(u)
					}
				})
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
