package p2p

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"relayvpn/internal/config"
)

func TestStealthHelpers(t *testing.T) {
	for in, want := range map[string]string{
		":8444":          "127.0.0.1:8444",
		"0.0.0.0:8444":   "127.0.0.1:8444",
		"[::]:8444":      "127.0.0.1:8444",
		"127.0.0.1:0":    "127.0.0.1:0",
		"192.168.1.5:80": "192.168.1.5:80",
	} {
		if got := wsListenAddr(in); got != want {
			t.Errorf("wsListenAddr(%q) = %q, want %q", in, got, want)
		}
	}
	if got := quicListenCandidates(":4433"); len(got) != 2 || got[0] != ":443" || got[1] != ":4433" {
		t.Errorf("default QUIC address candidates = %v", got)
	}
	if got := quicListenCandidates("127.0.0.1:0"); len(got) != 1 || got[0] != "127.0.0.1:0" {
		t.Errorf("explicit QUIC address candidates = %v", got)
	}
	for in, want := range map[string]string{
		"wss://x.trycloudflare.com/ws/peer": "wss://x.trycloudflare.com/ws/peer-e2e",
		"ws://10.0.0.5:8444/ws/peer":        "ws://10.0.0.5:8444/ws/peer-e2e",
		"wss://example.com/custom":          "",
	} {
		if got := e2eWSURL(in); got != want {
			t.Errorf("e2eWSURL(%q) = %q, want %q", in, got, want)
		}
	}
	a, b := punchPacket(), punchPacket()
	if a[0] != 0 || len(a) != punchPacketBytes || string(a) == string(b) || strings.Contains(string(a), "RVPN") {
		t.Errorf("punch packets must be random noise starting with 0: %x %x", a, b)
	}
}

func newStealthNode(t *testing.T, ctx context.Context, id string) *Node {
	t.Helper()
	dir := t.TempDir()
	n, err := NewNode(&config.PeerConfig{
		PeerID: id, Name: id, PairSecret: "secret-" + id + "-1234567890",
		QUICAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0",
		CertFile: filepath.Join(dir, "peer.crt"), KeyFile: filepath.Join(dir, "peer.key"),
		AllowScreen: true, AllowInput: true, AllowShell: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.StartAsync(ctx); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestWebSocketPathIsEndToEndEncrypted: over the 443 fallback the session between the two
// machines is TLS 1.3 with the host's certificate pinned, so the tunnel in between (Cloudflare)
// sees only ciphertext, and a substituted host is refused.
func TestWebSocketPathIsEndToEndEncrypted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := newStealthNode(t, ctx, "host")
	viewer := newStealthNode(t, ctx, "viewer")
	wsURL := "ws://" + host.wsAddrStr + "/ws/peer"

	// A wrong pinned fingerprint (someone else's server on the path) is refused before the
	// password is sent.
	if _, err := viewer.dialWSPeer(ctx, wsURL, host.cfg.PairSecret, "sha256:"+strings.Repeat("ab", 32), false); err == nil ||
		!strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("wrong host certificate: err = %v, want a fingerprint mismatch", err)
	}

	info, err := viewer.dialWSPeer(ctx, wsURL, host.cfg.PairSecret, host.identity.Fingerprint, false)
	if err != nil {
		t.Fatalf("E2E WebSocket connect: %v", err)
	}
	if info.Transport != transportWSE2E {
		t.Fatalf("transport = %q, want %q", info.Transport, transportWSE2E)
	}
}

// TestWebSocketPathOldHostStillWorks: a host without the E2E endpoint (an older APN) is still
// reached, labelled as not end-to-end encrypted.
func TestWebSocketPathOldHostStillWorks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := newStealthNode(t, ctx, "oldhost")
	viewer := newStealthNode(t, ctx, "viewer2")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws/peer", host.handleIncomingWS) // what an older version serves
	old := httptest.NewServer(mux)
	defer old.Close()

	info, err := viewer.dialWSPeer(ctx, "ws"+strings.TrimPrefix(old.URL, "http")+"/ws/peer", host.cfg.PairSecret, host.identity.Fingerprint, false)
	if err != nil {
		t.Fatalf("connect to an older host: %v", err)
	}
	if !strings.Contains(info.Transport, "ไม่เข้ารหัส") {
		t.Fatalf("an older host's connection must be labelled as not end-to-end encrypted, got %q", info.Transport)
	}
}

// TestQUICFallsBackToLegacyALPN: new peers offer "h3"; an older APN that knows only the legacy
// ALPN is still reached.
func TestQUICFallsBackToLegacyALPN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	viewer := newStealthNode(t, ctx, "viewer3")
	oldID := newStealthNode(t, ctx, "oldquic").identity

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	defer tr.Close()
	legacy := oldID.ServerTLSConfig()
	legacy.NextProtos = []string{P2PALPN}
	ln, err := tr.Listen(legacy, defaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan string, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c.ConnectionState().TLS.NegotiatedProtocol
		}
	}()
	sess, err := viewer.dialQUICSession(ctx, pc.LocalAddr().String(), oldID.Fingerprint, 3*time.Second)
	if err != nil {
		t.Fatalf("dial a legacy-ALPN peer: %v", err)
	}
	defer sess.Close()
	select {
	case proto := <-accepted:
		if proto != P2PALPN {
			t.Fatalf("negotiated %q with the legacy peer", proto)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the legacy peer never accepted")
	}

	// And two new peers agree on h3.
	cfg := viewer.identity.ClientTLSConfig("")
	srv := oldID.ServerTLSConfig()
	if cfg.NextProtos[0] != alpnHTTP3 || srv.NextProtos[0] != alpnHTTP3 {
		t.Fatalf("new peers should offer h3 first: client %v server %v", cfg.NextProtos, srv.NextProtos)
	}
	_ = tls.VersionTLS13
}
