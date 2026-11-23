package protocol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

const (
	wsReadLimitBytes = 4 << 20 // 4 MiB per WebSocket message frame
)

// NewYamuxConfig returns tuned Yamux settings for smooth 60 FPS video & VPN tunnels over port 443.
func NewYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.ConnectionWriteTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 30 * time.Second
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024 // 4 MiB prevents H.264 keyframe stalls over Internet RTT
	cfg.LogOutput = io.Discard
	return cfg
}

// DialOptions configures an outbound TLS 1.3 + WebSocket + Yamux session.
type DialOptions struct {
	ServerURL string
	Token     string
	Role      string
	PeerID    string
	PeerName  string
	PeerOS    string
	TLSConfig *tls.Config
	AsServer  bool // If true, runs yamux.Server on this side (used by Agents that accept streams)
}

// DialSession establishes a TLS 1.3 WebSocket connection and upgrades it to a Yamux multiplexed session.
// sessionCtx controls the lifetime of the underlying WebSocket net.Conn.
func DialSession(sessionCtx context.Context, opts DialOptions) (*yamux.Session, error) {
	dialCtx, cancel := context.WithTimeout(sessionCtx, 15*time.Second)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   opts.TLSConfig,
			ForceAttemptHTTP2: false, // WebSocket RFC 6455 upgrades over HTTP/1.1 TLS 1.3
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+opts.Token)
	headers.Set(HeaderRole, opts.Role)
	headers.Set(HeaderPeerID, opts.PeerID)
	if opts.PeerName != "" {
		headers.Set(HeaderPeerName, opts.PeerName)
	}
	if opts.PeerOS != "" {
		headers.Set(HeaderPeerOS, opts.PeerOS)
	}

	wsConn, resp, err := websocket.Dial(dialCtx, opts.ServerURL, &websocket.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      headers,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("websocket dial failed (HTTP %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	wsConn.SetReadLimit(wsReadLimitBytes)

	netConn := websocket.NetConn(sessionCtx, wsConn, websocket.MessageBinary)
	if opts.AsServer {
		return yamux.Server(netConn, NewYamuxConfig())
	}
	return yamux.Client(netConn, NewYamuxConfig())
}

// AcceptSession upgrades an incoming HTTP request to a WebSocket + Yamux session.
// If asClient is true, the Relay Server acts as yamux.Client (so it can open streams toward an Agent).
func AcceptSession(sessionCtx context.Context, w http.ResponseWriter, r *http.Request, asClient bool) (*yamux.Session, error) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("websocket accept: %w", err)
	}
	wsConn.SetReadLimit(wsReadLimitBytes)

	netConn := websocket.NetConn(sessionCtx, wsConn, websocket.MessageBinary)
	if asClient {
		return yamux.Client(netConn, NewYamuxConfig())
	}
	return yamux.Server(netConn, NewYamuxConfig())
}

// ByteCounter tracks bidirectional traffic across a proxied stream.
type ByteCounter struct {
	Sent     atomic.Int64
	Received atomic.Int64
}

// PipeBidirectional copies bytes between a and b until either side closes or errors,
// updating optional atomic counters.
func PipeBidirectional(a, b io.ReadWriteCloser, txCounter, rxCounter *atomic.Int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	copySide := func(dst io.WriteCloser, src io.Reader, counter *atomic.Int64) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				if counter != nil {
					counter.Add(int64(n))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		// Trigger clean shutdown of peer direction.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copySide(a, b, rxCounter)
	go copySide(b, a, txCounter)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
