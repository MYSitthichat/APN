package p2p

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Stealth and transport hardening.
//
//   - The 443 fallback (WebSocket through a Cloudflare tunnel) carries a TLS 1.3 session between
//     the two machines inside it, with the host's certificate pinned like on QUIC. Cloudflare
//     terminates only the outer HTTPS, so it sees ciphertext; before, it could read the password
//     and the whole session. The protected endpoint is wsE2EPath; the old /ws/peer stays for
//     older versions and is marked as not end-to-end encrypted.
//   - The WebSocket listener binds to this machine only: cloudflared reaches it locally, and
//     nothing on the LAN or the internet can connect to it (it used to listen on every
//     interface, unencrypted, with a firewall rule open to all networks).
//   - QUIC listens on UDP 443 when it can and negotiates ALPN "h3", so to a network observer it
//     looks like ordinary HTTP/3 web traffic. Older peers are reached with the old ALPN.
//   - Hole-punch packets carry random bytes instead of the readable marker "RVPN-PUNCH".

const (
	alpnHTTP3 = "h3"
	wsE2EPath = "/ws/peer-e2e"

	// transport labels shown on the peer cards
	transportWSE2E    = "WSS/443 + TLS 1.3 E2E"
	transportWSLegacy = "WSS/443 ⚠ ไม่เข้ารหัสปลายทาง (ปลายทางเวอร์ชันเก่า)"
	transportWSPlain  = "WS/TCP ⚠ ไม่เข้ารหัส"

	wsTLSHandshakeTimeout = 15 * time.Second

	defaultQUICPort  = "4433"
	stealthQUICPort  = "443"
	defaultQUICAddr  = ":" + defaultQUICPort
	wsListenAnyEnv   = "APN_WS_LISTEN_ANY" // "1": old behaviour, WebSocket port on every interface
	punchPacketBytes = 16
)

// punchPacket is a hole-punch datagram: random bytes whose first byte is 0, which QUIC stacks
// discard as "not a QUIC packet" (the fixed bit is unset), and which reads as noise to an observer.
func punchPacket() []byte {
	b := make([]byte, punchPacketBytes)
	_, _ = rand.Read(b)
	b[0] = 0
	return b
}

// wsListenAddr turns the configured WebSocket address into one bound to this machine only.
// An explicit non-wildcard address is kept as configured.
func wsListenAddr(cfg string) string {
	if os.Getenv(wsListenAnyEnv) == "1" {
		return cfg
	}
	host, port, err := net.SplitHostPort(cfg)
	if err != nil {
		return cfg
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return cfg
}

// quicListenCandidates is the UDP addresses to try for QUIC, in order. The default port
// (":4433") first tries 443, where QUIC traffic looks like HTTP/3; when 443 is taken or needs
// privileges this process does not have, 4433 is used as before.
func quicListenCandidates(cfg string) []string {
	if cfg == "" {
		return []string{":0"}
	}
	if cfg == defaultQUICAddr {
		return []string{":" + stealthQUICPort, defaultQUICAddr}
	}
	return []string{cfg}
}

// e2eWSURL is the end-to-end protected endpoint for a peer WebSocket URL, or "" when the URL
// does not point at the standard /ws/peer path.
func e2eWSURL(wsURL string) string {
	u, err := url.Parse(wsURL)
	if err != nil || !strings.HasSuffix(u.Path, "/ws/peer") {
		return ""
	}
	u.Path = strings.TrimSuffix(u.Path, "/ws/peer") + wsE2EPath
	return u.String()
}

// isALPNMismatch reports a TLS handshake that failed because the peer does not speak the
// offered application protocol (an older APN that knows only the legacy ALPN).
func isALPNMismatch(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no application protocol") || strings.Contains(s, "0x178")
}

// clientTLSOverStream runs a pinned TLS 1.3 client handshake over an already-open stream.
func (id *PeerIdentity) clientTLSOverStream(ctx context.Context, c net.Conn, expectedFP string) (net.Conn, error) {
	cfg := id.ClientTLSConfig(expectedFP)
	cfg.NextProtos = []string{P2PALPN}
	tc := tls.Client(c, cfg)
	hctx, cancel := context.WithTimeout(ctx, wsTLSHandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	return tc, nil
}

// serverTLSOverStream runs this peer's TLS 1.3 server handshake over an already-open stream.
func (id *PeerIdentity) serverTLSOverStream(ctx context.Context, c net.Conn) (net.Conn, error) {
	tc := tls.Server(c, id.ServerTLSConfig())
	hctx, cancel := context.WithTimeout(ctx, wsTLSHandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	return tc, nil
}

var errNoE2EEndpoint = errors.New("peer has no end-to-end WebSocket endpoint")
