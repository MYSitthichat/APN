package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"relayvpn/internal/agent"
	"relayvpn/internal/client"
	"relayvpn/internal/config"
	"relayvpn/internal/protocol"
	"relayvpn/internal/security"
	"relayvpn/internal/server"
	"relayvpn/internal/webui"
)

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func TestEndToEndTunnelAndSecurity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	allowedEchoAddr := startEchoServer(t)
	blockedEchoAddr := startEchoServer(t)

	caCert, srvCert, srvKey, err := security.GenerateDevPKI(t.TempDir(), []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("generate dev PKI: %v", err)
	}

	agentToken, err := security.GenerateToken(32)
	if err != nil {
		t.Fatalf("generate agent token: %v", err)
	}
	clientToken, err := security.GenerateToken(32)
	if err != nil {
		t.Fatalf("generate client token: %v", err)
	}

	// 1. Start Relay Server (TLS 1.3 / WSS)
	srvCfg := &config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		CertFile:   srvCert,
		KeyFile:    srvKey,
		Agents: []config.AgentAuth{
			{ID: "home-pc", Name: "Home PC", TokenHash: security.HashToken(agentToken)},
		},
		Clients: []config.ClientAuth{
			{ID: "laptop-1", Name: "My Laptop", TokenHash: security.HashToken(clientToken), AllowedAgents: []string{"home-pc"}},
		},
	}
	srv, err := server.New(srvCfg, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	srv.SetPortalHandler(webui.NewPortalHandler(srv, logger))
	boundAddr, err := srv.StartAsync(ctx)
	if err != nil {
		t.Fatalf("server.StartAsync: %v", err)
	}
	serverURL := fmt.Sprintf("wss://%s/ws/tunnel", boundAddr)

	// 2. Start Agent with strict allowlist (ONLY allowedEchoAddr) + remote screen/shell enabled
	agCfg := &config.AgentConfig{
		AgentID:     "home-pc",
		Name:        "Home PC",
		ServerURL:   serverURL,
		Token:       agentToken,
		CAFile:      caCert,
		ServerName:  "127.0.0.1",
		AllowScreen: true,
		AllowInput:  true,
		AllowShell:  true,
		AllowedTargets: []config.AllowedTarget{
			{Name: "Echo Service", Address: allowedEchoAddr},
		},
	}
	ag, err := agent.New(agCfg, logger)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	go func() { _ = ag.Run(ctx) }()

	waitUntil(t, 5*time.Second, "agent connected", func() bool {
		return ag.Snapshot().State == "connected"
	})

	// 3. Start Client
	clCfg := &config.ClientConfig{
		ClientID:   "laptop-1",
		ServerURL:  serverURL,
		Token:      clientToken,
		CAFile:     caCert,
		ServerName: "127.0.0.1",
	}
	cl, err := client.New(clCfg, logger)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	go func() { _ = cl.Run(ctx) }()
	go func() {
		_ = webui.Start(ctx, webui.Options{Addr: "127.0.0.1:0", Mode: "client", Client: cl, Logger: logger})
	}()
	go func() {
		_ = webui.Start(ctx, webui.Options{Addr: "127.0.0.1:0", Mode: "agent", Agent: ag, Logger: logger})
	}()
	go func() {
		_ = webui.Start(ctx, webui.Options{Addr: "127.0.0.1:0", Mode: "server", Server: srv, Logger: logger})
	}()

	waitUntil(t, 5*time.Second, "client connected and discovered agent", func() bool {
		snap := cl.Snapshot()
		return snap.State == "connected" && len(snap.Agents) == 1 && len(snap.Agents[0].Targets) == 1
	})

	// 4. Open tunnel to ALLOWED target and send 5 concurrent multiplexed streams
	tun, err := cl.AddTunnel(config.TunnelRule{
		Name:       "Allowed Echo",
		LocalAddr:  "127.0.0.1:0",
		AgentID:    "home-pc",
		TargetAddr: allowedEchoAddr,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddTunnel allowed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", tun.LocalAddr, 3*time.Second)
			if err != nil {
				t.Errorf("stream %d dial: %v", idx, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

			payload := bytes.Repeat([]byte(fmt.Sprintf("stream-%d-hello-relayvpn-443|", idx)), 128)
			if _, err := conn.Write(payload); err != nil {
				t.Errorf("stream %d write: %v", idx, err)
				return
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Errorf("stream %d read: %v", idx, err)
				return
			}
			if !bytes.Equal(payload, reply) {
				t.Errorf("stream %d payload mismatch", idx)
			}
		}(i)
	}
	wg.Wait()

	// 5. Security Test: Disallowed target MUST be rejected by Agent allowlist
	blockedTun, err := cl.AddTunnel(config.TunnelRule{
		Name:       "Blocked Service",
		LocalAddr:  "127.0.0.1:0",
		AgentID:    "home-pc",
		TargetAddr: blockedEchoAddr,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddTunnel blocked: %v", err)
	}
	conn, err := net.DialTimeout("tcp", blockedTun.LocalAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial local blocked tunnel: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("should-fail"))
	buf := make([]byte, 32)
	n, readErr := conn.Read(buf)
	_ = conn.Close()
	if n > 0 || readErr == nil {
		t.Fatalf("expected disallowed target to be closed/rejected, got %d bytes, err=%v", n, readErr)
	}

	// 6. Security Test: Owner Pause toggle blocks new connections
	ag.SetPaused(true)
	pausedConn, err := net.DialTimeout("tcp", tun.LocalAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial local while paused: %v", err)
	}
	_ = pausedConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = pausedConn.Write([]byte("paused"))
	n, readErr = pausedConn.Read(buf)
	_ = pausedConn.Close()
	if n > 0 || readErr == nil {
		t.Fatalf("expected paused agent to reject connection, got %d bytes, err=%v", n, readErr)
	}

	// Resume and verify traffic flows again
	ag.SetPaused(false)
	resumedConn, err := net.DialTimeout("tcp", tun.LocalAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial after resume: %v", err)
	}
	defer resumedConn.Close()
	_ = resumedConn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("resumed-ok")
	if _, err := resumedConn.Write(msg); err != nil {
		t.Fatalf("write after resume: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(resumedConn, got); err != nil {
		t.Fatalf("read after resume: %v", err)
	}
	if !bytes.Equal(msg, got) {
		t.Fatalf("resumed echo mismatch: got %q", got)
	}

	// 7. Security Test: Invalid bearer token MUST be rejected at WebSocket handshake
	tlsCfg, err := security.ClientTLSConfig(caCert, "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	badSession, err := protocol.DialSession(ctx, protocol.DialOptions{
		ServerURL: serverURL,
		Token:     "wrong-token",
		Role:      protocol.RoleClient,
		PeerID:    "laptop-1",
		TLSConfig: tlsCfg,
	})
	if err == nil {
		_ = badSession.Close()
		t.Fatalf("expected invalid token to be rejected")
	}

	// 8. Remote Shell E2E Test over TLS 1.3 + WSS + Yamux
	shellStream, _, err := cl.OpenShellStream("home-pc")
	if err != nil {
		t.Fatalf("OpenShellStream: %v", err)
	}
	_ = shellStream.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := shellStream.Write([]byte("echo RELAYVPN_SHELL_OK\nexit\n")); err != nil {
		_ = shellStream.Close()
		t.Fatalf("write shell command: %v", err)
	}
	shellOut, _ := io.ReadAll(shellStream)
	_ = shellStream.Close()
	if !strings.Contains(string(shellOut), "RELAYVPN_SHELL_OK") {
		t.Fatalf("expected shell output to contain RELAYVPN_SHELL_OK, got: %q", string(shellOut))
	}

	// 9. Remote Screen E2E Test over TLS 1.3 + WSS + Yamux (Dirty-Tile Batch!)
	screenStream, screenResp, err := cl.OpenScreenStreamRequest(protocol.StreamOpenRequest{
		AgentID: "home-pc",
		FPS:     15,
		Quality: 82,
		Codec:   "tiles",
	})
	if err != nil {
		t.Fatalf("OpenScreenStream: %v", err)
	}
	defer screenStream.Close()
	if !screenResp.AllowInput {
		t.Fatalf("expected AllowInput=true")
	}
	_ = screenStream.SetDeadline(time.Now().Add(8 * time.Second))
	verifyFirstVideoFrame(t, screenStream)
}

func verifyFirstVideoFrame(t *testing.T, r io.Reader) {
	t.Helper()
	for i := 0; i < 4; i++ {
		fType, payload, err := protocol.ReadTypedFrame(r)
		if err != nil {
			t.Fatalf("read screen frame: %v", err)
		}
		if fType == protocol.FrameTypeInfo {
			continue
		}
		if fType == protocol.FrameTypeTileBatch {
			if len(payload) < 23 {
				t.Fatalf("tile batch too short: %d", len(payload))
			}
			w := binary.BigEndian.Uint16(payload[4:6])
			h := binary.BigEndian.Uint16(payload[6:8])
			count := binary.BigEndian.Uint16(payload[8:10])
			if w == 0 || h == 0 || count == 0 {
				t.Fatalf("invalid tile batch header: %dx%d count=%d", w, h, count)
			}
			tileDataOff := 10 + 13
			if len(payload) < tileDataOff+2 || payload[tileDataOff] != 0xFF || payload[tileDataOff+1] != 0xD8 {
				t.Fatalf("expected valid JPEG tile inside TileBatch")
			}
			return
		}
		if fType == protocol.FrameTypeError {
			return
		}
		t.Fatalf("unexpected screen frame type: %d", fType)
	}
	t.Fatalf("did not receive a video frame")
}
