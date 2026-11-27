package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/config"
	"relayvpn/internal/p2p"
	"relayvpn/internal/protocol"
	"relayvpn/internal/security"
	"relayvpn/internal/server"
	"relayvpn/internal/vpn"
	"relayvpn/internal/webui"
)

func TestP2PBidirectionalQUICAndWebSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	echoA := startEchoServer(t)
	echoB := startEchoServer(t)
	blockedB := startEchoServer(t)

	dirA := t.TempDir()
	dirB := t.TempDir()
	dirC := t.TempDir()

	cfgA := &config.PeerConfig{
		PeerID:        "peer-a",
		Name:          "Laptop A",
		PairSecret:    "secret-a-1234567890",
		QUICAddr:      "127.0.0.1:0",
		WSAddr:        "127.0.0.1:0",
		CertFile:      filepath.Join(dirA, "peer.crt"),
		KeyFile:       filepath.Join(dirA, "peer.key"),
		EnableLANDisc: false,
		AllowScreen:   true,
		AllowInput:    true,
		AllowShell:    true,
		// A dials B below and the test then drives A from B over the same connection.
		AllowReverseAccess: true,
		AllowedTargets: []config.AllowedTarget{
			{Name: "Echo A", Address: echoA},
		},
	}
	cfgB := &config.PeerConfig{
		PeerID:        "peer-b",
		Name:          "Home PC B",
		PairSecret:    "secret-b-1234567890",
		QUICAddr:      "127.0.0.1:0",
		WSAddr:        "127.0.0.1:0",
		CertFile:      filepath.Join(dirB, "peer.crt"),
		KeyFile:       filepath.Join(dirB, "peer.key"),
		EnableLANDisc: false,
		AllowScreen:   true,
		AllowInput:    true,
		AllowShell:    true,
		AllowedTargets: []config.AllowedTarget{
			{Name: "Echo B", Address: echoB},
		},
	}

	nodeA, err := p2p.NewNode(cfgA, logger)
	if err != nil {
		t.Fatalf("NewNode A: %v", err)
	}
	nodeB, err := p2p.NewNode(cfgB, logger)
	if err != nil {
		t.Fatalf("NewNode B: %v", err)
	}

	if err := nodeA.StartAsync(ctx); err != nil {
		t.Fatalf("StartAsync A: %v", err)
	}
	if err := nodeB.StartAsync(ctx); err != nil {
		t.Fatalf("StartAsync B: %v", err)
	}

	// Verify Peer WebUI mounts cleanly without route conflicts
	go func() {
		_ = webui.Start(ctx, webui.Options{Addr: "127.0.0.1:0", Mode: "peer", Peer: nodeA, Logger: logger})
	}()

	// 1. Peer A connects to Peer B via direct QUIC TLS 1.3 (Cert Fingerprint Pinned!)
	snapB := nodeB.Snapshot()
	if _, err := nodeA.ConnectDirect(ctx, snapB.QUICListenAddr, cfgB.PairSecret, snapB.Fingerprint); err != nil {
		t.Fatalf("Peer A -> Peer B QUIC connect failed: %v", err)
	}

	// Verify BOTH sides now see each other as connected peers!
	waitUntil(t, 4*time.Second, "both peers registered each other", func() bool {
		return len(nodeA.Snapshot().ConnectedPeers) == 1 && len(nodeB.Snapshot().ConnectedPeers) == 1
	})

	// 2. Test A -> B: TCP Tunnel over QUIC
	tunAB, err := nodeA.AddTunnel("A->B Echo", "127.0.0.1:0", "peer-b", echoB, true)
	if err != nil {
		t.Fatalf("AddTunnel A->B: %v", err)
	}
	verifyTCPEcho(t, tunAB.LocalAddr, "hello-from-A-to-B-over-QUIC")

	// 3. Test B -> A (REVERSE DIRECTION on the EXACT SAME single QUIC connection!)
	tunBA, err := nodeB.AddTunnel("B->A Echo", "127.0.0.1:0", "peer-a", echoA, true)
	if err != nil {
		t.Fatalf("AddTunnel B->A: %v", err)
	}
	verifyTCPEcho(t, tunBA.LocalAddr, "hello-from-B-back-to-A-symmetric")

	// 4. Test Bidirectional Remote Shell (A -> B and B -> A)
	verifyPeerShell(t, ctx, nodeA, "peer-b", "P2P_B_SHELL_OK")
	verifyPeerShell(t, ctx, nodeB, "peer-a", "P2P_A_SHELL_OK")

	// 5. Test Remote Screen stream A -> B over QUIC (Dirty-Tile Batch!)
	scStream, scResp, err := nodeA.OpenPeerStream(ctx, "peer-b", protocol.StreamOpenRequest{
		Mode:    protocol.ModeScreen,
		FPS:     15,
		Quality: 82,
		Codec:   "tiles",
	})
	if err != nil {
		t.Fatalf("OpenPeerStream screen A->B: %v", err)
	}
	if !scResp.AllowInput {
		t.Fatalf("expected AllowInput=true on Peer B")
	}
	verifyFirstVideoFrame(t, scStream)
	_ = scStream.Close()

	// 6. Security: Disallowed target on Peer B MUST be rejected
	if _, _, err := nodeA.OpenPeerStream(ctx, "peer-b", protocol.StreamOpenRequest{
		Mode:       protocol.ModeTCP,
		TargetAddr: blockedB,
	}); err == nil {
		t.Fatalf("expected disallowed target on Peer B to be rejected")
	}

	// 7. Security: Wrong PairSecret MUST be rejected
	cfgC := &config.PeerConfig{
		PeerID:             "peer-c",
		Name:               "Node C",
		PairSecret:         "secret-c-1234567890",
		QUICAddr:           "127.0.0.1:0",
		WSAddr:             "127.0.0.1:0",
		CertFile:           filepath.Join(dirC, "peer.crt"),
		KeyFile:            filepath.Join(dirC, "peer.key"),
		EnableLANDisc:      false,
		AllowShell:         true,
		AllowReverseAccess: true, // B opens a shell back on C (which dialled B)
	}
	nodeC, err := p2p.NewNode(cfgC, logger)
	if err != nil {
		t.Fatalf("NewNode C: %v", err)
	}
	if err := nodeC.StartAsync(ctx); err != nil {
		t.Fatalf("StartAsync C: %v", err)
	}

	if _, err := nodeC.ConnectDirect(ctx, snapB.QUICListenAddr, "wrong-secret", snapB.Fingerprint); err == nil {
		t.Fatalf("expected wrong pair secret to be rejected")
	}

	// 8. Test WebSocket Peer Transport (Cloudflare Tunnel / WSS fallback path) + Bidirectional Shell!
	wsURL := "ws://" + snapB.WSListenAddr + "/ws/peer"
	if _, err := nodeC.ConnectDirect(ctx, wsURL, cfgB.PairSecret, ""); err != nil {
		t.Fatalf("Peer C -> Peer B WS connect failed: %v", err)
	}
	waitUntil(t, 4*time.Second, "peer C and B connected via WS", func() bool {
		return len(nodeC.Snapshot().ConnectedPeers) == 1 && len(nodeB.Snapshot().ConnectedPeers) == 2
	})
	verifyPeerShell(t, ctx, nodeC, "peer-b", "P2P_WS_C_TO_B_OK")
	verifyPeerShell(t, ctx, nodeB, "peer-c", "P2P_WS_B_TO_C_OK")

	// 9. Test Built-in L3 VPN Packet Routing (ModeTUN) over P2P QUIC!
	gotPktCh := make(chan []byte, 1)
	nodeB.SetPacketSink(func(pkt []byte) {
		select {
		case gotPktCh <- pkt:
		default:
		}
	})
	vpnIPB := net.ParseIP(nodeB.Snapshot().VPN.VPNIP).To4()
	vpnIPA := net.ParseIP(nodeA.Snapshot().VPN.VPNIP).To4()
	if vpnIPA == nil || vpnIPB == nil || vpnIPA.Equal(vpnIPB) {
		t.Fatalf("invalid derived VPN IPs: A=%v B=%v", vpnIPA, vpnIPB)
	}
	// Construct a valid 28-byte minimal IPv4 packet addressed from A -> B
	rawPkt := make([]byte, 28)
	rawPkt[0] = 0x45 // IPv4, IHL=5
	rawPkt[3] = 28
	copy(rawPkt[12:16], vpnIPA)
	copy(rawPkt[16:20], vpnIPB)
	copy(rawPkt[20:28], []byte("VPN-PING"))
	if dst, ok := vpn.ExtractIPv4Dst(rawPkt); !ok || dst != vpnIPB.String() {
		t.Fatalf("ExtractIPv4Dst failed: %q %v", dst, ok)
	}
	if err := nodeA.InjectOutboundPacket(rawPkt); err != nil {
		t.Fatalf("InjectOutboundPacket A->B: %v", err)
	}
	select {
	case recv := <-gotPktCh:
		if !bytes.Equal(recv, rawPkt) {
			t.Fatalf("L3 VPN packet mismatch: got %x want %x", recv, rawPkt)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for L3 VPN packet on Peer B")
	}
}

func verifyTCPEcho(t *testing.T, addr, text string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	msg := []byte(text)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write %s: %v", addr, err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read %s: %v", addr, err)
	}
	if !bytes.Equal(msg, reply) {
		t.Fatalf("echo mismatch: got %q want %q", reply, msg)
	}
}

func verifyPeerShell(t *testing.T, ctx context.Context, from *p2p.Node, targetPeerID, marker string) {
	t.Helper()
	st, _, err := from.OpenPeerStream(ctx, targetPeerID, protocol.StreamOpenRequest{
		Mode: protocol.ModeShell,
	})
	if err != nil {
		t.Fatalf("OpenPeerStream shell -> %s: %v", targetPeerID, err)
	}
	if _, err := st.Write([]byte("echo " + marker + "\nexit\n")); err != nil {
		_ = st.Close()
		t.Fatalf("write shell -> %s: %v", targetPeerID, err)
	}
	out, _ := io.ReadAll(st)
	_ = st.Close()
	if !strings.Contains(string(out), marker) {
		t.Fatalf("shell output missing %q, got %q", marker, string(out))
	}
}

func TestEasyPINPermanentPasswordAndApproval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 1. Start a Relay Server acting as Rendezvous Directory over TLS 1.3
	caCert, srvCert, srvKey, err := security.GenerateDevPKI(t.TempDir(), []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("GenerateDevPKI: %v", err)
	}
	srv, err := server.New(&config.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		CertFile:   srvCert,
		KeyFile:    srvKey,
	}, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	rdvAddr, err := srv.StartAsync(ctx)
	if err != nil {
		t.Fatalf("server.StartAsync: %v", err)
	}
	rdvURL := "https://" + rdvAddr

	tlsCfg, err := security.ClientTLSConfig(caCert, "127.0.0.1")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	rdvHTTP := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// 2. Start Peer Host & Peer Caller with 9-digit Device IDs + Rendezvous
	dirHost := t.TempDir()
	dirCaller := t.TempDir()
	hostCfg := &config.PeerConfig{
		DeviceID:      "482917305",
		PeerID:        "host-desk",
		Name:          "Host Desk",
		QUICAddr:      "127.0.0.1:0",
		WSAddr:        "127.0.0.1:0",
		RendezvousURL: rdvURL,
		CertFile:      filepath.Join(dirHost, "peer.crt"),
		KeyFile:       filepath.Join(dirHost, "peer.key"),
		AllowShell:    true,
	}
	callerCfg := &config.PeerConfig{
		DeviceID:      "901234567",
		PeerID:        "caller-desk",
		Name:          "Caller Desk",
		QUICAddr:      "127.0.0.1:0",
		WSAddr:        "127.0.0.1:0",
		RendezvousURL: rdvURL,
		CertFile:      filepath.Join(dirCaller, "peer.crt"),
		KeyFile:       filepath.Join(dirCaller, "peer.key"),
		AllowShell:    true,
	}

	hostNode, err := p2p.NewNode(hostCfg, logger)
	if err != nil {
		t.Fatalf("NewNode host: %v", err)
	}
	hostNode.SetConfigPath(filepath.Join(dirHost, "peer.json"))
	hostNode.SetRendezvousHTTPClient(rdvHTTP)
	// Cleanups run last-in-first-out, so this runs before t.TempDir removes dirHost. Stopping the
	// nodes is not enough: background goroutines (rendezvous sync, peer disconnect bookkeeping)
	// can still save peer.json while RemoveAll runs, which failed CI with "directory not empty".
	// SetConfigPath takes the node lock that every save holds, so clearing the path waits for an
	// in-flight save and turns later saves into no-ops.
	t.Cleanup(func() {
		cancel()
		hostNode.SetConfigPath("")
	})

	callerNode, err := p2p.NewNode(callerCfg, logger)
	if err != nil {
		t.Fatalf("NewNode caller: %v", err)
	}
	callerNode.SetRendezvousHTTPClient(rdvHTTP)

	if err := hostNode.StartAsync(ctx); err != nil {
		t.Fatalf("StartAsync host: %v", err)
	}
	if err := callerNode.StartAsync(ctx); err != nil {
		t.Fatalf("StartAsync caller: %v", err)
	}

	waitUntil(t, 5*time.Second, "host registered in rendezvous", func() bool {
		return hostNode.Snapshot().RendezvousStatus == "online"
	})

	// 3. Connect using formatted 9-digit ID ("482 917 305") + 6-digit Temporary PIN!
	tempPIN := hostNode.Snapshot().TempPIN
	if len(tempPIN) != 6 {
		t.Fatalf("expected 6-digit temp PIN, got %q", tempPIN)
	}
	if _, err := callerNode.ConnectSmart(ctx, "482 917 305", tempPIN); err != nil {
		t.Fatalf("ConnectSmart with 9-digit ID + Temp PIN failed: %v", err)
	}
	verifyPeerShell(t, ctx, callerNode, "host-desk", "PIN_AUTH_OK")
	_ = callerNode.DisconnectPeer("host-desk")

	// 4. Set Permanent Password + Rotate Temp PIN -> connect using Permanent Password!
	if err := hostNode.SetPermanentPassword("MySecret#2026"); err != nil {
		t.Fatalf("SetPermanentPassword: %v", err)
	}
	if _, err := hostNode.RotateTempPIN(); err != nil {
		t.Fatalf("RotateTempPIN: %v", err)
	}
	if !hostNode.Snapshot().HasPermanentPassword {
		t.Fatalf("expected HasPermanentPassword=true")
	}
	// Old temp PIN should fail now
	if _, err := callerNode.ConnectSmart(ctx, "482-917-305", tempPIN); err == nil {
		t.Fatalf("expected old rotated PIN to be rejected")
	}
	// Permanent password should succeed
	if _, err := callerNode.ConnectSmart(ctx, "482 917 305", "MySecret#2026"); err != nil {
		t.Fatalf("ConnectSmart with Permanent Password failed: %v", err)
	}
	_ = callerNode.DisconnectPeer("host-desk")

	// 5. Interactive Approval Mode (Accept/Reject like AnyDesk) with empty password!
	hostNode.SetRequireApproval(true)
	hookCh := make(chan p2p.PendingApproval, 1)
	hostNode.SetOnApprovalRequest(func(a p2p.PendingApproval) { hookCh <- a })
	errCh := make(chan error, 1)
	go func() {
		_, err := callerNode.ConnectSmart(ctx, "482 917 305", "")
		errCh <- err
	}()

	waitUntil(t, 5*time.Second, "pending approval request appears on host", func() bool {
		return len(hostNode.Snapshot().PendingApprovals) == 1
	})
	reqID := hostNode.Snapshot().PendingApprovals[0].ID
	select {
	case a := <-hookCh:
		if a.ID != reqID || a.DeviceID != "901234567" || a.ExpiresAt.Sub(a.RequestedAt) != p2p.ApprovalTimeout {
			t.Fatalf("approval hook got %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("approval hook was not called")
	}
	if list := hostNode.PendingApprovals(); len(list) != 1 || list[0].ID != reqID {
		t.Fatalf("PendingApprovals = %+v", list)
	}
	if err := hostNode.ResolveApproval(reqID, true); err != nil {
		t.Fatalf("ResolveApproval: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("approval-based connect failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for approved connect")
	}
	verifyPeerShell(t, ctx, callerNode, "host-desk", fmt.Sprintf("APPROVED_%s", reqID))
}

// TestReverseAccessDeniedByDefault: a device you connect to must not get screen, shell, files,
// clipboard or tunnels on YOUR machine (it never proved it knows your password).
func TestReverseAccessDeniedByDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mk := func(id string) (*p2p.Node, *config.PeerConfig) {
		dir := t.TempDir()
		cfg := &config.PeerConfig{
			PeerID: id, Name: id, PairSecret: "secret-" + id + "-1234567890",
			QUICAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0",
			CertFile: filepath.Join(dir, "peer.crt"), KeyFile: filepath.Join(dir, "peer.key"),
			AllowScreen: true, AllowInput: true, AllowShell: true,
		}
		n, err := p2p.NewNode(cfg, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.StartAsync(ctx); err != nil {
			t.Fatal(err)
		}
		return n, cfg
	}
	caller, _ := mk("victim")
	host, hostCfg := mk("stranger")
	snap := host.Snapshot()
	if _, err := caller.ConnectDirect(ctx, snap.QUICListenAddr, hostCfg.PairSecret, snap.Fingerprint); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitUntil(t, 4*time.Second, "host sees caller", func() bool { return len(host.Snapshot().ConnectedPeers) == 1 })

	// The caller can still use the host normally.
	verifyPeerShell(t, ctx, caller, "stranger", "FORWARD_OK")

	// The host gets nothing on the caller.
	for _, mode := range []string{protocol.ModeShell, protocol.ModeFiles, protocol.ModeScreen, protocol.ModeClipboard, protocol.ModeTCP} {
		st, _, err := host.OpenPeerStream(ctx, "victim", protocol.StreamOpenRequest{Mode: mode, TargetAddr: "127.0.0.1:1"})
		if err == nil {
			_ = st.Close()
			t.Fatalf("mode %s: host opened a stream on the machine that connected to it", mode)
		}
		if !strings.Contains(err.Error(), "does not accept remote access back") {
			t.Fatalf("mode %s: unexpected error %v", mode, err)
		}
	}

	// Nor over the VPN: the host may only answer what the caller started.
	got := make(chan []byte, 8)
	caller.SetPacketSink(func(pkt []byte) { got <- pkt })
	callerIP := net.ParseIP(caller.Snapshot().VPN.VPNIP).To4()
	hostIP := net.ParseIP(host.Snapshot().VPN.VPNIP).To4()
	tcp := func(src, dst net.IP, sport, dport uint16) []byte {
		pkt := make([]byte, 40)
		pkt[0], pkt[3], pkt[8], pkt[9] = 0x45, 40, 64, 6
		copy(pkt[12:16], src)
		copy(pkt[16:20], dst)
		pkt[20], pkt[21] = byte(sport>>8), byte(sport)
		pkt[22], pkt[23] = byte(dport>>8), byte(dport)
		return pkt
	}
	expectNone := func(what string) {
		select {
		case <-got:
			t.Fatalf("%s reached the caller's VPN interface", what)
		case <-time.After(400 * time.Millisecond):
		}
	}
	// The host opens RDP to the caller on its own: dropped.
	if err := host.InjectOutboundPacket(tcp(hostIP, callerIP, 50000, 3389)); err != nil {
		t.Fatalf("host send: %v", err)
	}
	expectNone("a connection opened by the host")
	// The host pretends to be another VPN machine: dropped.
	if err := host.InjectOutboundPacket(tcp(net.IPv4(10, 99, 1, 1).To4(), callerIP, 3389, 51515)); err == nil {
		expectNone("a packet with a forged source address")
	}
	// The caller opens RDP to the host; the host's reply comes back.
	if err := caller.InjectOutboundPacket(tcp(callerIP, hostIP, 51515, 3389)); err != nil {
		t.Fatalf("caller send: %v", err)
	}
	reply := tcp(hostIP, callerIP, 3389, 51515)
	if err := host.InjectOutboundPacket(reply); err != nil {
		t.Fatalf("host reply: %v", err)
	}
	select {
	case pkt := <-got:
		if string(pkt) != string(reply) {
			t.Fatalf("unexpected packet at the caller: %x", pkt)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the reply to the caller's own connection did not arrive")
	}
}

// TestWrongPINsRotateTempPINAndLockOut: guessing the 6-digit PIN is cut off quickly.
func TestWrongPINsRotateTempPINAndLockOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mk := func(id string) *p2p.Node {
		dir := t.TempDir()
		n, err := p2p.NewNode(&config.PeerConfig{
			PeerID: id, Name: id, QUICAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0",
			CertFile: filepath.Join(dir, "peer.crt"), KeyFile: filepath.Join(dir, "peer.key"),
		}, logger)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.StartAsync(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}
	host := mk("host")
	attacker := mk("attacker")
	snap := host.Snapshot()
	pin := snap.TempPIN
	for i := 0; i < 5; i++ {
		if _, err := attacker.ConnectDirect(ctx, snap.QUICListenAddr, "000000", snap.Fingerprint); err == nil {
			t.Fatal("wrong PIN accepted")
		}
	}
	// The source is now locked out, even with the correct PIN.
	_, err := attacker.ConnectDirect(ctx, snap.QUICListenAddr, pin, snap.Fingerprint)
	if err == nil || !strings.Contains(err.Error(), "15") {
		t.Fatalf("correct PIN after 5 failures from the same address: err=%v, want lockout", err)
	}
}
