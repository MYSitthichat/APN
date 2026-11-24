//go:build linux && x11integration

// End-to-end clipboard auto-sync test over real P2P nodes, the viewer's web API and an X server.
// Needs Xvfb and xclip:  DISPLAY=:99 go test -tags x11integration -run ClipboardAutoSync ./tests/
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"relayvpn/internal/config"
	"relayvpn/internal/p2p"
	"relayvpn/internal/protocol"
	"relayvpn/internal/webui"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestClipboardAutoSyncEndToEnd(t *testing.T) {
	if os.Getenv("DISPLAY") == "" {
		t.Skip("DISPLAY not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mk := func(id, name string) (*p2p.Node, *config.PeerConfig) {
		dir := t.TempDir()
		cfg := &config.PeerConfig{
			PeerID: id, Name: name, PairSecret: "secret-" + id + "-123456",
			QUICAddr: "127.0.0.1:0", WSAddr: "127.0.0.1:0",
			CertFile: filepath.Join(dir, "peer.crt"), KeyFile: filepath.Join(dir, "peer.key"),
			AllowScreen: true, AllowInput: true,
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
	viewer, _ := mk("viewer", "Viewer")
	host, hostCfg := mk("host", "Host")
	snap := host.Snapshot()
	if _, err := viewer.ConnectDirect(ctx, snap.QUICListenAddr, hostCfg.PairSecret, snap.Fingerprint); err != nil {
		t.Fatalf("connect: %v", err)
	}

	uiAddr := freeAddr(t)
	go func() { _ = webui.Start(ctx, webui.Options{Addr: uiAddr, Mode: "peer", Peer: viewer, Logger: logger}) }()
	sync := func() map[string]any {
		t.Helper()
		var out map[string]any
		for i := 0; i < 50; i++ {
			resp, err := http.Post("http://"+uiAddr+"/api/peer/clipboard/sync", "application/json",
				bytes.NewBufferString(`{"peer_id":"host"}`))
			if err != nil {
				time.Sleep(100 * time.Millisecond) // web UI still starting
				continue
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("sync status %d: %v", resp.StatusCode, out)
			}
			return out
		}
		t.Fatal("web UI did not start")
		return nil
	}
	copyText := func(s string) {
		t.Helper()
		cmd := exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = bytes.NewBufferString(s)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Viewer -> host: a fresh copy is pushed once, then not again until it changes.
	copyText("copied on the viewer")
	if out := sync(); out["pushed"] != true {
		t.Fatalf("first sync should push: %v", out)
	}
	if out := sync(); out["pushed"] != false {
		t.Fatalf("unchanged clipboard must not be pushed again: %v", out)
	}
	copyText("a newer copy")
	if out := sync(); out["pushed"] != true {
		t.Fatalf("changed clipboard should push: %v", out)
	}

	// Host -> viewer: the screen stream announces a copy made by another app on the host.
	st, _, err := viewer.OpenPeerStream(ctx, "host", protocol.StreamOpenRequest{Mode: protocol.ModeScreen, FPS: 5, Quality: 60, Codec: "tiles"})
	if err != nil {
		t.Fatalf("open screen: %v", err)
	}
	defer st.Close()
	got := make(chan bool, 1)
	go func() {
		for {
			fType, _, err := protocol.ReadTypedFrame(st)
			if err != nil {
				got <- false
				return
			}
			if fType == protocol.FrameTypeClipboardChanged {
				got <- true
				return
			}
		}
	}()
	time.Sleep(700 * time.Millisecond) // host watcher subscribes
	copyText("copied on the host with right-click")
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("screen stream closed before clipboard_changed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no clipboard_changed frame after a host-side copy")
	}
}
