package p2p

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"relayvpn/internal/config"
)

func TestIsDirectTarget(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.1.50", true},
		{"10.4.88.86", true},
		{"10.99.31.213", true},
		{"192.168.1.50:4433", true},
		{"::1", true},
		{"[::1]:4433", true},
		{"pc01.local", true},
		{"wss://example.trycloudflare.com/ws/peer", true},
		{"933127377", false},
		{"933 127 377", false},
		{"476-542-320", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isDirectTarget(tc.in); got != tc.want {
			t.Errorf("isDirectTarget(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeDirectTarget(t *testing.T) {
	q, ws := normalizeDirectTarget("192.168.1.50")
	if q != "192.168.1.50:4433" || ws != "ws://192.168.1.50:8444/ws/peer" {
		t.Fatalf("bare IPv4 got (%q, %q)", q, ws)
	}

	q, ws = normalizeDirectTarget("192.168.1.50:5555")
	if q != "192.168.1.50:5555" || ws != "" {
		t.Fatalf("explicit port got (%q, %q)", q, ws)
	}

	q, ws = normalizeDirectTarget("::1")
	if q != "[::1]:4433" || ws != "ws://[::1]:8444/ws/peer" {
		t.Fatalf("bare IPv6 got (%q, %q)", q, ws)
	}
}

func TestSavedPeerGroupAndRename(t *testing.T) {
	n := &Node{
		cfg: &config.PeerConfig{
			DeviceID: "111222333",
			KnownPeers: []config.KnownPeer{
				{DeviceID: "903008956", Name: "air-server"},
				{DeviceID: "476542320", Name: "CM WEB"},
			},
		},
	}

	if err := n.SetSavedPeerGroup("903 008 956", "  Server   หลัก "); err != nil {
		t.Fatalf("SetSavedPeerGroup: %v", err)
	}
	if err := n.SetSavedPeerGroup("476542320", "Server หลัก"); err != nil {
		t.Fatalf("SetSavedPeerGroup 2: %v", err)
	}
	if got := n.cfg.KnownPeers[0].Group; got != "Server หลัก" {
		t.Fatalf("normalized group = %q, want %q", got, "Server หลัก")
	}

	// Rename group
	cnt, err := n.RenameGroup("Server หลัก", "Production")
	if err != nil || cnt != 2 {
		t.Fatalf("RenameGroup = (%d, %v), want (2, nil)", cnt, err)
	}
	if n.cfg.KnownPeers[0].Group != "Production" || n.cfg.KnownPeers[1].Group != "Production" {
		t.Fatalf("unexpected groups after rename: %+v", n.cfg.KnownPeers)
	}

	// Dissolve group (newGroup == "") keeps devices intact!
	cnt, err = n.RenameGroup("Production", "")
	if err != nil || cnt != 2 {
		t.Fatalf("dissolve RenameGroup = (%d, %v), want (2, nil)", cnt, err)
	}
	if len(n.cfg.KnownPeers) != 2 || n.cfg.KnownPeers[0].Group != "" || n.cfg.KnownPeers[1].Group != "" {
		t.Fatalf("unexpected known peers after dissolve: %+v", n.cfg.KnownPeers)
	}
}

func TestProbeTargetDirectAndConnected(t *testing.T) {
	n := &Node{
		cfg: &config.PeerConfig{
			DeviceID: "111222333",
			KnownPeers: []config.KnownPeer{
				{
					DeviceID:      "903008956",
					Name:          "air-server",
					OS:            "linux/amd64",
					VPNIP:         "10.99.68.129",
					QUICAddr:      "192.168.1.50:4433",
					SavedPassword: "secret",
				},
			},
		},
		peers: map[string]*connectedPeer{
			"peer-online": {
				id:       "peer-online",
				deviceID: "476542320",
				name:     "CM WEB",
				osInfo:   "windows/amd64",
			},
		},
	}

	// Already connected ID
	res, err := n.ProbeTarget(context.Background(), "476 542 320")
	if err != nil {
		t.Fatalf("ProbeTarget connected: %v", err)
	}
	if !res.AlreadyConnected || !res.Reachable || res.Via != "connected" || res.Peer == nil {
		t.Fatalf("unexpected connected probe result: %+v", res)
	}

	// Direct IP matching KnownPeer enriches Name + HasSavedPassword
	res, err = n.ProbeTarget(context.Background(), "192.168.1.50")
	if err != nil {
		t.Fatalf("ProbeTarget direct: %v", err)
	}
	if res.Kind != "direct" || !res.Reachable || res.Name != "air-server" || !res.HasSavedPassword {
		t.Fatalf("unexpected direct probe result: %+v", res)
	}

	// Invalid ID
	if _, err := n.ProbeTarget(context.Background(), "12345"); err == nil {
		t.Fatal("expected error for invalid short ID")
	}
	// Self ID
	if _, err := n.ProbeTarget(context.Background(), "111222333"); err == nil {
		t.Fatal("expected error for self ID")
	}

	// Self VPN IP
	n.vpnIP = "10.99.10.20"
	if _, err := n.ProbeTarget(context.Background(), "10.99.10.20"); err == nil {
		t.Fatal("expected error for self VPN IP")
	}

	// URL targets (http/https/ws/wss) never fail host parsing
	for _, u := range []string{"http://192.168.1.50:8444", "wss://example.trycloudflare.com/ws/peer"} {
		res, err := n.ProbeTarget(context.Background(), u)
		if err != nil || !res.Reachable || res.Kind != "direct" {
			t.Fatalf("ProbeTarget(%q) = (%+v, %v)", u, res, err)
		}
	}
}

func TestProbeTargetRendezvousPresenceAndGroupPersistence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/rendezvous/presence" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			IDs []string `json:"ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		peers := map[string]any{}
		for _, id := range req.IDs {
			if id == "903008956" {
				peers[id] = map[string]any{"online": true, "name": "air-server", "os": "linux/amd64"}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "peers": peers})
	}))
	defer srv.Close()

	n := &Node{
		cfg: &config.PeerConfig{
			DeviceID: "111222333",
			KnownPeers: []config.KnownPeer{
				{DeviceID: "903008956", Name: "My Custom Server", CustomName: true, Group: "Production"},
			},
		},
		rendezvousURL: srv.URL,
		rdvClient:     srv.Client(),
		presence:      map[string]peerPresence{},
	}

	// Online peer keeps custom name & reports cloud reachable
	res, err := n.ProbeTarget(context.Background(), "903 008 956")
	if err != nil {
		t.Fatalf("ProbeTarget online: %v", err)
	}
	if !res.Reachable || res.Via != "cloud" || res.Name != "My Custom Server" || res.OS != "linux/amd64" {
		t.Fatalf("unexpected online probe result: %+v", res)
	}

	// Offline peer reports Reachable=false with user-friendly message
	resOff, err := n.ProbeTarget(context.Background(), "888777666")
	if err != nil {
		t.Fatalf("ProbeTarget offline: %v", err)
	}
	if resOff.Reachable || resOff.Message == "" {
		t.Fatalf("expected unreachable with message, got: %+v", resOff)
	}

	// Reconnecting via rememberPeerLocked preserves Group and CustomName
	n.rememberPeerLocked(&connectedPeer{
		deviceID: "903008956",
		name:     "remote-hostname",
		osInfo:   "linux/amd64",
	})
	if got := n.cfg.KnownPeers[0]; got.Group != "Production" || got.Name != "My Custom Server" || !got.CustomName {
		t.Fatalf("rememberPeerLocked lost Group or CustomName: %+v", got)
	}
}
