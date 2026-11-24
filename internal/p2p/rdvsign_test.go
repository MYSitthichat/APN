package p2p

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"relayvpn/internal/config"
	"relayvpn/internal/rendezvous"
)

// TestNodeRegistersSignedWithSelfHostedRendezvous checks the client and the self-hosted
// directory agree on the signing format: the node's register is accepted as signed, the
// device ID gets bound to the node's certificate, and a forged register is then refused.
func TestNodeRegistersSignedWithSelfHostedRendezvous(t *testing.T) {
	rdv := rendezvous.NewServer(rendezvous.Options{RatePerMin: -1, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ts := httptest.NewServer(rdv.Handler())
	defer ts.Close()

	dir := t.TempDir()
	node, err := NewNode(&config.PeerConfig{
		DeviceID:      "595514895",
		PeerID:        "linux-box",
		Name:          "Linux Box",
		QUICAddr:      "127.0.0.1:0",
		WSAddr:        "127.0.0.1:0",
		RendezvousURL: ts.URL,
		CertFile:      filepath.Join(dir, "peer.crt"),
		KeyFile:       filepath.Join(dir, "peer.key"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	node.SetRendezvousHTTPClient(ts.Client())
	node.mu.Lock()
	node.rendezvousURL = ts.URL
	node.mu.Unlock()

	node.registerWithRendezvous(context.Background())
	if st := node.Snapshot().RendezvousStatus; st != "online" {
		t.Fatalf("rendezvous status = %q, want online", st)
	}

	resp, err := http.Post(ts.URL+"/api/rendezvous/lookup/595514895", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var lk struct {
		Entry struct {
			Fingerprint string `json:"fingerprint"`
			Signed      bool   `json:"signed"`
		} `json:"entry"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&lk)
	resp.Body.Close()
	if !lk.Entry.Signed || lk.Entry.Fingerprint != node.identity.Fingerprint {
		t.Fatalf("entry signed=%v fp=%q, want signed with %q", lk.Entry.Signed, lk.Entry.Fingerprint, node.identity.Fingerprint)
	}

	forged, _ := json.Marshal(map[string]any{"device_id": "595514895", "fingerprint": "sha256:attacker", "ws_url": "wss://evil.example/ws"})
	resp, err = http.Post(ts.URL+"/api/rendezvous/register", "application/json", bytes.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged register status = %d, want 401", resp.StatusCode)
	}

	// The signed unregister on shutdown is accepted.
	node.unregisterFromRendezvous()
	if rdv.OnlineCount() != 0 {
		t.Fatalf("online after signed unregister = %d, want 0", rdv.OnlineCount())
	}
}
