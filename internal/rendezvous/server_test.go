package rendezvous

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRendezvousLifecyclePunchAndSnapshot(t *testing.T) {
	snapPath := filepath.Join(t.TempDir(), "rdv-snapshot.json")
	srv := NewServer(Options{
		SnapshotPath: snapPath,
		TTL:          2 * time.Minute,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Register peer 595514895
	regBody := `{"device_id":"595 514 895","peer_id":"linux-box","name":"LinuxBox","os":"linux/amd64","fingerprint":"fp1","udp_addrs":["1.2.3.4:4433"],"ws_url":"wss://test.trycloudflare.com/ws/peer"}`
	resp, err := http.Post(ts.URL+"/api/rendezvous/register", "application/json", bytes.NewBufferString(regBody))
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d, want 200", resp.StatusCode)
	}

	// 2. Lookup with punch request
	punchBody := `{"from_device_id":"933127377","udp_addrs":["5.6.7.8:4433"]}`
	resp, err = http.Post(ts.URL+"/api/rendezvous/lookup/595514895", "application/json", bytes.NewBufferString(punchBody))
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	var lk struct {
		OK    bool  `json:"ok"`
		Entry Entry `json:"entry"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lk); err != nil {
		t.Fatalf("decode lookup: %v", err)
	}
	resp.Body.Close()
	if !lk.OK || lk.Entry.DeviceID != "595514895" || lk.Entry.WSURL != "wss://test.trycloudflare.com/ws/peer" {
		t.Fatalf("unexpected lookup response: %+v", lk)
	}

	// 3. Next heartbeat drains punch request
	resp, err = http.Post(ts.URL+"/api/rendezvous/register", "application/json", bytes.NewBufferString(regBody))
	if err != nil {
		t.Fatalf("register 2 failed: %v", err)
	}
	var regRes struct {
		OK            bool           `json:"ok"`
		PunchRequests []PunchRequest `json:"punch_requests"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&regRes)
	resp.Body.Close()
	if !regRes.OK || len(regRes.PunchRequests) != 1 || regRes.PunchRequests[0].FromDeviceID != "933127377" {
		t.Fatalf("expected 1 punch request drained, got %+v", regRes)
	}

	// 4. Presence check
	resp, err = http.Post(ts.URL+"/api/rendezvous/presence", "application/json", bytes.NewBufferString(`{"ids":["595514895","111222333"]}`))
	if err != nil {
		t.Fatalf("presence failed: %v", err)
	}
	var pres struct {
		OK    bool                      `json:"ok"`
		Peers map[string]map[string]any `json:"peers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pres)
	resp.Body.Close()
	if !pres.OK || pres.Peers["595514895"]["online"] != true || pres.Peers["111222333"]["online"] != false {
		t.Fatalf("unexpected presence: %+v", pres)
	}

	// 5. Save snapshot and verify zero-gap reload into a brand-new server instance
	saved, err := srv.SaveSnapshot(snapPath)
	if err != nil || saved != 1 {
		t.Fatalf("SaveSnapshot got (%d, %v), want (1, nil)", saved, err)
	}
	srv2 := NewServer(Options{SnapshotPath: snapPath, TTL: 2 * time.Minute})
	if got := srv2.OnlineCount(); got != 1 {
		t.Fatalf("reloaded server OnlineCount = %d, want 1", got)
	}

	// 6. Unregister removes peer immediately
	resp, err = http.Post(ts.URL+"/api/rendezvous/unregister", "application/json", bytes.NewBufferString(`{"device_id":"595514895"}`))
	if err != nil {
		t.Fatalf("unregister failed: %v", err)
	}
	resp.Body.Close()
	if srv.OnlineCount() != 0 {
		t.Fatalf("OnlineCount after unregister = %d, want 0", srv.OnlineCount())
	}
}
