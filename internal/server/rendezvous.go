package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RendezvousEntry stores lightweight P2P contact info for a 9-digit Device ID (TTL 65s).
type RendezvousEntry struct {
	DeviceID    string    `json:"device_id"`
	PeerID      string    `json:"peer_id"`
	Name        string    `json:"name"`
	OS          string    `json:"os"`
	Fingerprint string    `json:"fingerprint"`
	UDPAddrs    []string  `json:"udp_addrs,omitempty"`
	WSURL       string    `json:"ws_url,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PunchRequest tells a target peer to send UDP hole-punch packets toward an incoming caller.
type PunchRequest struct {
	FromDeviceID string   `json:"from_device_id"`
	UDPAddrs     []string `json:"udp_addrs"`
}

type rendezvousDirectory struct {
	mu      sync.Mutex
	entries map[string]RendezvousEntry
	punches map[string][]PunchRequest
}

func newRendezvousDirectory() *rendezvousDirectory {
	return &rendezvousDirectory{
		entries: make(map[string]RendezvousEntry),
		punches: make(map[string][]PunchRequest),
	}
}

func normalizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (d *rendezvousDirectory) handleRegister(w http.ResponseWriter, r *http.Request) {
	var entry RendezvousEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	id := normalizeID(entry.DeviceID)
	if len(id) < 6 || len(id) > 16 {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}
	entry.DeviceID = id
	entry.UpdatedAt = time.Now().UTC()

	d.mu.Lock()
	d.entries[id] = entry
	pending := d.punches[id]
	delete(d.punches, id)
	d.pruneLocked()
	d.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":             true,
		"punch_requests": pending,
	})
}

func (d *rendezvousDirectory) handleLookup(w http.ResponseWriter, r *http.Request) {
	id := normalizeID(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing device_id", http.StatusBadRequest)
		return
	}

	var caller PunchRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&caller)
	}

	d.mu.Lock()
	d.pruneLocked()
	entry, ok := d.entries[id]
	if ok && len(caller.UDPAddrs) > 0 {
		d.punches[id] = append(d.punches[id], caller)
	}
	d.mu.Unlock()

	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "ไม่พบเครื่องหมายเลขนี้ในระบบ Rendezvous (อาจออฟไลน์อยู่)"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"entry": entry,
	})
}

func (d *rendezvousDirectory) handleUnregister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id := normalizeID(body.DeviceID)
	if id != "" {
		d.mu.Lock()
		delete(d.entries, id)
		delete(d.punches, id)
		d.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (d *rendezvousDirectory) handlePresence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	peers := make(map[string]any, len(body.IDs))

	d.mu.Lock()
	d.pruneLocked()
	for _, raw := range body.IDs {
		id := normalizeID(raw)
		if id == "" {
			continue
		}
		if e, ok := d.entries[id]; ok {
			peers[id] = map[string]any{
				"online":     true,
				"name":       e.Name,
				"os":         e.OS,
				"updated_at": e.UpdatedAt.Format(time.RFC3339),
			}
		} else {
			peers[id] = map[string]any{"online": false}
		}
	}
	d.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "peers": peers})
}

func (d *rendezvousDirectory) pruneLocked() {
	cutoff := time.Now().UTC().Add(-65 * time.Second)
	for id, e := range d.entries {
		if e.UpdatedAt.Before(cutoff) {
			delete(d.entries, id)
			delete(d.punches, id)
		}
	}
}
