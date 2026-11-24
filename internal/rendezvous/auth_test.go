package rendezvous

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testDevice struct {
	key  *ecdsa.PrivateKey
	der  []byte
	fp   string
	cert string
}

func newTestDevice(t *testing.T, name string) testDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{key: key, der: der, fp: CertFingerprint(der), cert: base64.StdEncoding.EncodeToString(der)}
}

func (d testDevice) registerBody(t *testing.T, id, wsURL string, udp []string, ts int64) map[string]any {
	t.Helper()
	sig, err := SignMessage(d.key, SignedMessage("register", id, d.fp, ts, wsURL, udp), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"device_id": id, "name": "dev", "os": "linux/amd64", "fingerprint": d.fp,
		"udp_addrs": udp, "ws_url": wsURL, "ts": ts, "cert": d.cert, "sig": sig,
	}
}

func (d testDevice) unregisterBody(t *testing.T, id string, ts int64) map[string]any {
	t.Helper()
	sig, err := SignMessage(d.key, SignedMessage("unregister", id, d.fp, ts, "", nil), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"device_id": id, "fingerprint": d.fp, "ts": ts, "cert": d.cert, "sig": sig}
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func lookupFP(t *testing.T, base, id string) string {
	t.Helper()
	code, out := post(t, base+"/api/rendezvous/lookup/"+id, map[string]any{})
	if code != http.StatusOK {
		return ""
	}
	entry, _ := out["entry"].(map[string]any)
	fp, _ := entry["fingerprint"].(string)
	return fp
}

func TestSignedRegistrationBindsDeviceID(t *testing.T) {
	srv := NewServer(Options{TTL: time.Minute, RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	const id = "595514895"
	owner := newTestDevice(t, "owner")
	attacker := newTestDevice(t, "attacker")
	now := time.Now().UnixMilli()

	if code, out := post(t, ts.URL+"/api/rendezvous/register", owner.registerBody(t, id, "wss://owner.example/ws", []string{"1.2.3.4:4433"}, now)); code != 200 {
		t.Fatalf("owner signed register = %d %v", code, out)
	}

	// Unsigned takeover of a bound ID is refused.
	unsigned := map[string]any{"device_id": id, "fingerprint": attacker.fp, "ws_url": "wss://evil.example/ws"}
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", unsigned); code != http.StatusUnauthorized {
		t.Fatalf("unsigned takeover = %d, want 401", code)
	}
	// A validly signed register from another key is refused too.
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", attacker.registerBody(t, id, "wss://evil.example/ws", nil, now)); code != http.StatusConflict {
		t.Fatalf("signed takeover by other key = %d, want 409", code)
	}
	if got := lookupFP(t, ts.URL, id); got != owner.fp {
		t.Fatalf("lookup fingerprint = %q, want owner %q", got, owner.fp)
	}

	// Signature over different endpoints than sent (tampered ws_url) is rejected.
	body := owner.registerBody(t, id, "wss://owner.example/ws", nil, now)
	body["ws_url"] = "wss://evil.example/ws"
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", body); code != http.StatusUnauthorized {
		t.Fatalf("tampered ws_url = %d, want 401", code)
	}
	// Timestamps outside the allowed skew are rejected.
	old := time.Now().Add(-SigMaxSkew - time.Hour).UnixMilli()
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", owner.registerBody(t, id, "", nil, old)); code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp = %d, want 401", code)
	}

	// Only the owner key can unregister.
	if code, _ := post(t, ts.URL+"/api/rendezvous/unregister", attacker.unregisterBody(t, id, now)); code != http.StatusForbidden {
		t.Fatalf("unregister by other key = %d, want 403", code)
	}
	if code, _ := post(t, ts.URL+"/api/rendezvous/unregister", owner.unregisterBody(t, id, now)); code != 200 || srv.OnlineCount() != 0 {
		t.Fatalf("owner unregister = %d, online %d", code, srv.OnlineCount())
	}
	// The binding outlives the entry: the attacker still cannot claim the now-offline ID.
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", attacker.registerBody(t, id, "wss://evil.example/ws", nil, now)); code != http.StatusConflict {
		t.Fatalf("claim of offline bound ID = %d, want 409", code)
	}
}

func TestLegacyLiveEntryCannotBeHijacked(t *testing.T) {
	srv := NewServer(Options{TTL: time.Minute, RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	const id = "111222333"
	owner := newTestDevice(t, "owner")
	attacker := newTestDevice(t, "attacker")

	// An old (unsigned) client is online.
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", map[string]any{"device_id": id, "fingerprint": owner.fp}); code != 200 {
		t.Fatalf("legacy register = %d", code)
	}
	// Neither an unsigned nor a signed register with another certificate may replace it.
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", map[string]any{"device_id": id, "fingerprint": attacker.fp}); code != http.StatusConflict {
		t.Fatalf("unsigned hijack of live legacy entry = %d, want 409", code)
	}
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", attacker.registerBody(t, id, "", nil, time.Now().UnixMilli())); code != http.StatusConflict {
		t.Fatalf("signed hijack of live legacy entry = %d, want 409", code)
	}
	// When the owner updates APN, its first signed register binds the ID.
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", owner.registerBody(t, id, "", nil, time.Now().UnixMilli())); code != 200 {
		t.Fatalf("owner upgrade to signed = %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", map[string]any{"device_id": id, "fingerprint": owner.fp}); code != http.StatusUnauthorized {
		t.Fatalf("unsigned register after binding = %d, want 401", code)
	}
}

func TestBindingSurvivesSnapshotReload(t *testing.T) {
	snap := filepath.Join(t.TempDir(), "rdv.json")
	srv := NewServer(Options{TTL: time.Minute, SnapshotPath: snap, RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	owner := newTestDevice(t, "owner")
	attacker := newTestDevice(t, "attacker")
	now := time.Now().UnixMilli()
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", owner.registerBody(t, id9, "", nil, now)); code != 200 {
		t.Fatalf("register = %d", code)
	}
	if _, err := srv.SaveSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	ts.Close()

	srv2 := NewServer(Options{TTL: time.Minute, SnapshotPath: snap, RatePerMin: -1})
	srv2.now = func() time.Time { return time.Now().Add(10 * time.Minute) } // entry expired, binding not
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()
	if code, _ := post(t, ts2.URL+"/api/rendezvous/register", attacker.registerBody(t, id9, "", nil, now)); code != http.StatusConflict {
		t.Fatalf("after reload, claim by other key = %d, want 409", code)
	}
	if code, _ := post(t, ts2.URL+"/api/rendezvous/register", owner.registerBody(t, id9, "", nil, now)); code != 200 {
		t.Fatalf("after reload, owner register = %d", code)
	}
}

const id9 = "482917305"

func TestRegisterFieldLimits(t *testing.T) {
	srv := NewServer(Options{RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	long := make([]byte, maxWSURLLen+1)
	for i := range long {
		long[i] = 'a'
	}
	cases := []map[string]any{
		{"device_id": "123456789", "fingerprint": "fp", "ws_url": "wss://" + string(long)},
		{"device_id": "123456789", "fingerprint": "fp", "ws_url": "https://not-a-websocket.example"},
		{"device_id": "123456789", "fingerprint": string(long[:maxFPLen+1])},
	}
	for i, c := range cases {
		if code, _ := post(t, ts.URL+"/api/rendezvous/register", c); code != http.StatusBadRequest {
			t.Fatalf("case %d: status %d, want 400", i, code)
		}
	}
	// Over-long names are stored truncated rather than rejected.
	name := string(long[:500])
	if code, _ := post(t, ts.URL+"/api/rendezvous/register", map[string]any{"device_id": "123456789", "fingerprint": "fp", "name": name}); code != 200 {
		t.Fatalf("long name register = %d", code)
	}
	_, out := post(t, ts.URL+"/api/rendezvous/lookup/123456789", map[string]any{})
	if got := out["entry"].(map[string]any)["name"].(string); len(got) != maxNameLen {
		t.Fatalf("stored name length %d, want %d", len(got), maxNameLen)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	srv := NewServer(Options{RatePerMin: 60, RateBurst: 5})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	limited := false
	for i := 0; i < 20; i++ {
		if code, _ := post(t, ts.URL+"/api/rendezvous/presence", map[string]any{"ids": []string{"123456789"}}); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected 429 after the burst")
	}
}

func TestClientIPTrustsHeadersOnlyFromPrivatePeers(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r.RemoteAddr = "127.0.0.1:5555"
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("via local proxy = %q", got)
	}
	r.RemoteAddr = "172.18.0.3:5555" // Docker network
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("via docker proxy = %q", got)
	}
	r.RemoteAddr = "198.51.100.7:5555" // public peer: header is spoofable, ignore it
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("direct public peer = %q", got)
	}
}

// TestWriteWorkerFixture writes a signed register request for the Cloudflare Worker test
// (cloudflare-worker/test/worker.test.mjs), so both directories are checked against the
// exact bytes the Go client produces. Run with APN_WRITE_WORKER_FIXTURE=1 to regenerate.
func TestWriteWorkerFixture(t *testing.T) {
	if os.Getenv("APN_WRITE_WORKER_FIXTURE") == "" {
		t.Skip("set APN_WRITE_WORKER_FIXTURE=1 to regenerate the Worker fixture")
	}
	owner := newTestDevice(t, "fixture-owner")
	attacker := newTestDevice(t, "fixture-attacker")
	ts := time.Now().UnixMilli()
	fixture := map[string]any{
		"ts":                  ts,
		"owner_register":      owner.registerBody(t, id9, "wss://owner.example/ws", []string{"1.2.3.4:4433"}, ts),
		"owner_unregister":    owner.unregisterBody(t, id9, ts),
		"attacker_register":   attacker.registerBody(t, id9, "wss://evil.example/ws", nil, ts),
		"attacker_unregister": attacker.unregisterBody(t, id9, ts),
	}
	b, _ := json.MarshalIndent(fixture, "", "  ")
	out := filepath.Join("..", "..", "cloudflare-worker", "test", "fixture.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
