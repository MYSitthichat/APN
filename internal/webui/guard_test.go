package webui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func newGuardedServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewServer(localGuard(mux, nil))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	return srv, port
}

func doReq(t *testing.T, srv *httptest.Server, method, path, host string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestLocalGuardHostAllowlist(t *testing.T) {
	srv, port := newGuardedServer(t)
	for _, h := range []string{"127.0.0.1:" + port, "localhost:" + port, "LOCALHOST:" + port, "[::1]:" + port} {
		if got := doReq(t, srv, "GET", "/api/x", h, nil); got != http.StatusOK {
			t.Errorf("Host %q: got %d, want 200", h, got)
		}
	}
	// DNS rebinding: attacker's domain resolving to 127.0.0.1; wrong port; no port.
	for _, h := range []string{"evil.example:" + port, "127.0.0.1.nip.io:" + port, "127.0.0.1:1", "127.0.0.1", "localhost"} {
		if got := doReq(t, srv, "GET", "/api/x", h, nil); got == http.StatusOK {
			t.Errorf("Host %q was accepted", h)
		}
	}
}

func TestLocalGuardFetchMetadata(t *testing.T) {
	srv, _ := newGuardedServer(t)
	cases := []struct {
		method, path string
		hdr          map[string]string
		want         int
	}{
		{"POST", "/api/peer/quit", map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"GET", "/api/state", map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"POST", "/api/peer/quit", nil, 200}, // non-browser local client (CLI/service)
		{"POST", "/api/peer/quit", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"GET", "/api/state", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"GET", "/ws/remote", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "websocket"}, 403},
		// A link from another site may open the dashboard page, but nothing else.
		{"GET", "/", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, 200},
		{"GET", "/", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"}, 403},
		{"GET", "/api/state", map[string]string{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, 403},
	}
	for _, c := range cases {
		if got := doReq(t, srv, c.method, c.path, "", c.hdr); got != c.want {
			t.Errorf("%s %s %v: got %d, want %d", c.method, c.path, c.hdr, got, c.want)
		}
	}
}

func TestLocalGuardHeadersAndSelfCaller(t *testing.T) {
	srv, _ := newGuardedServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// 200 here also proves the OS caller check identifies this test process's own account.
	if resp.StatusCode != 200 {
		t.Fatalf("own account refused: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing anti-framing headers: %v", resp.Header)
	}
}

// curlStatus fetches url with the system curl (a separate process) and returns the HTTP status.
func curlStatus(t *testing.T, url string, prep func(*exec.Cmd)) string {
	t.Helper()
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not available")
	}
	cmd := exec.Command(curl, "-s", "-o", os.DevNull, "-w", "%{http_code}", url)
	if prep != nil {
		prep(cmd)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("curl: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestLocalGuardOtherProcessSameAccount(t *testing.T) {
	srv, _ := newGuardedServer(t)
	if got := curlStatus(t, srv.URL+"/api/state", nil); got != "200" {
		t.Fatalf("another process of the same account got %s, want 200", got)
	}
}
