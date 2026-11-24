package webui

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

// localGuard protects the local control UI/API (it can open remote shells, read and write local
// files, change the password and install updates).
//
//   - Host allowlist: only 127.0.0.1 / localhost / [::1] on our own port. A DNS-rebinding web
//     page arrives with its own domain in Host and is refused.
//   - Fetch metadata: browsers mark cross-site requests (and frames) with Sec-Fetch-Site; only
//     same-origin and direct navigation ("none") are accepted, for GET and WebSocket too.
//   - Caller identity: the TCP connection's owning OS account must be this process's account,
//     SYSTEM/root, or the user logged in on the screen. Other local users (another RDP/SSH
//     session, low-privilege malware) can no longer drive a root/SYSTEM service.
//   - Anti-framing headers against clickjacking (e.g. tricking a click on "Allow").
//
// APN_UI_ALLOW_ANY_LOCAL_USER=1 disables only the caller-identity check (for troubleshooting).
func localGuard(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedLocalHost(r.Host, serverPort(r)) {
			http.Error(w, "forbidden: unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" && !isTopLevelPageLoad(r) {
			http.Error(w, "forbidden: cross-site request", http.StatusForbidden)
			return
		}
		if os.Getenv("APN_UI_ALLOW_ANY_LOCAL_USER") != "1" {
			if ok, why := callerAllowed(r); !ok {
				if logger != nil {
					logger.Warn("refused local UI request from another account", "remote", r.RemoteAddr, "path", r.URL.Path, "reason", why)
				}
				http.Error(w, "forbidden: this APN belongs to another user account", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// isTopLevelPageLoad lets a link from another site open the dashboard page itself (harmless; it
// cannot be framed). Everything the page then does is same-origin.
func isTopLevelPageLoad(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/" &&
		r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
}

func serverPort(r *http.Request) string {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if la == nil {
		return ""
	}
	_, p, err := net.SplitHostPort(la.String())
	if err != nil {
		return ""
	}
	return p
}

func allowedLocalHost(host, port string) bool {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if port == "" || p != port {
		return false
	}
	switch strings.ToLower(strings.Trim(h, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// localConnPorts returns the client's and our ports for a loopback connection.
func localConnPorts(r *http.Request) (clientIP net.IP, clientPort, serverPort int, ok bool) {
	ch, cp, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, 0, 0, false
	}
	clientIP = net.ParseIP(ch)
	if clientIP == nil || !clientIP.IsLoopback() {
		return nil, 0, 0, false
	}
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if la == nil {
		return nil, 0, 0, false
	}
	_, sp, err := net.SplitHostPort(la.String())
	if err != nil {
		return nil, 0, 0, false
	}
	clientPort, serverPort = atoi(cp), atoi(sp)
	return clientIP, clientPort, serverPort, clientPort > 0 && serverPort > 0
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
