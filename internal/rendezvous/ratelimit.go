package rendezvous

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipLimiter is a per-client-IP token bucket. It keeps one public directory from being flooded
// with registrations (memory) or presence scans (enumerating every online device).
type ipLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(perMin, burst int) *ipLimiter {
	return &ipLimiter{
		perSec:  float64(perMin) / 60,
		burst:   float64(burst),
		buckets: make(map[string]*tokenBucket),
	}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.perSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops buckets that have been idle long enough to be full again.
func (l *ipLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	full := time.Duration(l.burst/l.perSec*float64(time.Second)) + time.Minute
	for ip, b := range l.buckets {
		if now.Sub(b.last) > full {
			delete(l.buckets, ip)
		}
	}
}

// clientIP returns the caller's IP. Forwarding headers are trusted only when the direct peer is
// on loopback or a private network (cloudflared / a reverse proxy / Docker on the same host);
// a directly exposed server ignores them so callers cannot spoof their IP.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if first := strings.TrimSpace(strings.Split(v, ",")[0]); first != "" {
				return first
			}
		}
	}
	return host
}
