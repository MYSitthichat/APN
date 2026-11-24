package p2p

import (
	"net"
	"strings"
	"sync"
	"time"
)

// authLimiter slows down password/PIN guessing against this host.
//
// Without it a 6-digit temporary PIN (1,000,000 values) could be brute-forced over QUIC or the
// public WSS URL in minutes to hours. Now:
//   - one source address gets perKeyMaxFails wrong attempts per window, then is locked out;
//   - every pinRotateEvery failures from anywhere rotate the temporary PIN, so even a
//     distributed attack gets only a handful of guesses per PIN;
//   - an extreme failure rate pauses password logins for everyone for a short time;
//   - each failure is answered only after failDelay.
type authLimiter struct {
	mu          sync.Mutex
	perKey      map[string][]time.Time
	lockedUntil map[string]time.Time
	global      []time.Time
	globalLock  time.Time
	sinceRotate int
	now         func() time.Time
}

const (
	authWindow      = 10 * time.Minute
	perKeyMaxFails  = 5
	perKeyLockout   = 15 * time.Minute
	pinRotateEvery  = 20
	globalMaxFails  = 100
	globalLockout   = 5 * time.Minute
	authFailDelay   = 1200 * time.Millisecond
	maxPendingAsk   = 3
	authLimiterKeys = 10000
)

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		perKey:      map[string][]time.Time{},
		lockedUntil: map[string]time.Time{},
		now:         time.Now,
	}
}

// allow reports whether key may attempt a password login now.
func (l *authLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.globalLock) {
		return false
	}
	return !now.Before(l.lockedUntil[key]) || l.lockedUntil[key].IsZero()
}

// fail records a wrong password from key. It returns true when the temporary PIN should be
// rotated now.
func (l *authLimiter) fail(key string) (rotatePIN bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-authWindow)

	if len(l.perKey) >= authLimiterKeys {
		l.pruneLocked(cut, now)
	}
	l.perKey[key] = append(prune(l.perKey[key], cut), now)
	if len(l.perKey[key]) >= perKeyMaxFails {
		l.lockedUntil[key] = now.Add(perKeyLockout)
	}

	l.global = append(prune(l.global, cut), now)
	if len(l.global) >= globalMaxFails {
		l.globalLock = now.Add(globalLockout)
	}

	l.sinceRotate++
	if l.sinceRotate >= pinRotateEvery {
		l.sinceRotate = 0
		return true
	}
	return false
}

// success clears key's failure history after a correct password.
func (l *authLimiter) success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.perKey, key)
	delete(l.lockedUntil, key)
}

func (l *authLimiter) pruneLocked(cut, now time.Time) {
	for k, v := range l.perKey {
		if v = prune(v, cut); len(v) == 0 {
			delete(l.perKey, k)
		} else {
			l.perKey[k] = v
		}
	}
	for k, until := range l.lockedUntil {
		if now.After(until) {
			delete(l.lockedUntil, k)
		}
	}
}

func prune(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	return ts[i:]
}

// authKey is the rate-limit key for a remote address: the IP (an IPv6 address is reduced to its
// /64, since one client usually controls a whole /64).
func authKey(remoteAddr string) string {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
