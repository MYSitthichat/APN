package p2p

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authLimiter slows down password/PIN guessing against this host.
//
// Without it a 6-digit temporary PIN (1,000,000 values) could be brute-forced over QUIC or the
// public WSS URL in minutes to hours. Now:
//   - one source address gets perKeyMaxFails wrong attempts per window, then is locked out for
//     a minute; each further lockout within lockoutMemory doubles it, up to perKeyLockoutMax.
//     Someone who mistyped waits a minute; a guesser still gets only a few tries per hour;
//   - every pinRotateEvery failures from anywhere rotate the temporary PIN, so even a
//     distributed attack gets only a handful of guesses per PIN;
//   - an extreme failure rate pauses password logins for everyone for a short time;
//   - each failure is answered only after failDelay.
type authLimiter struct {
	mu          sync.Mutex
	perKey      map[string][]time.Time
	lockedUntil map[string]time.Time
	strikes     map[string]lockStrikes
	global      []time.Time
	globalLock  time.Time
	sinceRotate int
	now         func() time.Time
}

// lockStrikes counts the lockouts of one source address.
type lockStrikes struct {
	n    int
	last time.Time
}

const (
	authWindow       = 10 * time.Minute
	perKeyMaxFails   = 5
	perKeyLockout    = 1 * time.Minute  // first lockout
	perKeyLockoutMax = 15 * time.Minute // doubling stops here
	lockoutMemory    = time.Hour        // lockouts older than this no longer lengthen the next one
	pinRotateEvery   = 20
	globalMaxFails   = 100
	globalLockout    = 5 * time.Minute
	authFailDelay    = 1200 * time.Millisecond
	maxPendingAsk    = 3
	authLimiterKeys  = 10000
)

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		perKey:      map[string][]time.Time{},
		lockedUntil: map[string]time.Time{},
		strikes:     map[string]lockStrikes{},
		now:         time.Now,
	}
}

// allow reports whether key may attempt a password login now.
func (l *authLimiter) allow(key string) bool {
	return l.wait(key) == 0
}

// wait is how long key must wait before its next password login (0 = it may try now).
func (l *authLimiter) wait(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var w time.Duration
	if now.Before(l.globalLock) {
		w = l.globalLock.Sub(now)
	}
	if until := l.lockedUntil[key]; now.Before(until) && until.Sub(now) > w {
		w = until.Sub(now)
	}
	return w
}

// lockoutFor is the length of a source's next lockout: perKeyLockout, doubled for each lockout
// it had within lockoutMemory, at most perKeyLockoutMax. l.mu must be held.
func (l *authLimiter) lockoutFor(key string, now time.Time) time.Duration {
	s := l.strikes[key]
	if now.Sub(s.last) > lockoutMemory {
		s.n = 0
	}
	d := perKeyLockout
	for i := 0; i < s.n && d < perKeyLockoutMax; i++ {
		d *= 2
	}
	if d > perKeyLockoutMax {
		d = perKeyLockoutMax
	}
	l.strikes[key] = lockStrikes{n: s.n + 1, last: now}
	return d
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
		l.lockedUntil[key] = now.Add(l.lockoutFor(key, now))
		// The next lockout comes after another full set of wrong attempts, not after one.
		l.perKey[key] = nil
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
	delete(l.strikes, key)
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
	for k, s := range l.strikes {
		if now.Sub(s.last) > lockoutMemory {
			delete(l.strikes, k)
		}
	}
}

// waitText says how long to wait, in Thai: "45 วินาที", "2 นาที".
func waitText(d time.Duration) string {
	if d < time.Minute {
		s := int(d.Seconds() + 0.999)
		if s < 1 {
			s = 1
		}
		return strconv.Itoa(s) + " วินาที"
	}
	return strconv.Itoa(int(d.Minutes()+0.999)) + " นาที"
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
