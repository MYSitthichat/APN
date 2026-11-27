package p2p

import (
	"testing"
	"time"
)

func TestAuthLimiterLocksOutRepeatedFailures(t *testing.T) {
	l := newAuthLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < perKeyMaxFails; i++ {
		if !l.allow("203.0.113.5") {
			t.Fatalf("locked out after only %d failures", i)
		}
		l.fail("203.0.113.5")
	}
	if l.allow("203.0.113.5") {
		t.Fatal("not locked out after the failure limit")
	}
	if !l.allow("198.51.100.9") {
		t.Fatal("another address must not be locked out")
	}
	if w := l.wait("203.0.113.5"); w != time.Minute {
		t.Fatalf("first lockout = %v, want 1 minute", w)
	}
	now = now.Add(perKeyLockout + time.Second)
	if !l.allow("203.0.113.5") {
		t.Fatal("still locked out after the lockout period")
	}
}

// TestAuthLimiterLockoutGrows: someone who mistyped waits a minute; a guesser who keeps going
// waits 2, 4, 8 and then at most 15 minutes, and the doubling is forgotten after an hour.
func TestAuthLimiterLockoutGrows(t *testing.T) {
	l := newAuthLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	lockOnce := func() time.Duration {
		for i := 0; i < perKeyMaxFails; i++ {
			if !l.allow("k") {
				t.Fatalf("locked out after %d of %d failures", i, perKeyMaxFails)
			}
			l.fail("k")
		}
		w := l.wait("k")
		now = now.Add(w + time.Second)
		return w
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		if got := lockOnce(); got != w {
			t.Fatalf("lockout #%d = %v, want %v", i+1, got, w)
		}
	}
	now = now.Add(lockoutMemory + time.Minute)
	if got := lockOnce(); got != time.Minute {
		t.Fatalf("lockout after a quiet hour = %v, want 1 minute again", got)
	}
	l.success("k")
	if got := lockOnce(); got != time.Minute {
		t.Fatalf("lockout after a successful login = %v, want 1 minute", got)
	}
}

func TestWaitText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second:            "45 วินาที",
		200 * time.Millisecond:      "1 วินาที",
		time.Minute:                 "1 นาที",
		time.Minute + 2*time.Second: "2 นาที",
		15 * time.Minute:            "15 นาที",
	} {
		if got := waitText(d); got != want {
			t.Errorf("waitText(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestAuthLimiterSuccessResets(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < perKeyMaxFails-1; i++ {
		l.fail("k")
	}
	l.success("k")
	l.fail("k")
	if !l.allow("k") {
		t.Fatal("history not cleared by a successful login")
	}
}

func TestAuthLimiterRotatesPINAndGlobalLock(t *testing.T) {
	l := newAuthLimiter()
	rotations := 0
	for i := 0; i < globalMaxFails; i++ {
		// Spread over many addresses like a distributed attack.
		if l.fail(authKey("10.0." + tItoa(i/250) + "." + tItoa(i%250) + ":4433")) {
			rotations++
		}
	}
	if rotations != globalMaxFails/pinRotateEvery {
		t.Fatalf("PIN rotations = %d, want %d", rotations, globalMaxFails/pinRotateEvery)
	}
	if l.allow("192.0.2.1") {
		t.Fatal("password logins not paused after the global failure limit")
	}
}

func TestAuthKeyGroupsIPv6By64(t *testing.T) {
	a := authKey("[2001:db8:1:2:aaaa::1]:4433")
	b := authKey("[2001:db8:1:2:bbbb::9]:4433")
	if a != b {
		t.Fatalf("same /64 gave different keys: %s %s", a, b)
	}
	if authKey("203.0.113.7:1234") != "203.0.113.7" {
		t.Fatal("IPv4 key should be the bare IP")
	}
}

func tItoa(i int) string {
	return string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}
