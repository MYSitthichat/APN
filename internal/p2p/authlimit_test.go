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
	now = now.Add(perKeyLockout + time.Second)
	if !l.allow("203.0.113.5") {
		t.Fatal("still locked out after the lockout period")
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
