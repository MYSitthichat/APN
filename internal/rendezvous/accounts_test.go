package rendezvous

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type acctResp struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Token     string `json:"token"`
	Rev       int64  `json:"rev"`
	Vault     string `json:"vault"`
	Unchanged bool   `json:"unchanged"`
}

func testAuthKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, accountAuthKeyLen))
}

func acctCall(t *testing.T, base, method, path, bearer string, body any) (int, acctResp) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out acctResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func newAccountServer(t *testing.T, dir string, signup bool) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer(Options{AccountsDir: dir, AccountSignup: signup, RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestAccountRegisterLoginVault(t *testing.T) {
	dir := t.TempDir()
	_, ts := newAccountServer(t, dir, true)

	st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": " Somchai ", "auth_key": testAuthKey(1), "device": "pc-a"})
	if st != 200 || r.Token == "" || r.Rev != 0 {
		t.Fatalf("register: status %d %+v", st, r)
	}
	bearerA := "somchai:" + r.Token

	if st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "somchai", "auth_key": testAuthKey(2)}); st != 409 || r.Code != "username_taken" {
		t.Fatalf("duplicate register: status %d code %q", st, r.Code)
	}
	for _, bad := range []string{"ab", "has space", "../etc", "-lead", strings.Repeat("a", 33), "ไทย"} {
		if st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": bad, "auth_key": testAuthKey(2)}); st != 400 || r.Code != "invalid_username" {
			t.Errorf("username %q: status %d code %q, want 400 invalid_username", bad, st, r.Code)
		}
	}

	// Empty account: nothing stored yet.
	if st, r := acctCall(t, ts.URL, "GET", "/api/account/vault?rev=0", bearerA, nil); st != 200 || !r.Unchanged || r.Rev != 0 {
		t.Fatalf("empty vault: status %d %+v", st, r)
	}

	v1 := base64.StdEncoding.EncodeToString([]byte("ciphertext-1"))
	if st, r := acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerA, map[string]any{"base_rev": 0, "vault": v1}); st != 200 || r.Rev != 1 {
		t.Fatalf("put vault: status %d %+v", st, r)
	}

	// A second machine signs in and reads the same vault.
	st, r = acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "SOMCHAI", "auth_key": testAuthKey(1), "device": "pc-b"})
	if st != 200 || r.Token == "" || r.Rev != 1 {
		t.Fatalf("login: status %d %+v", st, r)
	}
	bearerB := "somchai:" + r.Token
	if st, r := acctCall(t, ts.URL, "GET", "/api/account/vault?rev=0", bearerB, nil); st != 200 || r.Vault != v1 || r.Rev != 1 {
		t.Fatalf("get vault on B: status %d %+v", st, r)
	}
	if st, r := acctCall(t, ts.URL, "GET", "/api/account/vault?rev=1", bearerB, nil); st != 200 || !r.Unchanged || r.Vault != "" {
		t.Fatalf("get unchanged vault: status %d %+v", st, r)
	}

	// B writes; A still has rev 1 and must be told about the conflict, with B's vault.
	v2 := base64.StdEncoding.EncodeToString([]byte("ciphertext-2"))
	if st, r := acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerB, map[string]any{"base_rev": 1, "vault": v2}); st != 200 || r.Rev != 2 {
		t.Fatalf("put vault on B: status %d %+v", st, r)
	}
	if st, r := acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerA, map[string]any{"base_rev": 1, "vault": v1}); st != 409 || r.Code != "conflict" || r.Rev != 2 || r.Vault != v2 {
		t.Fatalf("stale put: status %d %+v", st, r)
	}

	// Limits and bad input.
	big := base64.StdEncoding.EncodeToString(make([]byte, maxVaultBytes+1))
	if st, _ := acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerA, map[string]any{"base_rev": 2, "vault": big}); st != 413 {
		t.Fatalf("oversized vault: status %d, want 413", st)
	}
	if st, _ := acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerA, map[string]any{"base_rev": 2, "vault": ""}); st != 400 {
		t.Fatalf("empty vault: status %d, want 400", st)
	}
	for _, bearer := range []string{"", "somchai:wrong", "nobody:" + r.Token, "somchai"} {
		if st, _ := acctCall(t, ts.URL, "GET", "/api/account/vault", bearer, nil); st != 401 {
			t.Errorf("bearer %q: status %d, want 401", bearer, st)
		}
	}

	// The server keeps neither the auth key nor the token itself.
	meta, err := os.ReadFile(filepath.Join(dir, "u-somchai.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(meta, []byte(testAuthKey(1))) || bytes.Contains(meta, []byte(strings.TrimPrefix(bearerA, "somchai:"))) {
		t.Fatal("account file contains the auth key or a session token in clear")
	}

	// Sign-out ends only that session.
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/logout", bearerA, nil); st != 200 {
		t.Fatalf("logout: status %d", st)
	}
	if st, _ := acctCall(t, ts.URL, "GET", "/api/account/vault", bearerA, nil); st != 401 {
		t.Fatalf("after logout: status %d, want 401", st)
	}
	if st, _ := acctCall(t, ts.URL, "GET", "/api/account/vault", bearerB, nil); st != 200 {
		t.Fatalf("other session after logout: status %d, want 200", st)
	}

	// Restart: accounts, sessions and the vault are read back from disk.
	_, ts2 := newAccountServer(t, dir, true)
	if st, r := acctCall(t, ts2.URL, "GET", "/api/account/vault", bearerB, nil); st != 200 || r.Vault != v2 || r.Rev != 2 {
		t.Fatalf("after restart: status %d %+v", st, r)
	}
}

func TestAccountWrongPasswordIsThrottled(t *testing.T) {
	_, ts := newAccountServer(t, t.TempDir(), true)
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 200 {
		t.Fatalf("register: status %d", st)
	}
	for i := 0; i < loginIPUserLimit; i++ {
		if st, r := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(9)}); st != 401 || r.Code != "invalid_credentials" {
			t.Fatalf("wrong password #%d: status %d code %q", i, st, r.Code)
		}
	}
	// Blocked now, even with the right key.
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 429 || r.Code != "rate_limited" {
		t.Fatalf("after %d failures: status %d code %q, want 429", loginIPUserLimit, st, r.Code)
	}
	// An unknown user answers exactly like a wrong password.
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "ghost", "auth_key": testAuthKey(1)}); st != 401 || r.Code != "invalid_credentials" {
		t.Fatalf("unknown user: status %d code %q", st, r.Code)
	}
}

func TestAccountThrottleExpires(t *testing.T) {
	srv, ts := newAccountServer(t, t.TempDir(), true)
	now := time.Now()
	srv.now = func() time.Time { return now }
	acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)})
	for i := 0; i < loginIPUserLimit; i++ {
		acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(9)})
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 429 {
		t.Fatalf("status %d, want 429", st)
	}
	now = now.Add(loginIPUserWindow + time.Second)
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 200 {
		t.Fatalf("after the window: status %d, want 200", st)
	}
}

func TestAccountSignupLimits(t *testing.T) {
	_, closed := newAccountServer(t, t.TempDir(), false)
	if st, r := acctCall(t, closed.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 403 || r.Code != "signup_closed" {
		t.Fatalf("closed sign-up: status %d code %q", st, r.Code)
	}

	_, open := newAccountServer(t, t.TempDir(), true)
	for i := 0; i < signupPerIPLimit; i++ {
		if st, _ := acctCall(t, open.URL, "POST", "/api/account/register", "", map[string]any{"username": fmt.Sprintf("user%d", i), "auth_key": testAuthKey(1)}); st != 200 {
			t.Fatalf("register #%d: status %d", i, st)
		}
	}
	if st, r := acctCall(t, open.URL, "POST", "/api/account/register", "", map[string]any{"username": "onemore", "auth_key": testAuthKey(1)}); st != 429 || r.Code != "rate_limited" {
		t.Fatalf("register past the per-address limit: status %d code %q", st, r.Code)
	}

	srv := NewServer(Options{AccountsDir: t.TempDir(), AccountSignup: true, MaxAccounts: 1, RatePerMin: -1})
	full := httptest.NewServer(srv.Handler())
	defer full.Close()
	acctCall(t, full.URL, "POST", "/api/account/register", "", map[string]any{"username": "first", "auth_key": testAuthKey(1)})
	if st, r := acctCall(t, full.URL, "POST", "/api/account/register", "", map[string]any{"username": "second", "auth_key": testAuthKey(1)}); st != 403 || r.Code != "full" {
		t.Fatalf("register past max accounts: status %d code %q", st, r.Code)
	}
}

func TestAccountPasswordChange(t *testing.T) {
	_, ts := newAccountServer(t, t.TempDir(), true)
	_, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)})
	bearerA := "malee:" + r.Token
	_, r = acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)})
	bearerB := "malee:" + r.Token
	v1 := base64.StdEncoding.EncodeToString([]byte("old-key-ciphertext"))
	acctCall(t, ts.URL, "PUT", "/api/account/vault", bearerA, map[string]any{"base_rev": 0, "vault": v1})

	v2 := base64.StdEncoding.EncodeToString([]byte("new-key-ciphertext"))
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/password", bearerA, map[string]any{"auth_key": testAuthKey(7), "new_auth_key": testAuthKey(2), "base_rev": 1, "vault": v2}); st != 401 || r.Code != "invalid_credentials" {
		t.Fatalf("wrong current password: status %d code %q", st, r.Code)
	}
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/password", bearerA, map[string]any{"auth_key": testAuthKey(1), "new_auth_key": testAuthKey(2), "base_rev": 0, "vault": v2}); st != 409 || r.Vault != v1 {
		t.Fatalf("stale base_rev: status %d %+v", st, r)
	}
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/password", bearerA, map[string]any{"auth_key": testAuthKey(1), "new_auth_key": testAuthKey(2), "base_rev": 1, "vault": v2}); st != 200 || r.Rev != 2 {
		t.Fatalf("password change: status %d %+v", st, r)
	}
	if st, r := acctCall(t, ts.URL, "GET", "/api/account/vault", bearerA, nil); st != 200 || r.Vault != v2 {
		t.Fatalf("vault after change: status %d %+v", st, r)
	}
	if st, _ := acctCall(t, ts.URL, "GET", "/api/account/vault", bearerB, nil); st != 401 {
		t.Fatalf("other session after password change: status %d, want 401", st)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 401 {
		t.Fatalf("old password after change: status %d, want 401", st)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(2)}); st != 200 {
		t.Fatalf("new password after change: status %d, want 200", st)
	}
}

func TestAccountsDisabled(t *testing.T) {
	srv := NewServer(Options{RatePerMin: -1})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 404 || r.Code != "accounts_disabled" {
		t.Fatalf("status %d code %q, want 404 accounts_disabled", st, r.Code)
	}
}
