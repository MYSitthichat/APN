package rendezvous

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Accounts: sign-in for the address book.
//
// An account stores one opaque blob (the "vault"): the caller's list of remembered devices,
// encrypted on the caller's machine with a key derived from the account password. The server
// never sees the password, the key or the list. What it does see and check:
//
//   - auth_key: 32 bytes derived from the password on the client (Argon2id, then HKDF). The
//     server keeps only a salted SHA-256 of it.
//   - session tokens: random, kept as SHA-256, sent as "Authorization: Bearer <user>:<token>".
//   - the vault's revision number, so two machines cannot silently overwrite each other.
//
// Storage is one small JSON file per account plus one vault file, under Options.AccountsDir.
//
// Forgotten password: the account's e-mail address receives a short-lived code (see mail.go).
// Whoever presents the code sets a new auth key. The vault cannot be decrypted without the old
// password, so it is discarded; the machines that still hold the list upload it again after
// signing in with the new password.
const (
	maxVaultBytes      = 256 * 1024 // ciphertext; the client gzips before encrypting
	maxAccountBody     = 400 * 1024
	accountAuthKeyLen  = 32
	maxSessionsPerUser = 50
	sessionIdleTTL     = 90 * 24 * time.Hour
	defaultMaxAccounts = 10_000

	signupPerIPLimit  = 5 // new accounts per client IP per hour
	signupPerIPWindow = time.Hour
	loginIPUserLimit  = 8 // failed sign-ins per client IP and username per 10 minutes
	loginIPUserWindow = 10 * time.Minute
	loginUserLimit    = 60 // failed sign-ins per username per hour, from any IP
	loginUserWindow   = time.Hour

	resetCodeDigits   = 8
	resetCodeTTL      = 15 * time.Minute
	resetCodeAttempts = 5  // wrong guesses before a code is thrown away
	resetPerUserLimit = 3  // reset mails per account per hour
	resetPerIPLimit   = 10 // reset requests per client IP per hour
	resetConfirmPerIP = 30 // wrong codes per client IP per hour, across accounts
	resetLimitWindow  = time.Hour
)

var usernameRe = regexp.MustCompile("^[a-z0-9][a-z0-9._-]{2,31}$")

// NormalizeUsername lower-cases and trims a username.
func NormalizeUsername(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// ValidUsername reports whether u (already normalized) is 3-32 characters of a-z 0-9 . _ -
// starting with a letter or digit.
func ValidUsername(u string) bool { return usernameRe.MatchString(u) }

type accountSession struct {
	Hash     string `json:"hash"`
	Device   string `json:"device,omitempty"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used"`
}

type account struct {
	Username string           `json:"username"`
	Email    string           `json:"email,omitempty"` // where password-reset codes are sent
	AuthSalt string           `json:"auth_salt"`
	AuthHash string           `json:"auth_hash"`
	Created  int64            `json:"created"`
	VaultRev int64            `json:"vault_rev"`
	VaultAt  int64            `json:"vault_at,omitempty"`
	Sessions []accountSession `json:"sessions,omitempty"`
}

type failWindow struct {
	n     int
	start time.Time
}

// resetCode is a pending password reset. Codes live in memory only: a restart cancels them.
type resetCode struct {
	hash     string
	expires  time.Time
	attempts int
}

type accountStore struct {
	mu       sync.Mutex
	dir      string
	signup   bool
	max      int
	accounts map[string]*account
	counters map[string]*failWindow
	resets   map[string]*resetCode
	// mailer sends a reset code; nil when the server has no SMTP settings.
	mailer func(to, subject, body string) error
}

// newAccountStore loads every account under dir. A missing dir is created.
func newAccountStore(dir string, signup bool, max int) (*accountStore, error) {
	if max <= 0 {
		max = defaultMaxAccounts
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &accountStore{dir: dir, signup: signup, max: max, accounts: map[string]*account{}, counters: map[string]*failWindow{}, resets: map[string]*resetCode{}}
	names, err := filepath.Glob(filepath.Join(dir, "u-*.json"))
	if err != nil {
		return nil, err
	}
	for _, p := range names {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var acc account
		if json.Unmarshal(b, &acc) != nil || !ValidUsername(acc.Username) || acc.AuthHash == "" {
			continue
		}
		a.accounts[acc.Username] = &acc
	}
	return a, nil
}

func (a *accountStore) metaPath(u string) string  { return filepath.Join(a.dir, "u-"+u+".json") }
func (a *accountStore) vaultPath(u string) string { return filepath.Join(a.dir, "u-"+u+".vault") }

// writeFileAtomic replaces path in one step, so a crash never leaves half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *accountStore) saveMeta(acc *account) error {
	b, err := json.Marshal(acc)
	if err != nil {
		return err
	}
	return writeFileAtomic(a.metaPath(acc.Username), b)
}

func hashAuthKey(saltHex string, authKey []byte) string {
	salt, _ := hex.DecodeString(saltHex)
	h := sha256.New()
	h.Write(salt)
	h.Write(authKey)
	return hex.EncodeToString(h.Sum(nil))
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// over reports whether key already used up limit within window; hit counts one more use.
func (a *accountStore) over(key string, limit int, window time.Duration, now time.Time) bool {
	w := a.counters[key]
	return w != nil && now.Sub(w.start) < window && w.n >= limit
}

func (a *accountStore) hit(key string, window time.Duration, now time.Time) {
	w := a.counters[key]
	if w == nil || now.Sub(w.start) >= window {
		a.counters[key] = &failWindow{n: 1, start: now}
		return
	}
	w.n++
}

// prune drops counters whose window is over (called from the maintenance loop).
func (a *accountStore) prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, w := range a.counters {
		if now.Sub(w.start) >= loginUserWindow {
			delete(a.counters, k)
		}
	}
	for u, rc := range a.resets {
		if now.After(rc.expires) {
			delete(a.resets, u)
		}
	}
}

func decodeAuthKey(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != accountAuthKeyLen {
		return nil, false
	}
	return b, true
}

func accountError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": msg})
}

func cleanDeviceName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// newSession adds a session to acc and returns its token. The caller saves acc.
func (a *accountStore) newSession(acc *account, device string, now time.Time) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	ms := now.UnixMilli()
	acc.Sessions = append(acc.Sessions, accountSession{Hash: hashToken(token), Device: cleanDeviceName(device), Created: ms, LastUsed: ms})
	if extra := len(acc.Sessions) - maxSessionsPerUser; extra > 0 {
		acc.Sessions = acc.Sessions[extra:] // oldest first
	}
	return token, nil
}

var errNoSession = errors.New("no valid session")

// session finds the account and session a request's bearer token belongs to. a.mu must be held.
func (a *accountStore) session(r *http.Request, now time.Time) (*account, int, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, 0, errNoSession
	}
	user, token, ok := strings.Cut(strings.TrimPrefix(h, "Bearer "), ":")
	if !ok || token == "" {
		return nil, 0, errNoSession
	}
	acc := a.accounts[NormalizeUsername(user)]
	if acc == nil {
		return nil, 0, errNoSession
	}
	want := hashToken(token)
	ms := now.UnixMilli()
	for i := range acc.Sessions {
		s := &acc.Sessions[i]
		if subtle.ConstantTimeCompare([]byte(s.Hash), []byte(want)) != 1 {
			continue
		}
		if ms-s.LastUsed > sessionIdleTTL.Milliseconds() {
			acc.Sessions = append(acc.Sessions[:i], acc.Sessions[i+1:]...)
			_ = a.saveMeta(acc)
			return nil, 0, errNoSession
		}
		if ms-s.LastUsed > (24 * time.Hour).Milliseconds() {
			s.LastUsed = ms
			_ = a.saveMeta(acc)
		}
		return acc, i, nil
	}
	return nil, 0, errNoSession
}

func readAccountBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAccountBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			accountError(w, http.StatusRequestEntityTooLarge, "too_large", "request is too large")
		} else {
			accountError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		}
		return false
	}
	_, _ = io.Copy(io.Discard, r.Body)
	return true
}

func (s *Server) accountRoutes(mux *http.ServeMux) {
	if s.accounts == nil {
		mux.HandleFunc("/api/account/", func(w http.ResponseWriter, _ *http.Request) {
			accountError(w, http.StatusNotFound, "accounts_disabled", "accounts are not enabled on this server")
		})
		return
	}
	mux.HandleFunc("POST /api/account/register", s.handleAccountRegister)
	mux.HandleFunc("POST /api/account/login", s.handleAccountLogin)
	mux.HandleFunc("POST /api/account/logout", s.handleAccountLogout)
	mux.HandleFunc("GET /api/account/vault", s.handleAccountVaultGet)
	mux.HandleFunc("PUT /api/account/vault", s.handleAccountVaultPut)
	mux.HandleFunc("POST /api/account/password", s.handleAccountPassword)
	mux.HandleFunc("POST /api/account/email", s.handleAccountEmail)
	mux.HandleFunc("POST /api/account/reset/request", s.handleAccountResetRequest)
	mux.HandleFunc("POST /api/account/reset/confirm", s.handleAccountResetConfirm)
}

func (s *Server) handleAccountRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		AuthKey  string `json:"auth_key"`
		Device   string `json:"device"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	user := NormalizeUsername(body.Username)
	if !ValidUsername(user) {
		accountError(w, http.StatusBadRequest, "invalid_username", "username must be 3-32 characters of a-z 0-9 . _ -")
		return
	}
	authKey, ok := decodeAuthKey(body.AuthKey)
	if !ok {
		accountError(w, http.StatusBadRequest, "bad_request", "invalid auth_key")
		return
	}
	email := NormalizeEmail(body.Email)
	a := s.accounts
	now := s.now()
	ipKey := "s:" + clientIP(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case email == "" && a.mailer != nil:
		// Without an address a forgotten password could never be reset.
		accountError(w, http.StatusBadRequest, "email_required", "an e-mail address is required")
		return
	case email != "" && !ValidEmail(email):
		accountError(w, http.StatusBadRequest, "invalid_email", "invalid e-mail address")
		return
	case !a.signup:
		accountError(w, http.StatusForbidden, "signup_closed", "sign-up is closed on this server")
		return
	case a.over(ipKey, signupPerIPLimit, signupPerIPWindow, now):
		accountError(w, http.StatusTooManyRequests, "rate_limited", "too many new accounts from this address, try again later")
		return
	case a.accounts[user] != nil:
		accountError(w, http.StatusConflict, "username_taken", "this username is already taken")
		return
	case len(a.accounts) >= a.max:
		accountError(w, http.StatusForbidden, "full", "this server cannot take more accounts")
		return
	}
	salt, err := randomHex(16)
	if err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	acc := &account{Username: user, Email: email, AuthSalt: salt, AuthHash: hashAuthKey(salt, authKey), Created: now.UnixMilli()}
	token, err := a.newSession(acc, body.Device, now)
	if err == nil {
		err = a.saveMeta(acc)
	}
	if err != nil {
		s.logger.Warn("account create failed", "err", err)
		accountError(w, http.StatusInternalServerError, "internal", "could not save the account")
		return
	}
	a.accounts[user] = acc
	a.hit(ipKey, signupPerIPWindow, now)
	s.logger.Info("account created", "username", user, "accounts", len(a.accounts))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user, "email": email, "token": token, "rev": int64(0)})
}

// checkAuthKey verifies authKey for user and applies the failed sign-in limits. On failure it
// has already written the response. a.mu must be held.
func (a *accountStore) checkAuthKey(w http.ResponseWriter, r *http.Request, user string, authKey []byte, now time.Time) *account {
	ipUserKey := "f:" + clientIP(r) + "|" + user
	userKey := "u:" + user
	if a.over(ipUserKey, loginIPUserLimit, loginIPUserWindow, now) || a.over(userKey, loginUserLimit, loginUserWindow, now) {
		accountError(w, http.StatusTooManyRequests, "rate_limited", "too many failed sign-ins, try again later")
		return nil
	}
	acc := a.accounts[user]
	salt, want := "00", ""
	if acc != nil {
		salt, want = acc.AuthSalt, acc.AuthHash
	}
	got := hashAuthKey(salt, authKey)
	if acc == nil || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		a.hit(ipUserKey, loginIPUserWindow, now)
		a.hit(userKey, loginUserWindow, now)
		accountError(w, http.StatusUnauthorized, "invalid_credentials", "wrong username or password")
		return nil
	}
	return acc
}

func (s *Server) handleAccountLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		AuthKey  string `json:"auth_key"`
		Device   string `json:"device"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	user := NormalizeUsername(body.Username)
	authKey, ok := decodeAuthKey(body.AuthKey)
	if !ok || !ValidUsername(user) {
		accountError(w, http.StatusUnauthorized, "invalid_credentials", "wrong username or password")
		return
	}
	a := s.accounts
	now := s.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	acc := a.checkAuthKey(w, r, user, authKey, now)
	if acc == nil {
		return
	}
	token, err := a.newSession(acc, body.Device, now)
	if err == nil {
		err = a.saveMeta(acc)
	}
	if err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user, "email": acc.Email, "token": token, "rev": acc.VaultRev})
}

func (s *Server) handleAccountLogout(w http.ResponseWriter, r *http.Request) {
	a := s.accounts
	a.mu.Lock()
	defer a.mu.Unlock()
	if acc, i, err := a.session(r, s.now()); err == nil {
		acc.Sessions = append(acc.Sessions[:i], acc.Sessions[i+1:]...)
		_ = a.saveMeta(acc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAccountVaultGet(w http.ResponseWriter, r *http.Request) {
	a := s.accounts
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, _, err := a.session(r, s.now())
	if err != nil {
		accountError(w, http.StatusUnauthorized, "unauthorized", "sign in again")
		return
	}
	if have := r.URL.Query().Get("rev"); have != "" {
		if n, perr := strconv.ParseInt(have, 10, 64); perr == nil && n == acc.VaultRev {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rev": acc.VaultRev, "unchanged": true})
			return
		}
	}
	vault, err := a.readVault(acc)
	if err != nil {
		s.logger.Warn("vault read failed", "username", acc.Username, "err", err)
		accountError(w, http.StatusInternalServerError, "internal", "could not read the address book")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rev": acc.VaultRev, "vault": vault})
}

// readVault returns the stored vault as base64 ("" when the account has none yet).
func (a *accountStore) readVault(acc *account) (string, error) {
	if acc.VaultRev == 0 {
		return "", nil
	}
	b, err := os.ReadFile(a.vaultPath(acc.Username))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// storeVault checks baseRev and the size, writes the vault and bumps the revision. On a
// conflict or an invalid vault it has already written the response. a.mu must be held.
func (a *accountStore) storeVault(w http.ResponseWriter, acc *account, baseRev int64, vaultB64 string, now time.Time) bool {
	if baseRev != acc.VaultRev {
		cur, _ := a.readVault(acc)
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "conflict", "error": "the address book changed on another machine", "rev": acc.VaultRev, "vault": cur})
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(vaultB64)
	if err != nil || len(blob) == 0 {
		accountError(w, http.StatusBadRequest, "bad_request", "invalid vault")
		return false
	}
	if len(blob) > maxVaultBytes {
		accountError(w, http.StatusRequestEntityTooLarge, "too_large", "the address book is too large")
		return false
	}
	if err := writeFileAtomic(a.vaultPath(acc.Username), blob); err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the address book")
		return false
	}
	acc.VaultRev++
	acc.VaultAt = now.UnixMilli()
	return true
}

func (s *Server) handleAccountVaultPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseRev int64  `json:"base_rev"`
		Vault   string `json:"vault"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	a := s.accounts
	now := s.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, _, err := a.session(r, now)
	if err != nil {
		accountError(w, http.StatusUnauthorized, "unauthorized", "sign in again")
		return
	}
	if !a.storeVault(w, acc, body.BaseRev, body.Vault, now) {
		return
	}
	if err := a.saveMeta(acc); err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the address book")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rev": acc.VaultRev})
}

// handleAccountPassword replaces the auth key and, in the same step, the vault re-encrypted
// with the key of the new password. Every other session is signed out: those machines hold
// the old vault key and have to sign in again.
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthKey    string `json:"auth_key"`
		NewAuthKey string `json:"new_auth_key"`
		BaseRev    int64  `json:"base_rev"`
		Vault      string `json:"vault"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	oldKey, ok1 := decodeAuthKey(body.AuthKey)
	newKey, ok2 := decodeAuthKey(body.NewAuthKey)
	if !ok1 || !ok2 {
		accountError(w, http.StatusBadRequest, "bad_request", "invalid auth_key")
		return
	}
	a := s.accounts
	now := s.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, idx, err := a.session(r, now)
	if err != nil {
		accountError(w, http.StatusUnauthorized, "unauthorized", "sign in again")
		return
	}
	if a.checkAuthKey(w, r, acc.Username, oldKey, now) == nil {
		return
	}
	if acc.VaultRev == 0 && body.BaseRev == 0 && body.Vault == "" {
		// No address book stored yet: only the auth key changes.
	} else if !a.storeVault(w, acc, body.BaseRev, body.Vault, now) {
		return
	}
	salt, err := randomHex(16)
	if err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	acc.AuthSalt, acc.AuthHash = salt, hashAuthKey(salt, newKey)
	acc.Sessions = []accountSession{acc.Sessions[idx]}
	if err := a.saveMeta(acc); err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the account")
		return
	}
	s.logger.Info("account password changed", "username", acc.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rev": acc.VaultRev})
}

// handleAccountEmail changes the address reset codes go to. It asks for the current password
// (as auth key) on top of the session, because whoever controls the address controls the account.
func (s *Server) handleAccountEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthKey string `json:"auth_key"`
		Email   string `json:"email"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	authKey, ok := decodeAuthKey(body.AuthKey)
	if !ok {
		accountError(w, http.StatusBadRequest, "bad_request", "invalid auth_key")
		return
	}
	email := NormalizeEmail(body.Email)
	if !ValidEmail(email) {
		accountError(w, http.StatusBadRequest, "invalid_email", "invalid e-mail address")
		return
	}
	a := s.accounts
	now := s.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, _, err := a.session(r, now)
	if err != nil {
		accountError(w, http.StatusUnauthorized, "unauthorized", "sign in again")
		return
	}
	if a.checkAuthKey(w, r, acc.Username, authKey, now) == nil {
		return
	}
	acc.Email = email
	delete(a.resets, acc.Username) // a code mailed to the old address must not work any more
	if err := a.saveMeta(acc); err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": email})
}

func randomDigits(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// 250 is the largest multiple of 10 below 256: bytes above it are redrawn to avoid bias.
	for i := range buf {
		for buf[i] >= 250 {
			var one [1]byte
			if _, err := rand.Read(one[:]); err != nil {
				return "", err
			}
			buf[i] = one[0]
		}
		buf[i] = '0' + buf[i]%10
	}
	return string(buf), nil
}

func hashResetCode(user, code string) string {
	sum := sha256.Sum256([]byte("APN-reset-v1\n" + user + "\n" + code))
	return hex.EncodeToString(sum[:])
}

// handleAccountResetRequest mails a reset code when the username and e-mail address belong to
// the same account. The answer is the same either way, and the mail is sent after the answer,
// so a caller learns nothing about which addresses are registered.
func (s *Server) handleAccountResetRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	a := s.accounts
	if a.mailer == nil {
		accountError(w, http.StatusServiceUnavailable, "reset_unavailable", "this server is not set up to send e-mail")
		return
	}
	user := NormalizeUsername(body.Username)
	email := NormalizeEmail(body.Email)
	now := s.now()
	ipKey := "rr:" + clientIP(r)
	userKey := "ru:" + user

	a.mu.Lock()
	if a.over(ipKey, resetPerIPLimit, resetLimitWindow, now) {
		a.mu.Unlock()
		accountError(w, http.StatusTooManyRequests, "rate_limited", "too many reset requests, try again later")
		return
	}
	a.hit(ipKey, resetLimitWindow, now)
	var to, code string
	acc := a.accounts[user]
	if acc != nil && acc.Email != "" && subtle.ConstantTimeCompare([]byte(acc.Email), []byte(email)) == 1 &&
		!a.over(userKey, resetPerUserLimit, resetLimitWindow, now) {
		if c, err := randomDigits(resetCodeDigits); err == nil {
			a.hit(userKey, resetLimitWindow, now)
			a.resets[user] = &resetCode{hash: hashResetCode(user, c), expires: now.Add(resetCodeTTL)}
			to, code = acc.Email, c
		}
	}
	mailer := a.mailer
	a.mu.Unlock()

	if to != "" {
		go func() {
			subject := "รหัสรีเซ็ตรหัสผ่านบัญชี APN: " + code
			text := "มีคำขอรีเซ็ตรหัสผ่านของบัญชี APN \"" + user + "\"\r\n\r\n" +
				"รหัสรีเซ็ต: " + code + "\r\n\r\n" +
				"รหัสนี้ใช้ได้ " + strconv.Itoa(int(resetCodeTTL/time.Minute)) + " นาที กรอกในแอป APN ที่หน้า \"ลืมรหัสผ่าน\" พร้อมรหัสผ่านใหม่\r\n" +
				"เมื่อรีเซ็ตแล้ว รายชื่อเครื่องที่เก็บไว้บนเซิร์ฟเวอร์จะถูกล้าง และทุกเครื่องต้องเข้าสู่ระบบใหม่ " +
				"รายชื่อบนเครื่องของคุณยังอยู่และจะถูกอัปโหลดกลับเมื่อเข้าสู่ระบบ\r\n\r\n" +
				"ถ้าคุณไม่ได้ขอรีเซ็ต ไม่ต้องทำอะไร รหัสผ่านเดิมยังใช้ได้ตามปกติ\r\n"
			if err := mailer(to, subject, text); err != nil {
				s.logger.Warn("password reset mail failed", "username", user, "err", err)
			} else {
				s.logger.Info("password reset mail sent", "username", user)
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ttl_minutes": int(resetCodeTTL / time.Minute)})
}

// handleAccountResetConfirm sets a new auth key for whoever presents the mailed code. The old
// vault is unreadable from now on and is removed; every session ends.
func (s *Server) handleAccountResetConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username   string `json:"username"`
		Code       string `json:"code"`
		NewAuthKey string `json:"new_auth_key"`
		Device     string `json:"device"`
	}
	if !readAccountBody(w, r, &body) {
		return
	}
	newKey, ok := decodeAuthKey(body.NewAuthKey)
	if !ok {
		accountError(w, http.StatusBadRequest, "bad_request", "invalid auth_key")
		return
	}
	user := NormalizeUsername(body.Username)
	code := normalizeID(body.Code) // digits only: tolerates spaces and dashes typed from the mail
	a := s.accounts
	now := s.now()
	ipKey := "rc:" + clientIP(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.over(ipKey, resetConfirmPerIP, resetLimitWindow, now) {
		accountError(w, http.StatusTooManyRequests, "rate_limited", "too many wrong codes, try again later")
		return
	}
	acc := a.accounts[user]
	rc := a.resets[user]
	valid := acc != nil && rc != nil && !now.After(rc.expires)
	if valid {
		rc.attempts++
		if rc.attempts > resetCodeAttempts {
			delete(a.resets, user)
			valid = false
		}
	}
	if !valid || subtle.ConstantTimeCompare([]byte(rc.hash), []byte(hashResetCode(user, code))) != 1 {
		a.hit(ipKey, resetLimitWindow, now)
		accountError(w, http.StatusUnauthorized, "invalid_code", "the reset code is wrong or has expired")
		return
	}
	delete(a.resets, user)
	salt, err := randomHex(16)
	if err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	acc.AuthSalt, acc.AuthHash = salt, hashAuthKey(salt, newKey)
	acc.Sessions = nil
	acc.VaultRev, acc.VaultAt = 0, 0
	_ = os.Remove(a.vaultPath(user))
	token, err := a.newSession(acc, body.Device, now)
	if err == nil {
		err = a.saveMeta(acc)
	}
	if err != nil {
		accountError(w, http.StatusInternalServerError, "internal", "could not save the account")
		return
	}
	// The address just proved it can receive mail for this account: forget its failed sign-ins.
	delete(a.counters, "u:"+user)
	s.logger.Info("account password reset by e-mail code", "username", user)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": user, "email": acc.Email, "token": token, "rev": int64(0)})
}
