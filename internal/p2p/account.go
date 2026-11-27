package p2p

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"relayvpn/internal/config"
	"relayvpn/internal/rendezvous"
)

// Account sign-in: carries the remembered devices (names, groups, trusted certificates and
// saved passwords) to every machine the user signs in on.
//
// The rendezvous server stores the list but cannot read it. From the account password this
// machine derives one master key (Argon2id) and from that two independent keys (HKDF):
//
//	auth key   sent to the server to prove who is signing in
//	vault key  encrypts the list (AES-256-GCM); never leaves this machine
//
// The password itself is not stored anywhere and is not sent.
const (
	accountMinPassword = 10
	accountSyncEvery   = 60 * time.Second
	accountKickDelay   = 3 * time.Second
	accountVaultVer    = 1
	maxVaultPlain      = 16 << 20 // refuse to inflate more than this from a (hostile) server
)

// AccountStatus is what the dashboard shows about the sign-in.
type AccountStatus struct {
	Available bool   `json:"available"`          // a rendezvous server is configured
	Server    string `json:"server,omitempty"`   // where the account lives
	Username  string `json:"username,omitempty"` // set when signed in, or when the session ended
	Email     string `json:"email,omitempty"`    // address for password-reset codes
	SignedIn  bool   `json:"signed_in"`          // has a live session
	Syncing   bool   `json:"syncing"`
	LastSync  string `json:"last_sync,omitempty"` // RFC3339
	Error     string `json:"error,omitempty"`     // last sync problem, in Thai
	Devices   int    `json:"devices"`             // devices in the synced list
}

type accountRuntime struct {
	syncing  bool
	lastSync time.Time
	lastErr  string
}

// deriveAccountKeys turns the account password into the auth key (for the server) and the
// vault key (for this machine only). The salt comes from the username, so any machine can
// derive the same keys without asking the server first.
func deriveAccountKeys(username, password string) (authKey, encKey []byte, err error) {
	salt := sha256.Sum256([]byte("APN-account-v1\n" + username))
	master := argon2.IDKey([]byte(password), salt[:], 3, 64*1024, 2, 32)
	authKey, err = hkdf.Key(sha256.New, master, nil, "APN-account-auth-v1", 32)
	if err != nil {
		return nil, nil, err
	}
	encKey, err = hkdf.Key(sha256.New, master, nil, "APN-account-vault-v1", 32)
	if err != nil {
		return nil, nil, err
	}
	return authKey, encKey, nil
}

type vaultDoc struct {
	V     int                 `json:"v"`
	Peers []config.SyncedPeer `json:"peers"`
}

// sealVault compresses and encrypts the address book. Layout: version byte, 12-byte nonce,
// AES-256-GCM ciphertext. The username is bound in as associated data.
func sealVault(encKey []byte, username string, peers []config.SyncedPeer) ([]byte, error) {
	plain, err := json.Marshal(vaultDoc{V: accountVaultVer, Peers: peers})
	if err != nil {
		return nil, err
	}
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{accountVaultVer}, nonce...)
	return gcm.Seal(out, nonce, zbuf.Bytes(), []byte("APN-vault-v1\n"+username)), nil
}

var errVaultKey = errors.New("ถอดรหัสรายชื่อเครื่องไม่ได้ (รหัสผ่านบัญชีอาจถูกเปลี่ยนจากเครื่องอื่น) กรุณาเข้าสู่ระบบใหม่")

func openVault(encKey []byte, username string, blob []byte) ([]config.SyncedPeer, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if blob[0] != accountVaultVer || len(blob) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("รายชื่อเครื่องบนเซิร์ฟเวอร์อยู่ในรูปแบบที่โปรแกรมรุ่นนี้ไม่รู้จัก กรุณาอัปเดตโปรแกรม")
	}
	nonce, ct := blob[1:1+gcm.NonceSize()], blob[1+gcm.NonceSize():]
	zipped, err := gcm.Open(nil, nonce, ct, []byte("APN-vault-v1\n"+username))
	if err != nil {
		return nil, errVaultKey
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(zr, maxVaultPlain+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > maxVaultPlain {
		return nil, errors.New("รายชื่อเครื่องบนเซิร์ฟเวอร์ใหญ่ผิดปกติ")
	}
	var doc vaultDoc
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, err
	}
	return doc.Peers, nil
}

// accountServerOK refuses to send account credentials over plain HTTP, except to this machine.
func accountServerOK(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return errors.New("ยังไม่ได้ตั้งค่าเซิร์ฟเวอร์ Rendezvous จึงใช้ระบบบัญชีไม่ได้")
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("ระบบบัญชีต้องใช้เซิร์ฟเวอร์ Rendezvous ที่เป็น https เท่านั้น")
}

type accountAPIError struct {
	Status int
	Code   string
	Msg    string
}

func (e *accountAPIError) Error() string {
	switch e.Code {
	case "invalid_credentials":
		return "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
	case "username_taken":
		return "ชื่อผู้ใช้นี้มีคนใช้แล้ว"
	case "invalid_username":
		return "ชื่อผู้ใช้ต้องยาว 3-32 ตัว ใช้ได้เฉพาะ a-z 0-9 . _ - และขึ้นต้นด้วยตัวอักษรหรือตัวเลข"
	case "signup_closed":
		return "เซิร์ฟเวอร์นี้ปิดรับสมัครบัญชีใหม่"
	case "full":
		return "เซิร์ฟเวอร์นี้รับบัญชีเพิ่มไม่ได้แล้ว"
	case "rate_limited":
		return "ลองหลายครั้งเกินไป กรุณารอสักครู่แล้วลองใหม่"
	case "unauthorized":
		return "เซสชันหมดอายุหรือถูกยกเลิก กรุณาเข้าสู่ระบบใหม่"
	case "too_large":
		return "รายชื่อเครื่องใหญ่เกินกว่าที่เซิร์ฟเวอร์รับได้"
	case "accounts_disabled":
		return "เซิร์ฟเวอร์ Rendezvous นี้ยังไม่เปิดใช้ระบบบัญชี"
	case "email_required":
		return "กรุณากรอกอีเมล (ใช้รับรหัสรีเซ็ตเมื่อลืมรหัสผ่าน)"
	case "invalid_email":
		return "อีเมลไม่ถูกต้อง"
	case "invalid_code":
		return "รหัสรีเซ็ตไม่ถูกต้องหรือหมดอายุแล้ว กรุณาขอรหัสใหม่"
	case "reset_unavailable":
		return "เซิร์ฟเวอร์นี้ยังไม่ได้ตั้งค่าการส่งอีเมล จึงรีเซ็ตรหัสผ่านทางอีเมลไม่ได้ กรุณาติดต่อผู้ดูแลเซิร์ฟเวอร์"
	}
	if e.Status == http.StatusNotFound {
		return "เซิร์ฟเวอร์ Rendezvous นี้ยังไม่รองรับระบบบัญชี (ต้องอัปเดตเซิร์ฟเวอร์)"
	}
	if e.Msg != "" {
		return "เซิร์ฟเวอร์ตอบกลับ: " + e.Msg
	}
	return "เซิร์ฟเวอร์ตอบกลับ HTTP " + strconv.Itoa(e.Status)
}

type accountReply struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
	Error     string `json:"error"`
	Email     string `json:"email"`
	Token     string `json:"token"`
	Rev       int64  `json:"rev"`
	Vault     string `json:"vault"`
	Unchanged bool   `json:"unchanged"`
}

// accountCall sends one request to the account API. A non-2xx answer comes back as
// *accountAPIError together with the decoded reply (a 409 carries the current vault).
func (n *Node) accountCall(ctx context.Context, server, method, path, bearer string, body any) (accountReply, error) {
	var out accountReply
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return out, err
		}
		rd = bytes.NewReader(b)
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, method, server+path, rd)
	if err != nil {
		return out, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	n.mu.RLock()
	hc := n.rdvClient
	n.mu.RUnlock()
	resp, err := hc.Do(req)
	if err != nil {
		return out, fmt.Errorf("ติดต่อเซิร์ฟเวอร์บัญชีไม่ได้: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, fmt.Errorf("อ่านคำตอบจากเซิร์ฟเวอร์บัญชีไม่ได้: %w", err)
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return out, &accountAPIError{Status: resp.StatusCode, Code: out.Code, Msg: out.Error}
	}
	return out, nil
}

func checkAccountInput(username, password string) (string, error) {
	user := rendezvous.NormalizeUsername(username)
	if !rendezvous.ValidUsername(user) {
		return "", (&accountAPIError{Code: "invalid_username"})
	}
	if utf8.RuneCountInString(password) < accountMinPassword {
		return "", fmt.Errorf("รหัสผ่านบัญชีต้องยาวอย่างน้อย %d ตัวอักษร", accountMinPassword)
	}
	return user, nil
}

func (n *Node) accountServer() (string, error) {
	n.mu.RLock()
	server := n.rendezvousURL
	n.mu.RUnlock()
	if server == "" {
		return "", errors.New("ยังไม่ได้ตั้งค่าเซิร์ฟเวอร์ Rendezvous จึงใช้ระบบบัญชีไม่ได้")
	}
	return server, accountServerOK(server)
}

func accountDeviceLabel(cfgName string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return cfgName
}

// AccountRegister creates an account and signs this machine in to it. The devices already
// remembered here become the account's first address book.
func (n *Node) AccountRegister(ctx context.Context, username, password, email string) error {
	email = rendezvous.NormalizeEmail(email)
	if email == "" {
		return &accountAPIError{Code: "email_required"}
	}
	if !rendezvous.ValidEmail(email) {
		return &accountAPIError{Code: "invalid_email"}
	}
	return n.accountSignIn(ctx, "/api/account/register", username, password, email)
}

// AccountLogin signs this machine in. The account's address book is merged with the devices
// already remembered here.
func (n *Node) AccountLogin(ctx context.Context, username, password string) error {
	return n.accountSignIn(ctx, "/api/account/login", username, password, "")
}

func (n *Node) accountSignIn(ctx context.Context, path, username, password, email string) error {
	user := rendezvous.NormalizeUsername(username)
	if path == "/api/account/register" {
		// The length rule applies to new passwords only; signing in accepts whatever the account has.
		if _, err := checkAccountInput(username, password); err != nil {
			return err
		}
	} else if !rendezvous.ValidUsername(user) || password == "" {
		return &accountAPIError{Code: "invalid_credentials"}
	}
	server, err := n.accountServer()
	if err != nil {
		return err
	}
	authKey, encKey, err := deriveAccountKeys(user, password)
	if err != nil {
		return err
	}
	n.mu.RLock()
	device := accountDeviceLabel(n.cfg.Name)
	n.mu.RUnlock()
	body := map[string]any{
		"username": user,
		"auth_key": base64.StdEncoding.EncodeToString(authKey),
		"device":   device,
	}
	if email != "" {
		body["email"] = email
	}
	rep, err := n.accountCall(ctx, server, http.MethodPost, path, "", body)
	if err != nil {
		return err
	}
	return n.finishSignIn(ctx, server, user, encKey, rep)
}

// finishSignIn stores a fresh session and runs the first sync. The address book starts from
// revision 0 with no base, so whatever this machine remembers is merged with the account.
func (n *Node) finishSignIn(ctx context.Context, server, user string, encKey []byte, rep accountReply) error {
	if rep.Token == "" {
		return errors.New("เซิร์ฟเวอร์ไม่ได้ส่งเซสชันกลับมา")
	}
	n.mu.Lock()
	n.cfg.Account = &config.AccountState{
		Server:   server,
		Username: user,
		Email:    rep.Email,
		Token:    rep.Token,
		EncKey:   base64.StdEncoding.EncodeToString(encKey),
	}
	n.persistConfigLocked()
	n.mu.Unlock()
	n.setAccountRuntime(func(r *accountRuntime) { r.lastErr = ""; r.lastSync = time.Time{} })
	n.logger.Info("account signed in", "username", user, "server", server)
	// The sign-in itself succeeded; a failed first sync is shown as the account's status.
	_ = n.SyncAccount(ctx)
	return nil
}

// AccountResetRequest asks the server to mail a reset code to the account's address. The
// server answers the same whether or not the username and address match an account.
func (n *Node) AccountResetRequest(ctx context.Context, username, email string) error {
	user := rendezvous.NormalizeUsername(username)
	email = rendezvous.NormalizeEmail(email)
	if !rendezvous.ValidUsername(user) {
		return &accountAPIError{Code: "invalid_username"}
	}
	if !rendezvous.ValidEmail(email) {
		return &accountAPIError{Code: "invalid_email"}
	}
	server, err := n.accountServer()
	if err != nil {
		return err
	}
	_, err = n.accountCall(ctx, server, http.MethodPost, "/api/account/reset/request", "", map[string]any{"username": user, "email": email})
	return err
}

// AccountResetConfirm sets a new account password with the mailed code and signs this machine
// in. The list stored on the server was sealed with the forgotten password and is discarded
// there; the devices remembered on this machine are uploaded as the account's new list.
func (n *Node) AccountResetConfirm(ctx context.Context, username, code, newPassword string) error {
	user, err := checkAccountInput(username, newPassword)
	if err != nil {
		return err
	}
	code = NormalizeDeviceID(code) // digits only
	if code == "" {
		return &accountAPIError{Code: "invalid_code"}
	}
	server, err := n.accountServer()
	if err != nil {
		return err
	}
	authKey, encKey, err := deriveAccountKeys(user, newPassword)
	if err != nil {
		return err
	}
	n.mu.RLock()
	device := accountDeviceLabel(n.cfg.Name)
	n.mu.RUnlock()
	rep, err := n.accountCall(ctx, server, http.MethodPost, "/api/account/reset/confirm", "", map[string]any{
		"username":     user,
		"code":         code,
		"new_auth_key": base64.StdEncoding.EncodeToString(authKey),
		"device":       device,
	})
	if err != nil {
		return err
	}
	return n.finishSignIn(ctx, server, user, encKey, rep)
}

// AccountSetEmail changes the address reset codes are mailed to. It needs the account password.
func (n *Node) AccountSetEmail(ctx context.Context, password, email string) error {
	n.mu.RLock()
	a := n.cfg.Account
	if a == nil || a.Token == "" {
		n.mu.RUnlock()
		return errors.New("ยังไม่ได้เข้าสู่ระบบ")
	}
	acct := *a
	n.mu.RUnlock()
	email = rendezvous.NormalizeEmail(email)
	if !rendezvous.ValidEmail(email) {
		return &accountAPIError{Code: "invalid_email"}
	}
	authKey, encKey, err := deriveAccountKeys(acct.Username, password)
	if err != nil {
		return err
	}
	if base64.StdEncoding.EncodeToString(encKey) != acct.EncKey {
		return errors.New("รหัสผ่านบัญชีไม่ถูกต้อง")
	}
	rep, err := n.accountCall(ctx, acct.Server, http.MethodPost, "/api/account/email", acct.Username+":"+acct.Token, map[string]any{
		"auth_key": base64.StdEncoding.EncodeToString(authKey),
		"email":    email,
	})
	if err != nil {
		return err
	}
	n.mu.Lock()
	if cur := n.cfg.Account; cur != nil && cur.Token == acct.Token {
		cur.Email = rep.Email
		n.accountQuiet = true
		n.persistConfigLocked()
		n.accountQuiet = false
	}
	n.mu.Unlock()
	return nil
}

// AccountLogout ends this machine's session. With wipe, the remembered devices and their
// saved passwords are also removed from this machine (they stay in the account).
func (n *Node) AccountLogout(ctx context.Context, wipe bool) error {
	n.accountSyncMu.Lock()
	defer n.accountSyncMu.Unlock()
	n.mu.Lock()
	acct := n.cfg.Account
	n.cfg.Account = nil
	if wipe {
		n.cfg.KnownPeers = nil
		n.presence = make(map[string]peerPresence)
	}
	n.persistConfigLocked()
	n.mu.Unlock()
	n.setAccountRuntime(func(r *accountRuntime) { *r = accountRuntime{} })
	if acct != nil && acct.Token != "" {
		// Best effort: the session also expires on its own.
		_, _ = n.accountCall(ctx, acct.Server, http.MethodPost, "/api/account/logout", acct.Username+":"+acct.Token, nil)
	}
	return nil
}

func (n *Node) setAccountRuntime(f func(*accountRuntime)) {
	n.accountStatMu.Lock()
	f(&n.accountStat)
	n.accountStatMu.Unlock()
}

// accountStatusLocked builds the dashboard status. n.mu must be held (read or write).
func (n *Node) accountStatusLocked() AccountStatus {
	st := AccountStatus{Available: n.rendezvousURL != "", Server: n.rendezvousURL}
	if a := n.cfg.Account; a != nil {
		st.Server = a.Server
		st.Username = a.Username
		st.Email = a.Email
		st.SignedIn = a.Token != ""
		st.Devices = len(a.Base)
	}
	n.accountStatMu.Lock()
	st.Syncing = n.accountStat.syncing
	st.Error = n.accountStat.lastErr
	if !n.accountStat.lastSync.IsZero() {
		st.LastSync = n.accountStat.lastSync.UTC().Format(time.RFC3339)
	}
	n.accountStatMu.Unlock()
	return st
}

// kickAccountSync asks the account loop to sync soon. Called whenever the config is saved.
func (n *Node) kickAccountSync() {
	if n.accountQuiet || n.cfg.Account == nil || n.cfg.Account.Token == "" {
		return
	}
	select {
	case n.accountKick <- struct{}{}:
	default:
	}
}

func (n *Node) accountLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(4 * time.Second):
	}
	_ = n.SyncAccount(ctx)
	ticker := time.NewTicker(accountSyncEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.accountKick:
			// Several changes usually arrive together (connect, then save the password).
			select {
			case <-ctx.Done():
				return
			case <-time.After(accountKickDelay):
			}
			select {
			case <-n.accountKick:
			default:
			}
		}
		_ = n.SyncAccount(ctx)
	}
}

// SyncAccount brings this machine's remembered devices and the account's copy in line.
// It does nothing when signed out.
func (n *Node) SyncAccount(ctx context.Context) error {
	n.accountSyncMu.Lock()
	defer n.accountSyncMu.Unlock()

	n.mu.RLock()
	signedIn := n.cfg.Account != nil && n.cfg.Account.Token != ""
	n.mu.RUnlock()
	if !signedIn {
		return nil
	}
	n.setAccountRuntime(func(r *accountRuntime) { r.syncing = true })
	err := n.syncAccountOnce(ctx)
	var apiErr *accountAPIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized || errors.Is(err, errVaultKey) {
		// The session is gone (signed out elsewhere, password changed, or expired). Keep the
		// username so the dashboard can ask for the password again; keep the local devices.
		n.mu.Lock()
		if a := n.cfg.Account; a != nil {
			a.Token, a.EncKey = "", ""
			n.accountQuiet = true
			n.persistConfigLocked()
			n.accountQuiet = false
		}
		n.mu.Unlock()
	}
	n.setAccountRuntime(func(r *accountRuntime) {
		r.syncing = false
		if err != nil {
			r.lastErr = err.Error()
		} else {
			r.lastErr = ""
			r.lastSync = time.Now()
		}
	})
	if err != nil && ctx.Err() == nil {
		n.logger.Warn("account sync failed", "err", err)
	}
	return err
}

func cloneBase(m map[string]config.SyncedPeer) map[string]config.SyncedPeer {
	out := make(map[string]config.SyncedPeer, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (n *Node) syncAccountOnce(ctx context.Context) error {
	n.mu.RLock()
	a := n.cfg.Account
	if a == nil || a.Token == "" {
		n.mu.RUnlock()
		return nil
	}
	acct := *a
	base := cloneBase(a.Base)
	local := append([]config.KnownPeer(nil), n.cfg.KnownPeers...)
	selfID := n.cfg.DeviceID
	n.mu.RUnlock()

	encKey, err := base64.StdEncoding.DecodeString(acct.EncKey)
	if err != nil || len(encKey) != 32 {
		return errVaultKey
	}
	bearer := acct.Username + ":" + acct.Token

	// Ask only for the revision first when nothing changed here: the usual case.
	path := "/api/account/vault"
	if !localDiffersFromBase(selfID, local, base) {
		path += "?rev=" + strconv.FormatInt(acct.Rev, 10)
	}
	rep, err := n.accountCall(ctx, acct.Server, http.MethodGet, path, bearer, nil)
	if err != nil {
		return err
	}
	if rep.Unchanged {
		return nil
	}
	for attempt := 0; attempt < 4; attempt++ {
		blob, err := base64.StdEncoding.DecodeString(rep.Vault)
		if err != nil {
			return errors.New("เซิร์ฟเวอร์ส่งรายชื่อเครื่องมาในรูปแบบที่อ่านไม่ได้")
		}
		remote, err := openVault(encKey, acct.Username, blob)
		if err != nil {
			return err
		}
		res := mergeAddressBook(selfID, local, base, remote, time.Now())
		rev := rep.Rev
		if res.push {
			sealed, err := sealVault(encKey, acct.Username, res.vault)
			if err != nil {
				return err
			}
			put, err := n.accountCall(ctx, acct.Server, http.MethodPut, "/api/account/vault", bearer, map[string]any{
				"base_rev": rep.Rev,
				"vault":    base64.StdEncoding.EncodeToString(sealed),
			})
			var apiErr *accountAPIError
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
				rep = put // another machine got there first: merge with what it wrote
				continue
			}
			if err != nil {
				return err
			}
			rev = put.Rev
		}
		n.applyAccountMerge(acct.Token, local, res, rev)
		return nil
	}
	return errors.New("รายชื่อเครื่องถูกแก้จากเครื่องอื่นพร้อมกันหลายครั้ง จะลองซิงก์ใหม่ในรอบถัดไป")
}

// applyAccountMerge writes a finished merge into the config. A device the user changed on
// this machine while the sync was talking to the server is left alone and keeps its old base
// entry, so the next sync merges that change instead of overwriting it.
func (n *Node) applyAccountMerge(token string, snapshot []config.KnownPeer, res addressBookMerge, rev int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a := n.cfg.Account
	if a == nil || a.Token != token {
		return // signed out or signed in again meanwhile
	}
	snap := make(map[string]config.SyncedPeer, len(snapshot))
	for _, kp := range snapshot {
		sp := syncedFromKnown(kp)
		snap[sp.DeviceID] = sp
	}
	index := func(id string) int {
		for i := range n.cfg.KnownPeers {
			if NormalizeDeviceID(n.cfg.KnownPeers[i].DeviceID) == id {
				return i
			}
		}
		return -1
	}
	// untouched reports whether the device is still as it was when the sync started.
	untouched := func(id string) bool {
		i := index(id)
		was, had := snap[id]
		if i < 0 || !had {
			return i < 0 && !had
		}
		return sameSynced(syncedFromKnown(n.cfg.KnownPeers[i]), was)
	}
	newBase := res.base
	keepOldBase := func(id string) {
		if old, ok := a.Base[id]; ok {
			newBase[id] = old
		} else {
			delete(newBase, id)
		}
	}
	for _, sp := range res.upserts {
		if !untouched(sp.DeviceID) {
			keepOldBase(sp.DeviceID)
			continue
		}
		if i := index(sp.DeviceID); i >= 0 {
			kp := &n.cfg.KnownPeers[i]
			kp.Name, kp.CustomName, kp.Group = sp.Name, sp.CustomName, sp.Group
			kp.OS, kp.Fingerprint, kp.SavedPassword = sp.OS, sp.Fingerprint, sp.SavedPassword
			kp.LastConnected = sp.LastConnected
		} else {
			n.cfg.KnownPeers = append(n.cfg.KnownPeers, config.KnownPeer{
				DeviceID: sp.DeviceID, Name: sp.Name, CustomName: sp.CustomName, Group: sp.Group, OS: sp.OS,
				Fingerprint: sp.Fingerprint, SavedPassword: sp.SavedPassword, LastConnected: sp.LastConnected,
			})
		}
	}
	for _, id := range res.deletes {
		if !untouched(id) {
			keepOldBase(id)
			continue
		}
		if i := index(id); i >= 0 {
			n.cfg.KnownPeers = append(n.cfg.KnownPeers[:i], n.cfg.KnownPeers[i+1:]...)
			delete(n.presence, id)
		}
	}
	a.Rev = rev
	a.Base = newBase
	n.accountQuiet = true
	n.persistConfigLocked()
	n.accountQuiet = false
}

// AccountChangePassword re-encrypts the address book with the key of the new password and
// replaces the sign-in key on the server in the same step. Every other machine is signed out.
func (n *Node) AccountChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	n.mu.RLock()
	a := n.cfg.Account
	if a == nil || a.Token == "" {
		n.mu.RUnlock()
		return errors.New("ยังไม่ได้เข้าสู่ระบบ")
	}
	acct := *a
	n.mu.RUnlock()
	if utf8.RuneCountInString(newPassword) < accountMinPassword {
		return fmt.Errorf("รหัสผ่านบัญชีต้องยาวอย่างน้อย %d ตัวอักษร", accountMinPassword)
	}
	oldAuth, oldEnc, err := deriveAccountKeys(acct.Username, oldPassword)
	if err != nil {
		return err
	}
	if base64.StdEncoding.EncodeToString(oldEnc) != acct.EncKey {
		return errors.New("รหัสผ่านปัจจุบันไม่ถูกต้อง")
	}
	newAuth, newEnc, err := deriveAccountKeys(acct.Username, newPassword)
	if err != nil {
		return err
	}
	// Upload anything still pending first, so the re-encrypted copy is complete.
	if err := n.SyncAccount(ctx); err != nil {
		return err
	}
	n.accountSyncMu.Lock()
	defer n.accountSyncMu.Unlock()
	bearer := acct.Username + ":" + acct.Token
	rep, err := n.accountCall(ctx, acct.Server, http.MethodGet, "/api/account/vault", bearer, nil)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		vault := ""
		if rep.Rev != 0 {
			blob, err := base64.StdEncoding.DecodeString(rep.Vault)
			if err != nil {
				return errors.New("เซิร์ฟเวอร์ส่งรายชื่อเครื่องมาในรูปแบบที่อ่านไม่ได้")
			}
			peers, err := openVault(oldEnc, acct.Username, blob)
			if err != nil {
				return err
			}
			sealed, err := sealVault(newEnc, acct.Username, peers)
			if err != nil {
				return err
			}
			vault = base64.StdEncoding.EncodeToString(sealed)
		}
		done, err := n.accountCall(ctx, acct.Server, http.MethodPost, "/api/account/password", bearer, map[string]any{
			"auth_key":     base64.StdEncoding.EncodeToString(oldAuth),
			"new_auth_key": base64.StdEncoding.EncodeToString(newAuth),
			"base_rev":     rep.Rev,
			"vault":        vault,
		})
		var apiErr *accountAPIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
			rep = done
			continue
		}
		if err != nil {
			return err
		}
		n.mu.Lock()
		if cur := n.cfg.Account; cur != nil && cur.Token == acct.Token {
			cur.EncKey = base64.StdEncoding.EncodeToString(newEnc)
			if cur.Rev == rep.Rev {
				cur.Rev = done.Rev // only the encryption changed, not the content
			}
			n.accountQuiet = true
			n.persistConfigLocked()
			n.accountQuiet = false
		}
		n.mu.Unlock()
		return nil
	}
	return errors.New("รายชื่อเครื่องถูกแก้จากเครื่องอื่นระหว่างเปลี่ยนรหัสผ่าน กรุณาลองใหม่")
}
