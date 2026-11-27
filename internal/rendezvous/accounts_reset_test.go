package rendezvous

import (
	"bufio"
	"encoding/base64"
	"mime"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type sentMail struct{ to, subject, body string }

// withMailer makes the server "send" reset mail into a channel.
func withMailer(srv *Server) chan sentMail {
	ch := make(chan sentMail, 16)
	srv.accounts.mailer = func(to, subject, body string) error {
		ch <- sentMail{to, subject, body}
		return nil
	}
	return ch
}

var resetCodeRe = regexp.MustCompile(`\b\d{8}\b`)

func waitMail(t *testing.T, ch chan sentMail) sentMail {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no reset mail was sent")
		return sentMail{}
	}
}

func noMail(t *testing.T, ch chan sentMail) {
	t.Helper()
	select {
	case m := <-ch:
		t.Fatalf("unexpected mail to %s", m.to)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestAccountResetByEmail(t *testing.T) {
	dir := t.TempDir()
	srv, ts := newAccountServer(t, dir, true)
	mails := withMailer(srv)

	// With mail configured, an account needs an address, and it has to be a plain one.
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 400 || r.Code != "email_required" {
		t.Fatalf("register without e-mail: status %d code %q", st, r.Code)
	}
	for _, bad := range []string{"malee", "a@b", "malee@example.com\r\nBcc: x@evil.test", "Malee <malee@example.com>", "a b@example.com"} {
		if st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1), "email": bad}); st != 400 || r.Code != "invalid_email" {
			t.Errorf("e-mail %q: status %d code %q, want 400 invalid_email", bad, st, r.Code)
		}
	}
	st, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1), "email": " Malee@Example.com "})
	if st != 200 {
		t.Fatalf("register: status %d %+v", st, r)
	}
	oldBearer := "malee:" + r.Token
	vault := base64.StdEncoding.EncodeToString([]byte("sealed-with-the-forgotten-password"))
	if st, _ := acctCall(t, ts.URL, "PUT", "/api/account/vault", oldBearer, map[string]any{"base_rev": 0, "vault": vault}); st != 200 {
		t.Fatalf("put vault: status %d", st)
	}

	// A request with the wrong address, or for nobody, answers the same and mails nothing.
	for _, body := range []map[string]any{
		{"username": "malee", "email": "someone@else.test"},
		{"username": "ghost", "email": "malee@example.com"},
	} {
		if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", body); st != 200 {
			t.Fatalf("reset request %v: status %d, want 200", body, st)
		}
	}
	noMail(t, mails)

	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "Malee", "email": "MALEE@example.com"}); st != 200 {
		t.Fatalf("reset request: status %d", st)
	}
	m := waitMail(t, mails)
	code := resetCodeRe.FindString(m.body)
	if m.to != "malee@example.com" || code == "" || !strings.Contains(m.subject, code) {
		t.Fatalf("reset mail: to %q subject %q, code %q", m.to, m.subject, code)
	}

	wrong := "00000000"
	if wrong == code {
		wrong = "11111111"
	}
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": wrong, "new_auth_key": testAuthKey(2)}); st != 401 || r.Code != "invalid_code" {
		t.Fatalf("wrong code: status %d code %q", st, r.Code)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 200 {
		t.Fatalf("a wrong code must leave the account as it was; login status %d", st)
	}

	// The code typed with a space, as people copy it from a mail.
	st, r = acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": code[:4] + " " + code[4:], "new_auth_key": testAuthKey(2), "device": "new-pc"})
	if st != 200 || r.Token == "" || r.Rev != 0 {
		t.Fatalf("confirm: status %d %+v", st, r)
	}
	newBearer := "malee:" + r.Token

	if st, _ := acctCall(t, ts.URL, "GET", "/api/account/vault", oldBearer, nil); st != 401 {
		t.Fatalf("old session after reset: status %d, want 401", st)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 401 {
		t.Fatalf("old password after reset: status %d, want 401", st)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/login", "", map[string]any{"username": "malee", "auth_key": testAuthKey(2)}); st != 200 {
		t.Fatalf("new password after reset: status %d, want 200", st)
	}
	// The vault sealed with the lost key is gone, and the account starts again at revision 0.
	if st, r := acctCall(t, ts.URL, "GET", "/api/account/vault", newBearer, nil); st != 200 || r.Vault != "" || r.Rev != 0 {
		t.Fatalf("vault after reset: status %d %+v", st, r)
	}
	if _, err := os.Stat(filepath.Join(dir, "u-malee.vault")); !os.IsNotExist(err) {
		t.Fatalf("vault file still on disk after reset (err = %v)", err)
	}
	if st, r := acctCall(t, ts.URL, "PUT", "/api/account/vault", newBearer, map[string]any{"base_rev": 0, "vault": vault}); st != 200 || r.Rev != 1 {
		t.Fatalf("first upload after reset: status %d %+v", st, r)
	}
	// A code works once.
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": code, "new_auth_key": testAuthKey(3)}); st != 401 {
		t.Fatalf("code reuse: status %d, want 401", st)
	}
}

func TestAccountResetCodeLimits(t *testing.T) {
	srv, ts := newAccountServer(t, t.TempDir(), true)
	mails := withMailer(srv)
	now := time.Now()
	srv.now = func() time.Time { return now }
	acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1), "email": "malee@example.com"})
	request := func() string {
		acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "malee", "email": "malee@example.com"})
		return resetCodeRe.FindString(waitMail(t, mails).body)
	}

	// Five wrong guesses use the code up.
	code := request()
	for i := 0; i < resetCodeAttempts; i++ {
		acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": "99999999", "new_auth_key": testAuthKey(2)})
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": code, "new_auth_key": testAuthKey(2)}); st != 401 {
		t.Fatalf("right code after %d wrong guesses: status %d, want 401", resetCodeAttempts, st)
	}

	// A code expires.
	code = request()
	now = now.Add(resetCodeTTL + time.Second)
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": code, "new_auth_key": testAuthKey(2)}); st != 401 {
		t.Fatalf("expired code: status %d, want 401", st)
	}

	// A newer code replaces the older one; then the hourly limit per account stops further mail.
	first := request() // third mail this hour
	if resetPerUserLimit != 3 {
		t.Fatalf("test assumes 3 mails per hour, limit is %d", resetPerUserLimit)
	}
	acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "malee", "email": "malee@example.com"})
	noMail(t, mails)
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/reset/confirm", "", map[string]any{"username": "malee", "code": first, "new_auth_key": testAuthKey(2)}); st != 200 {
		t.Fatalf("latest code: status %d, want 200", st)
	}
}

func TestAccountResetNeedsMailSettings(t *testing.T) {
	_, ts := newAccountServer(t, t.TempDir(), true)
	// No SMTP: sign-up works without an address, and reset says plainly that it cannot.
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1)}); st != 200 {
		t.Fatalf("register without mail settings: status %d", st)
	}
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "malee", "email": "malee@example.com"}); st != 503 || r.Code != "reset_unavailable" {
		t.Fatalf("reset without mail settings: status %d code %q", st, r.Code)
	}
}

func TestAccountChangeEmail(t *testing.T) {
	srv, ts := newAccountServer(t, t.TempDir(), true)
	mails := withMailer(srv)
	_, r := acctCall(t, ts.URL, "POST", "/api/account/register", "", map[string]any{"username": "malee", "auth_key": testAuthKey(1), "email": "old@example.com"})
	bearer := "malee:" + r.Token

	if st, r := acctCall(t, ts.URL, "POST", "/api/account/email", bearer, map[string]any{"auth_key": testAuthKey(9), "email": "new@example.com"}); st != 401 || r.Code != "invalid_credentials" {
		t.Fatalf("change e-mail with a wrong password: status %d code %q", st, r.Code)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/email", "", map[string]any{"auth_key": testAuthKey(1), "email": "new@example.com"}); st != 401 {
		t.Fatalf("change e-mail without a session: status %d, want 401", st)
	}
	if st, r := acctCall(t, ts.URL, "POST", "/api/account/email", bearer, map[string]any{"auth_key": testAuthKey(1), "email": "not-an-address"}); st != 400 || r.Code != "invalid_email" {
		t.Fatalf("change to an invalid e-mail: status %d code %q", st, r.Code)
	}
	if st, _ := acctCall(t, ts.URL, "POST", "/api/account/email", bearer, map[string]any{"auth_key": testAuthKey(1), "email": "New@Example.com"}); st != 200 {
		t.Fatalf("change e-mail: status %d", st)
	}
	acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "malee", "email": "old@example.com"})
	noMail(t, mails)
	acctCall(t, ts.URL, "POST", "/api/account/reset/request", "", map[string]any{"username": "malee", "email": "new@example.com"})
	if m := waitMail(t, mails); m.to != "new@example.com" {
		t.Fatalf("reset mail went to %q", m.to)
	}
}

func TestValidEmail(t *testing.T) {
	for _, ok := range []string{"a@b.co", "first.last+tag@sub.example.com", "psms_center-01@example.co.th"} {
		if !ValidEmail(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a@b", "@example.com", "a@", "a@example.com.", "a b@example.com", "a@example.com\nBcc: x@y.z",
		"Name <a@example.com>", "a@example.com,b@example.com", strings.Repeat("a", 250) + "@example.com"} {
		if ValidEmail(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestSendMailToLocalServer speaks real SMTP to a throwaway server on loopback and checks the
// envelope and the message a mail client would show.
func TestSendMailToLocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type received struct{ from, to, data string }
	got := make(chan received, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rd := bufio.NewReader(conn)
		say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		say("220 test ESMTP")
		var rec received
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 test")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				rec.from = strings.TrimSpace(line[len("MAIL FROM:"):])
				say("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				rec.to = strings.TrimSpace(line[len("RCPT TO:"):])
				say("250 ok")
			case cmd == "DATA":
				say("354 go ahead")
				var b strings.Builder
				for {
					l, err := rd.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				rec.data = b.String()
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				got <- rec
				return
			default:
				say("502 not implemented")
			}
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	cfg := SMTPConfig{Host: "127.0.0.1", Port: port, From: "APN <noreply@example.com>"}
	if err := sendMail(cfg, "malee@example.com", "รหัสรีเซ็ต: 12345678", "รหัสรีเซ็ต: 12345678\r\nใช้ได้ 15 นาที\r\n"); err != nil {
		t.Fatalf("sendMail: %v", err)
	}
	var rec received
	select {
	case rec = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("the mail server did not receive a complete message")
	}
	if !strings.Contains(rec.from, "<noreply@example.com>") || !strings.Contains(rec.to, "<malee@example.com>") {
		t.Fatalf("envelope: from %q to %q", rec.from, rec.to)
	}
	head, body, ok := strings.Cut(rec.data, "\r\n\r\n")
	if !ok {
		t.Fatalf("message has no header/body separator:\n%s", rec.data)
	}
	var subject string
	for _, h := range strings.Split(head, "\r\n") {
		if v, found := strings.CutPrefix(h, "Subject: "); found {
			subject, _ = new(mime.WordDecoder).DecodeHeader(v)
		}
	}
	if subject != "รหัสรีเซ็ต: 12345678" {
		t.Fatalf("subject decodes to %q", subject)
	}
	if !strings.Contains(head, "To: <malee@example.com>") || !strings.Contains(head, "charset=utf-8") || !strings.Contains(head, "Message-ID: <") {
		t.Fatalf("headers:\n%s", head)
	}
	text, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil || !strings.Contains(string(text), "ใช้ได้ 15 นาที") {
		t.Fatalf("body decodes to %q (err %v)", text, err)
	}

	// A mail server elsewhere must offer encryption; this one does not, so nothing is sent to it.
	if err := sendMail(SMTPConfig{Host: "192.0.2.1", Port: 1, From: "a@example.com"}, "not an address", "s", "b"); err == nil {
		t.Fatal("an invalid recipient was accepted")
	}
	if (SMTPConfig{Host: "smtp.example.com"}).Enabled() || !cfg.Enabled() {
		t.Fatal("Enabled() must need both a host and a From address")
	}
}
