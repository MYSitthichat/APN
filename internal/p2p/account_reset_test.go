package p2p

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/config"
	"relayvpn/internal/rendezvous"
)

// mailSink is a throwaway SMTP server on loopback. It hands each message's decoded text to
// the test, so the reset code travels the same way it does in production: server to mailbox.
func mailSink(t *testing.T) (port int, bodies chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	bodies = make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				rd := bufio.NewReader(conn)
				say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				say("220 sink ESMTP")
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
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
						_, body, _ := strings.Cut(b.String(), "\r\n\r\n")
						text, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
						bodies <- string(text)
						say("250 queued")
					case cmd == "QUIT":
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return port, bodies
}

func TestAccountForgotPassword(t *testing.T) {
	port, mails := mailSink(t)
	srv := rendezvous.NewServer(rendezvous.Options{
		AccountsDir: t.TempDir(), AccountSignup: true, RatePerMin: -1,
		SMTP: rendezvous.SMTPConfig{Host: "127.0.0.1", Port: port, From: "APN <noreply@example.com>"},
	})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	ctx := context.Background()
	const forgotten, fresh = "the password nobody remembers", "a brand new password"

	// Machine A holds the list and is signed in.
	a := newAccountTestNode(t, hs.URL,
		config.KnownPeer{DeviceID: "111111111", Name: "ห้องเซิร์ฟเวอร์", CustomName: true, Group: "งาน", SavedPassword: "host-pass-1", Fingerprint: "sha256:aa11"},
		config.KnownPeer{DeviceID: "222222222", Name: "DESKTOP-B", SavedPassword: "host-pass-2"},
	)
	if err := a.AccountRegister(ctx, "somchai", forgotten, ""); err == nil {
		t.Fatal("sign-up without an e-mail address was accepted")
	}
	if err := a.AccountRegister(ctx, "somchai", forgotten, "not-an-address"); err == nil {
		t.Fatal("sign-up with an invalid e-mail address was accepted")
	}
	if err := a.AccountRegister(ctx, "somchai", forgotten, "Somchai@Example.com"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if st := a.Snapshot0(); st.Email != "somchai@example.com" || st.Devices != 2 {
		t.Fatalf("status on A: %+v", st)
	}

	// Machine C is new. The user forgot the password and asks for a reset there.
	c := newAccountTestNode(t, hs.URL)
	if err := c.AccountResetRequest(ctx, "somchai", "wrong@example.com"); err != nil {
		t.Fatalf("a request with the wrong address must look the same as a good one, got %v", err)
	}
	select {
	case <-mails:
		t.Fatal("a reset mail went out for the wrong address")
	case <-time.After(200 * time.Millisecond):
	}
	if err := c.AccountResetRequest(ctx, "somchai", "somchai@example.com"); err != nil {
		t.Fatalf("reset request: %v", err)
	}
	var text string
	select {
	case text = <-mails:
	case <-time.After(5 * time.Second):
		t.Fatal("no reset mail arrived")
	}
	code := regexp.MustCompile(`\b\d{8}\b`).FindString(text)
	if code == "" || !strings.Contains(text, "somchai") {
		t.Fatalf("reset mail has no code or no username:\n%s", text)
	}

	if err := c.AccountResetConfirm(ctx, "somchai", "00000000", fresh); err == nil || !strings.Contains(err.Error(), "รหัสรีเซ็ต") {
		t.Fatalf("wrong code: err = %v", err)
	}
	if err := c.AccountResetConfirm(ctx, "somchai", code, "short"); err == nil {
		t.Fatal("a too-short new password was accepted")
	}
	if err := c.AccountResetConfirm(ctx, "somchai", code[:4]+"-"+code[4:], fresh); err != nil {
		t.Fatalf("reset confirm: %v", err)
	}
	if st := c.Snapshot0(); !st.SignedIn || st.Username != "somchai" || st.Email != "somchai@example.com" || st.Devices != 0 || st.Error != "" {
		t.Fatalf("status on C right after the reset: %+v", st)
	}

	// A's session ended with the reset. Its list is untouched and comes back into the account
	// once A signs in with the new password; then C receives it.
	if err := a.SyncAccount(ctx); err == nil {
		t.Fatal("A still synced after the password was reset")
	}
	if st := a.Snapshot0(); st.SignedIn {
		t.Fatalf("A is still signed in after the reset: %+v", st)
	}
	if _, ok := knownByID(a, "111111111"); !ok {
		t.Fatal("A lost its devices when the password was reset")
	}
	if err := a.AccountLogin(ctx, "somchai", forgotten); err == nil {
		t.Fatal("the forgotten password still signs in")
	}
	if err := a.AccountLogin(ctx, "somchai", fresh); err != nil {
		t.Fatalf("login on A with the new password: %v", err)
	}
	if err := c.SyncAccount(ctx); err != nil {
		t.Fatalf("sync on C: %v", err)
	}
	got, ok := knownByID(c, "111111111")
	if !ok || got.Name != "ห้องเซิร์ฟเวอร์" || got.Group != "งาน" || got.SavedPassword != "host-pass-1" || got.Fingerprint != "sha256:aa11" {
		t.Fatalf("device 1 on C after A signed in again: %+v (found %v)", got, ok)
	}
	if kp, ok := knownByID(c, "222222222"); !ok || kp.SavedPassword != "host-pass-2" {
		t.Fatalf("device 2 on C: %+v (found %v)", kp, ok)
	}

	// The address can be changed, with the password.
	if err := c.AccountSetEmail(ctx, "not the password", "new@example.com"); err == nil {
		t.Fatal("e-mail change with a wrong password was accepted")
	}
	if err := c.AccountSetEmail(ctx, fresh, "New@Example.com"); err != nil {
		t.Fatalf("e-mail change: %v", err)
	}
	if st := c.Snapshot0(); st.Email != "new@example.com" {
		t.Fatalf("status on C after the e-mail change: %+v", st)
	}
}

func TestAccountForgotPasswordWithoutMailSettings(t *testing.T) {
	srv := rendezvous.NewServer(rendezvous.Options{AccountsDir: t.TempDir(), AccountSignup: true, RatePerMin: -1})
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	n := newAccountTestNode(t, hs.URL)
	err := n.AccountResetRequest(context.Background(), "somchai", "somchai@example.com")
	if err == nil || !strings.Contains(err.Error(), "ส่งอีเมล") {
		t.Fatalf("err = %v, want a message about mail not being set up", err)
	}
}
