package rendezvous

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig is the outgoing mail server used for password-reset codes. Host and From are
// required; without them the reset-by-email endpoints answer "reset_unavailable".
type SMTPConfig struct {
	Host     string // e.g. "smtp.gmail.com"
	Port     int    // 587 (STARTTLS, default) or 465 (TLS from the first byte)
	Username string // empty: no authentication
	Password string
	From     string // "name@example.com" or "APN <name@example.com>"
}

// Enabled reports whether the server can send mail at all.
func (c SMTPConfig) Enabled() bool {
	return strings.TrimSpace(c.Host) != "" && strings.TrimSpace(c.From) != ""
}

// NormalizeEmail lower-cases and trims an address; ValidEmail checks a normalized one.
func NormalizeEmail(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// ValidEmail accepts a plain "local@domain" address of sane length. Anything that could carry
// a second header line or a display name is refused, since the address goes into mail headers.
func ValidEmail(e string) bool {
	if len(e) < 3 || len(e) > 254 || strings.ContainsAny(e, " \t\r\n<>(),;:\"\\") {
		return false
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e {
		return false
	}
	at := strings.LastIndexByte(e, '@')
	return at > 0 && strings.Contains(e[at+1:], ".") && !strings.HasSuffix(e, ".")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// buildMail renders a UTF-8 text mail. The body is base64, so Thai text survives any relay.
func buildMail(from *mail.Address, to, subject, body string, now time.Time) []byte {
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 {
		domain = from.Address[at+1:]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: <%s>\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}

// sendMail delivers one text mail. The connection must be encrypted (TLS on port 465, STARTTLS
// otherwise) unless the mail server is on this machine.
func sendMail(c SMTPConfig, to, subject, body string) error {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("invalid From address %q: %w", c.From, err)
	}
	if !ValidEmail(NormalizeEmail(to)) {
		return errors.New("invalid recipient address")
	}
	port := c.Port
	if port == 0 {
		port = 587
	}
	host := strings.TrimSpace(c.Host)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	if port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to mail server %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))

	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("mail server greeting: %w", err)
	}
	defer cl.Close()
	if port != 465 {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		} else if !isLoopbackHost(host) {
			return errors.New("mail server does not offer STARTTLS; refusing to send over a plain connection")
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, host)); err != nil {
			return fmt.Errorf("mail server sign-in: %w", err)
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := cl.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(buildMail(from, to, subject, body, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail not accepted: %w", err)
	}
	return cl.Quit()
}

// SendTestMail sends a short message through cfg: used by "apn rdv-server -smtp-test" to check
// the mail settings before users depend on them.
func SendTestMail(cfg SMTPConfig, to string) error {
	if !cfg.Enabled() {
		return errors.New("SMTP is not configured (host and from address are required)")
	}
	return sendMail(cfg, NormalizeEmail(to), "ทดสอบการส่งอีเมลจาก APN Rendezvous Server",
		"อีเมลนี้ยืนยันว่าเซิร์ฟเวอร์ APN ส่งอีเมลได้แล้ว\r\nผู้ใช้จะได้รับรหัสรีเซ็ตรหัสผ่านบัญชีผ่านช่องทางนี้\r\n")
}
