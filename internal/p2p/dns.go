package p2p

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// resilientDialContext first dials using the OS default DNS resolver; if DNS fails (e.g., split-horizon
// corporate DNS for a shared domain or stale negative ISP cache), it transparently resolves the host
// via 1.1.1.1 / DNS-over-HTTPS (port 443) and dials the resolved IP while preserving TLS SNI.
func resilientDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	baseDialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := baseDialer.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || net.ParseIP(host) != nil {
		return nil, err
	}

	// Fallback 1: Public DNS over UDP 1.1.1.1:53
	ips := resolveViaPublicDNS(ctx, host)
	// Fallback 2: Cloudflare DNS-over-HTTPS (HTTPS port 443 — works even if UDP 53 is blocked)
	if len(ips) == 0 {
		ips = resolveViaDoH(ctx, host)
	}
	if len(ips) == 0 {
		return nil, err
	}

	var lastErr error = err
	for _, ip := range ips {
		c, derr := baseDialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if derr == nil {
			return c, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func resolveViaPublicDNS(ctx context.Context, host string) []string {
	rCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	addrs, err := r.LookupHost(rCtx, host)
	if err != nil {
		return nil
	}
	return addrs
}

func resolveViaDoH(ctx context.Context, host string) []string {
	rCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
	defer cancel()

	// Connect directly to 1.1.1.1 IP over TLS 1.3 (valid cert for 1.1.1.1) — zero DNS needed!
	dohURL := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", url.QueryEscape(host))
	req, err := http.NewRequestWithContext(rCtx, http.MethodGet, dohURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")

	hc := &http.Client{
		Timeout: 3500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	var ips []string
	for _, ans := range body.Answer {
		if ans.Type == 1 && net.ParseIP(ans.Data) != nil {
			ips = append(ips, ans.Data)
		}
	}
	return ips
}
