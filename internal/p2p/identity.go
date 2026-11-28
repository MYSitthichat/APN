package p2p

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// P2PALPN identifies RelayVPN P2P QUIC TLS 1.3 streams.
	P2PALPN      = "relayvpn-p2p/1"
	ticketPrefix = "RVPN1-"
)

// PeerIdentity holds this node's persistent ECDSA P-256 TLS 1.3 certificate and SHA-256 fingerprint.
type PeerIdentity struct {
	Cert        tls.Certificate
	Fingerprint string // "sha256:<hex>"
}

// PeerTicket is a compact copy-pasteable invite containing everything needed for zero-VPS P2P pairing.
type PeerTicket struct {
	PeerID      string   `json:"id"`
	Name        string   `json:"name"`
	OS          string   `json:"os,omitempty"`
	Fingerprint string   `json:"fp"`
	PairSecret  string   `json:"sec"`
	UDPAddrs    []string `json:"udp,omitempty"` // STUN public IP:Port + LAN IP:Port
	WSURL       string   `json:"ws,omitempty"`  // optional direct ws:// / wss:// (e.g. cloudflared)
}

// LoadOrCreateIdentity loads an existing peer TLS keypair or creates a fresh ECDSA P-256 identity.
func LoadOrCreateIdentity(certPath, keyPath, commonName string) (*PeerIdentity, error) {
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				cert, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err == nil && len(cert.Certificate) > 0 {
					return &PeerIdentity{
						Cert:        cert,
						Fingerprint: CertFingerprint(cert.Certificate[0]),
					}, nil
				}
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate peer key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if commonName == "" {
		commonName = "relayvpn-peer"
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"RelayVPN P2P"},
			CommonName:   commonName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create peer cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if certPath != "" && keyPath != "" {
		_ = os.MkdirAll(filepath.Dir(certPath), 0o700)
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &PeerIdentity{
		Cert:        tlsCert,
		Fingerprint: CertFingerprint(der),
	}, nil
}

// CertFingerprint returns "sha256:<hex>" of a raw DER X.509 certificate.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ServerTLSConfig returns a strict TLS 1.3 QUIC listener config using this peer's identity.
func (id *PeerIdentity) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.Cert},
		// "h3" first: new peers use it, so the handshake looks like HTTP/3 (stealth.go).
		NextProtos: []string{alpnHTTP3, P2PALPN},
		ClientAuth: tls.RequireAnyClientCert,
	}
}

// ClientTLSConfig returns a strict TLS 1.3 QUIC dialer config that pins the expected peer certificate fingerprint.
func (id *PeerIdentity) ClientTLSConfig(expectedFingerprint string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id.Cert},
		NextProtos:         []string{alpnHTTP3}, // legacy P2PALPN is retried for older peers
		InsecureSkipVerify: true,                // Verified explicitly via SHA-256 fingerprint pinning below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer presented no TLS certificate")
			}
			actual := CertFingerprint(rawCerts[0])
			if expectedFingerprint != "" && !strings.EqualFold(actual, expectedFingerprint) {
				return fmt.Errorf("peer certificate fingerprint mismatch: got %s, want %s", actual, expectedFingerprint)
			}
			return nil
		},
	}
}

// EncodeTicket serializes a PeerTicket to a compact copy-pasteable string.
func EncodeTicket(t PeerTicket) string {
	b, _ := json.Marshal(t)
	return ticketPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeTicket parses a PeerTicket string.
func DecodeTicket(raw string) (PeerTicket, error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, ticketPrefix) {
		return PeerTicket{}, errors.New("invalid peer ticket format (must start with RVPN1-)")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, ticketPrefix))
	if err != nil {
		return PeerTicket{}, fmt.Errorf("decode peer ticket: %w", err)
	}
	var t PeerTicket
	if err := json.Unmarshal(data, &t); err != nil {
		return PeerTicket{}, fmt.Errorf("parse peer ticket: %w", err)
	}
	if t.PeerID == "" {
		return PeerTicket{}, errors.New("peer ticket missing peer id")
	}
	return t, nil
}
