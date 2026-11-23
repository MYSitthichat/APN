package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ServerTLSConfig creates a strict TLS 1.3 server configuration from PEM cert and key files.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// ClientTLSConfig creates a strict TLS 1.3 client configuration.
// If caFile is provided, that CA is pinned as the trust root; otherwise system root CAs are used.
func ClientTLSConfig(caFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("invalid CA PEM in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// GenerateDevPKI creates a private ECDSA P-256 Root CA and a Server TLS certificate
// signed by that CA for the provided hostnames and IP addresses.
func GenerateDevPKI(outDir string, hosts []string) (caCertPath, serverCertPath, serverKeyPath string, err error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("create cert dir: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate CA key: %w", err)
	}

	caSerial, err := randSerial()
	if err != nil {
		return "", "", "", err
	}

	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"RelayVPN Private CA"},
			CommonName:   "RelayVPN Root CA",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create CA cert: %w", err)
	}

	caCertPath = filepath.Join(outDir, "ca.crt")
	if err := writePEM(caCertPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return "", "", "", err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate server key: %w", err)
	}

	srvSerial, err := randSerial()
	if err != nil {
		return "", "", "", err
	}

	srvTemplate := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			Organization: []string{"RelayVPN"},
			CommonName:   "RelayVPN Server",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			srvTemplate.IPAddresses = append(srvTemplate.IPAddresses, ip)
		} else if h != "" {
			srvTemplate.DNSNames = append(srvTemplate.DNSNames, h)
		}
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", "", "", err
	}

	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create server cert: %w", err)
	}

	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal server key: %w", err)
	}

	serverCertPath = filepath.Join(outDir, "server.crt")
	serverKeyPath = filepath.Join(outDir, "server.key")

	if err := writePEM(serverCertPath, "CERTIFICATE", srvDER, 0o644); err != nil {
		return "", "", "", err
	}
	if err := writePEM(serverKeyPath, "EC PRIVATE KEY", srvKeyDER, 0o600); err != nil {
		return "", "", "", err
	}

	return caCertPath, serverCertPath, serverKeyPath, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return n, nil
}

func writePEM(path, blockType string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		return fmt.Errorf("encode PEM %s: %w", path, err)
	}
	return nil
}
