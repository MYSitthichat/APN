package rendezvous

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Signed registration (v1).
//
// Without it, anyone could register another device's 9-digit ID with their own fingerprint,
// UDP addresses and ws_url. Callers then pinned the attacker's certificate and sent their
// password to the attacker. A device now signs register/unregister with the ECDSA P-256 key
// of its TLS certificate, and directories bind each ID to the first key that signs for it.
//
// The signed message is the same in Go (client and self-hosted server) and in the Cloudflare
// Worker (cloudflare-worker/rendezvous-worker.js): the lines below joined by "\n".
// The signature is ECDSA P-256 over SHA-256 in IEEE P1363 form (32-byte r || 32-byte s),
// which is the format WebCrypto verifies.
const (
	SigPrefix = "APN-RDV-v1"

	// SigMaxSkew is how far a signature timestamp may differ from the server clock.
	// It is wide on purpose: a device with a wrong clock must not drop off the directory.
	SigMaxSkew = 24 * time.Hour

	// BindingTTL is how long an ID stays bound to its key after the last signed register.
	BindingTTL = 30 * 24 * time.Hour
)

// SignedMessage builds the exact bytes a device signs for action "register" or "unregister".
func SignedMessage(action, deviceID, fingerprint string, tsMillis int64, wsURL string, udpAddrs []string) []byte {
	return []byte(strings.Join([]string{
		SigPrefix,
		action,
		deviceID,
		strings.ToLower(fingerprint),
		strconv.FormatInt(tsMillis, 10),
		wsURL,
		strings.Join(udpAddrs, ","),
	}, "\n"))
}

// CertFingerprint returns "sha256:<hex>" of a DER certificate (same as p2p.CertFingerprint).
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignMessage signs msg with key and returns the base64 P1363 signature.
func SignMessage(key *ecdsa.PrivateKey, msg []byte, rand interface{ Read([]byte) (int, error) }) (string, error) {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.StdEncoding.EncodeToString(sig), nil
}

var (
	errSigCert        = errors.New("invalid certificate")
	errSigFingerprint = errors.New("certificate does not match fingerprint")
	errSigBad         = errors.New("invalid signature")
	errSigClock       = errors.New("signature timestamp too far from server time")
)

// VerifySignature checks that certB64 hashes to fingerprint, that it holds an ECDSA P-256 key,
// and that sigB64 is that key's signature over msg. tsMillis must be within SigMaxSkew of now.
func VerifySignature(certB64, sigB64, fingerprint string, tsMillis int64, msg []byte, now time.Time) error {
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil || len(der) == 0 || len(der) > 4096 {
		return errSigCert
	}
	if !strings.EqualFold(CertFingerprint(der), fingerprint) {
		return errSigFingerprint
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return errSigCert
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().BitSize != 256 {
		return errSigCert
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return errSigBad
	}
	skew := now.Sub(time.UnixMilli(tsMillis))
	if skew < 0 {
		skew = -skew
	}
	if skew > SigMaxSkew {
		return errSigClock
	}
	h := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errSigBad
	}
	return nil
}
