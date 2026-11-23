package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	hashPrefix       = "sha256:"
	saltedHashPrefix = "sha256s:"
)

// GenerateToken creates a cryptographically secure random bearer token.
func GenerateToken(numBytes int) (string, error) {
	if numBytes < 24 {
		numBytes = 32
	}
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateDigits returns a cryptographically random numeric string of length n (e.g. 6-digit PIN or 9-digit ID).
// If noLeadingZero is true, the first digit is in 1..9.
func GenerateDigits(n int, noLeadingZero bool) (string, error) {
	if n <= 0 {
		return "", nil
	}
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		min := int64(0)
		if i == 0 && noLeadingZero {
			min = 1
		}
		span := big.NewInt(10 - min)
		v, err := rand.Int(rand.Reader, span)
		if err != nil {
			return "", fmt.Errorf("generate digits: %w", err)
		}
		b.WriteByte(byte('0') + byte(min+v.Int64()))
	}
	return b.String(), nil
}

// HashPassword hashes a user-chosen permanent password with a random 16-byte salt.
func HashPassword(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	sum := sha256.Sum256([]byte(saltHex + ":" + raw))
	return saltedHashPrefix + saltHex + ":" + hex.EncodeToString(sum[:]), nil
}

// HashToken hashes a raw token with SHA-256 for safe storage in server configuration.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hashPrefix + hex.EncodeToString(sum[:])
}

// VerifyToken verifies a presented raw token/password against a stored hash ("sha256s:...", "sha256:...", or raw).
// Constant-time comparison is always used to prevent timing side-channels.
func VerifyToken(presented, stored string) bool {
	if presented == "" || stored == "" {
		return false
	}
	if strings.HasPrefix(stored, saltedHashPrefix) {
		rest := strings.TrimPrefix(stored, saltedHashPrefix)
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			return false
		}
		sum := sha256.Sum256([]byte(parts[0] + ":" + presented))
		actualHex := hex.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(actualHex), []byte(parts[1])) == 1
	}
	if strings.HasPrefix(stored, hashPrefix) {
		expectedHex := strings.TrimPrefix(stored, hashPrefix)
		sum := sha256.Sum256([]byte(presented))
		actualHex := hex.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(actualHex), []byte(expectedHex)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(stored)) == 1
}
