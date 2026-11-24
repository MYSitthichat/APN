package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Signed updates.
//
// Every release manifest (latest.json) carries, for each platform asset, an Ed25519 signature
// made offline with the APN release key (scripts/signupdate). The public half is compiled in
// below. A manifest served by a compromised rendezvous server, Cloudflare account, CDN or GitHub
// token therefore cannot make clients run another binary: without the private key it cannot
// produce a valid signature for a different version, URL or SHA-256.
//
// Keep the private key offline and backed up. If it is lost, clients can only be moved to a new
// key by installing a build that trusts it manually.

// updatePublicKeys are the trusted release-signing keys (base64 Ed25519 public keys). Listing
// more than one allows rotating to a new key without breaking older clients.
var updatePublicKeys = []string{
	releasePublicKey,
}

// SigPrefix versions the signed message format.
const SigPrefix = "APN-UPDATE-v1"

// SignedMessage is the exact byte string signed for one platform asset of a release.
func SignedMessage(version, platform, assetURL, sha256hex string) []byte {
	return []byte(strings.Join([]string{
		SigPrefix,
		strings.TrimPrefix(strings.TrimSpace(version), "v"),
		platform,
		strings.TrimSpace(assetURL),
		strings.ToLower(strings.TrimSpace(sha256hex)),
	}, "\n"))
}

// Allowed download locations: release assets of the official repository only.
const allowedDownloadPrefix = "https://github.com/MYSitthichat/APN/releases/download/"

// GitHub serves release downloads through redirects to these hosts.
var allowedRedirectHosts = map[string]bool{
	"github.com":                            true,
	"objects.githubusercontent.com":         true,
	"release-assets.githubusercontent.com":  true,
	"github-releases.githubusercontent.com": true,
}

var (
	errNoSignature  = errors.New("ไฟล์อัปเดตไม่มีลายเซ็นของผู้พัฒนา (ยกเลิกเพื่อความปลอดภัย)")
	errBadSignature = errors.New("ลายเซ็นไฟล์อัปเดตไม่ถูกต้อง (ยกเลิกเพื่อความปลอดภัย)")
	errNoHash       = errors.New("ไฟล์อัปเดตไม่มีค่า SHA-256 (ยกเลิกเพื่อความปลอดภัย)")
	errBadURL       = errors.New("ที่อยู่ไฟล์อัปเดตไม่ใช่ GitHub Releases ของ APN (ยกเลิกเพื่อความปลอดภัย)")
)

// verifyAsset checks that an asset is downloadable from the official release location, has a
// SHA-256, and is signed by a trusted release key for exactly this version and platform.
func verifyAsset(version, platform string, a Asset) error {
	if !strings.HasPrefix(strings.TrimSpace(a.URL), allowedDownloadPrefix) {
		return errBadURL
	}
	if len(strings.TrimSpace(a.SHA256)) != 64 {
		return errNoHash
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Sig))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errNoSignature
	}
	msg := SignedMessage(version, platform, a.URL, a.SHA256)
	for _, k := range updatePublicKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return nil
		}
	}
	return errBadSignature
}

// restrictRedirects only follows HTTPS redirects to GitHub's release download hosts.
func restrictRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" || !allowedRedirectHosts[strings.ToLower(req.URL.Hostname())] {
		return errBadURL
	}
	return nil
}

// isAllowedDownloadURL reports whether u is an HTTPS URL under the official release path.
func isAllowedDownloadURL(u string) bool {
	parsed, err := url.Parse(u)
	return err == nil && parsed.Scheme == "https" && strings.HasPrefix(u, allowedDownloadPrefix)
}

// VerifyManifest checks every platform asset of m against the compiled-in release keys and
// returns the failures (empty when all assets are valid). Used by release tooling.
func VerifyManifest(m Manifest) map[string]error {
	bad := map[string]error{}
	for platform, a := range m.Assets {
		if err := verifyAsset(m.Version, platform, a); err != nil {
			bad[platform] = err
		}
	}
	return bad
}
