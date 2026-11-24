package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func withTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := updatePublicKeys
	updatePublicKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	t.Cleanup(func() { updatePublicKeys = old })
	return priv
}

func signedAsset(priv ed25519.PrivateKey, ver, plat, u, sum string) Asset {
	return Asset{URL: u, SHA256: sum, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SignedMessage(ver, plat, u, sum)))}
}

const (
	goodURL = "https://github.com/MYSitthichat/APN/releases/download/v1.3.14/APN-v1.3.14-windows-amd64.exe"
	goodSum = "75b4662480717b0b1e78ffea3c57a354b562d87b53ec49f01de55b86cba0674b"
)

func TestVerifyAssetAcceptsSignedOfficialRelease(t *testing.T) {
	priv := withTestKey(t)
	if err := verifyAsset("1.3.14", "windows-amd64", signedAsset(priv, "1.3.14", "windows-amd64", goodURL, goodSum)); err != nil {
		t.Fatalf("valid release rejected: %v", err)
	}
}

func TestVerifyAssetRejectsTampering(t *testing.T) {
	priv := withTestKey(t)
	a := signedAsset(priv, "1.3.14", "windows-amd64", goodURL, goodSum)
	other := strings.Repeat("a", 64)
	cases := map[string]struct {
		ver, plat string
		a         Asset
		want      error
	}{
		"other version":       {"99.0.0", "windows-amd64", a, errBadSignature},
		"other platform":      {"1.3.14", "linux-amd64", a, errBadSignature},
		"swapped binary hash": {"1.3.14", "windows-amd64", Asset{URL: a.URL, SHA256: other, Sig: a.Sig}, errBadSignature},
		"foreign URL":         {"1.3.14", "windows-amd64", signedAsset(priv, "1.3.14", "windows-amd64", "https://evil.example/x.exe", goodSum), errBadURL},
		"http URL":            {"1.3.14", "windows-amd64", Asset{URL: strings.Replace(goodURL, "https", "http", 1), SHA256: goodSum, Sig: a.Sig}, errBadURL},
		"missing hash":        {"1.3.14", "windows-amd64", Asset{URL: goodURL, Sig: a.Sig}, errNoHash},
		"missing signature":   {"1.3.14", "windows-amd64", Asset{URL: goodURL, SHA256: goodSum}, errNoSignature},
	}
	for name, c := range cases {
		if err := verifyAsset(c.ver, c.plat, c.a); err != c.want {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// A signature from another key is not trusted.
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifyAsset("1.3.14", "windows-amd64", signedAsset(attacker, "1.3.14", "windows-amd64", goodURL, goodSum)); err != errBadSignature {
		t.Errorf("attacker-signed release: got %v, want errBadSignature", err)
	}
}

func TestRestrictRedirects(t *testing.T) {
	ok := []string{"https://objects.githubusercontent.com/x", "https://release-assets.githubusercontent.com/y"}
	bad := []string{"http://objects.githubusercontent.com/x", "https://evil.example/x", "https://github.com.evil.example/x"}
	for _, u := range ok {
		r := &http.Request{URL: mustURL(t, u)}
		if err := restrictRedirects(r, nil); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		r := &http.Request{URL: mustURL(t, u)}
		if err := restrictRedirects(r, nil); err == nil {
			t.Errorf("%s allowed", u)
		}
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCompiledReleaseKeyIsValid(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("releasePublicKey is not a valid Ed25519 public key: %v", err)
	}
}
