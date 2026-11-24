// Command signupdate creates the APN release-signing key and signs release manifests.
//
//	go run ./scripts/signupdate -keygen -key <file>      # once: writes the private key, prints the public key
//	go run ./scripts/signupdate -sign dist/latest.json -key <file>
//
// The private key must stay offline (never in the repository). The public key goes into
// internal/updater/release_key.go.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"relayvpn/internal/updater"
)

func main() {
	keygen := flag.Bool("keygen", false, "generate a new Ed25519 release key")
	keyPath := flag.String("key", defaultKeyPath(), "private key file")
	sign := flag.String("sign", "", "latest.json to sign in place")
	verify := flag.String("verify", "", "latest.json to check against the release key compiled into APN")
	flag.Parse()

	var err error
	switch {
	case *keygen:
		err = runKeygen(*keyPath)
	case *sign != "":
		err = runSign(*sign, *keyPath)
	case *verify != "":
		err = runVerify(*verify)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "signupdate:", err)
		os.Exit(1)
	}
}

func defaultKeyPath() string {
	if p := os.Getenv("APN_UPDATE_KEY"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".apn-release", "update-signing.key")
}

func runKeygen(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a release key", path)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("private key:", path)
	fmt.Println("public key: ", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("release key not found (%w); see scripts/signupdate", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid release key file")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func runSign(manifestPath, keyPath string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM written by PowerShell
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	version, _ := m["version"].(string)
	assets, _ := m["assets"].(map[string]any)
	if version == "" || len(assets) == 0 {
		return errors.New("manifest has no version or assets")
	}
	for platform, v := range assets {
		a, ok := v.(map[string]any)
		if !ok {
			continue
		}
		url, _ := a["url"].(string)
		sum, _ := a["sha256"].(string)
		if url == "" || len(sum) != 64 {
			return fmt.Errorf("asset %s has no url or sha256", platform)
		}
		a["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, updater.SignedMessage(version, platform, url, sum)))
	}
	m["sig_alg"] = updater.SigPrefix + "/ed25519"
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %d assets of %s v%s\n", len(assets), manifestPath, version)
	return nil
}

func runVerify(manifestPath string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var m updater.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if len(m.Assets) == 0 {
		return errors.New("manifest has no assets")
	}
	if bad := updater.VerifyManifest(m); len(bad) > 0 {
		for k, e := range bad {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", k, e)
		}
		return fmt.Errorf("%d of %d assets fail verification", len(bad), len(m.Assets))
	}
	fmt.Printf("all %d assets of v%s verify against the compiled-in release key\n", len(m.Assets), m.Version)
	return nil
}
