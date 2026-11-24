package bootstrap

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPinnedDownloadsArePinned(t *testing.T) {
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	all := map[string]pinnedDownload{
		"FFmpegWindows": FFmpegWindows, "FFmpegLinuxAMD64": FFmpegLinuxAMD64, "FFmpegLinuxARM64": FFmpegLinuxARM64,
		"Wintun": Wintun, "CloudflaredWinAMD64": CloudflaredWinAMD64, "CloudflaredLinuxAMD64": CloudflaredLinuxAMD64,
		"CloudflaredLinuxARM64": CloudflaredLinuxARM64, "CloudflaredLinuxARM": CloudflaredLinuxARM,
	}
	for name, p := range all {
		if !strings.HasPrefix(p.URL, "https://") || strings.Contains(p.URL, "/latest/") || strings.Contains(p.URL, "-latest-") {
			t.Errorf("%s: not an immutable https URL: %s", name, p.URL)
		}
		if !hexRe.MatchString(p.SHA256) {
			t.Errorf("%s: bad SHA-256 %q", name, p.SHA256)
		}
	}
}

func TestVerifyFileSHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if err := verifyFileSHA256(p, abc); err != nil {
		t.Fatalf("matching hash refused: %v", err)
	}
	if err := verifyFileSHA256(p, strings.ToUpper(abc)); err != nil {
		t.Fatalf("upper-case hash refused: %v", err)
	}
	if err := verifyFileSHA256(p, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong hash accepted")
	}
	if err := verifyFileSHA256(p, ""); err == nil {
		t.Fatal("missing hash accepted")
	}
}
