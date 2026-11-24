//go:build windows

package vpn

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStageWintunBeside(t *testing.T) {
	base := t.TempDir()
	binDir := filepath.Join(base, "bin")
	exeDir := filepath.Join(base, "app")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	payload := []byte("fake-wintun-dll-binary-payload-v1")
	src := filepath.Join(binDir, "wintun.dll")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	// First call copies wintun.dll beside exeDir
	if err := stageWintunBeside(src, exeDir); err != nil {
		t.Fatalf("stageWintunBeside failed: %v", err)
	}
	dst := filepath.Join(exeDir, "wintun.dll")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("expected staged wintun.dll at %s: %v", dst, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("staged payload mismatch: got %q want %q", got, payload)
	}

	// Second call is a clean no-op (same size)
	if err := stageWintunBeside(src, exeDir); err != nil {
		t.Fatalf("second stageWintunBeside failed: %v", err)
	}

	// Same path is a clean no-op
	if err := stageWintunBeside(dst, exeDir); err != nil {
		t.Fatalf("same-dir stageWintunBeside failed: %v", err)
	}
}
