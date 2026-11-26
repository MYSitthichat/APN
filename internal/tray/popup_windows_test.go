//go:build windows

package tray

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestAppWindowArgsIsolatesProfile(t *testing.T) {
	env := func(k string) string {
		if k == "LOCALAPPDATA" {
			return `C:\Users\alice\AppData\Local`
		}
		return ""
	}
	args := appWindowArgs("http://127.0.0.1:8080", env)

	wantProfile := "--user-data-dir=" + filepath.Join(`C:\Users\alice\AppData\Local`, "APN", "AppProfile")
	for _, want := range []string{
		wantProfile,
		"--app=http://127.0.0.1:8080",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-mode",
		"--disable-features=msEdgeStartupBoost",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("expected %q in appWindowArgs, got %v", want, args)
		}
	}
}

func TestAppWindowArgsFallbackToUserProfile(t *testing.T) {
	env := func(k string) string {
		if k == "USERPROFILE" {
			return `C:\Users\bob`
		}
		return ""
	}
	args := appWindowArgs("http://127.0.0.1:8080", env)
	wantProfile := "--user-data-dir=" + filepath.Join(`C:\Users\bob`, "AppData", "Local", "APN", "AppProfile")
	if !slices.Contains(args, wantProfile) {
		t.Fatalf("expected fallback %q in appWindowArgs, got %v", wantProfile, args)
	}
}

func TestAppWindowArgsEmptyEnvOmitsUserDataDir(t *testing.T) {
	args := appWindowArgs("http://127.0.0.1:8080", func(string) string { return "" })
	for _, a := range args {
		if len(a) >= len("--user-data-dir=") && a[:len("--user-data-dir=")] == "--user-data-dir=" {
			t.Fatalf("did not expect --user-data-dir when env is empty, got %v", args)
		}
	}
}
