package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
	"testing"
)

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMergePeerConfigNewerUserPasswordAndNamesWin(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user.json")
	sys := filepath.Join(dir, "sys.json")
	writeJSONFile(t, sys, map[string]any{
		"device_id":               "595514895",
		"ui_addr":                 "127.0.0.1:18480",
		"permanent_password_hash": "old-hash",
		"require_approval":        true,
		"known_peers": []any{
			map[string]any{"device_id": "111", "name": "host-111"},
			map[string]any{"device_id": "222", "name": "only-in-service"},
		},
	})
	writeJSONFile(t, user, map[string]any{
		"device_id":               "595514895",
		"permanent_password_hash": "new-hash",
		"require_approval":        false,
		"known_peers": []any{
			map[string]any{"device_id": "111", "name": "My Office PC", "custom_name": true},
			map[string]any{"device_id": "333", "name": "only-in-user"},
		},
	})

	changed, err := mergePeerConfig(user, sys, true, false)
	if err != nil || !changed {
		t.Fatalf("merge changed=%v err=%v", changed, err)
	}
	got := readJSONFile(t, sys)
	if got["permanent_password_hash"] != "new-hash" {
		t.Fatalf("password hash = %v, want new-hash", got["permanent_password_hash"])
	}
	if got["require_approval"] != false {
		t.Fatalf("require_approval = %v, want false", got["require_approval"])
	}
	if got["ui_addr"] != "127.0.0.1:18480" {
		t.Fatalf("unrelated service settings must be kept, ui_addr = %v", got["ui_addr"])
	}
	names := map[string]any{}
	for _, p := range got["known_peers"].([]any) {
		m := p.(map[string]any)
		names[m["device_id"].(string)] = m["name"]
	}
	if names["111"] != "My Office PC" || names["222"] != "only-in-service" || names["333"] != "only-in-user" {
		t.Fatalf("known peers not merged correctly: %v", names)
	}
}

func TestMergePeerConfigNeverMixesDifferentDevices(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user.json")
	sys := filepath.Join(dir, "sys.json")
	writeJSONFile(t, sys, map[string]any{"device_id": "111111111", "permanent_password_hash": "a"})
	writeJSONFile(t, user, map[string]any{"device_id": "222222222", "permanent_password_hash": "b"})
	if changed, _ := mergePeerConfig(user, sys, true, false); changed {
		t.Fatal("configs of different devices must not be merged")
	}
	if readJSONFile(t, sys)["permanent_password_hash"] != "a" {
		t.Fatal("service password changed by another device's config")
	}
}

func TestMergePeerConfigFillOnlyKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user.json")
	sys := filepath.Join(dir, "sys.json")
	writeJSONFile(t, sys, map[string]any{"device_id": "1", "permanent_password_hash": "keep"})
	writeJSONFile(t, user, map[string]any{"device_id": "1", "permanent_password_hash": "other"})
	if changed, _ := mergePeerConfig(user, sys, false, false); changed {
		t.Fatal("fill-only merge must not replace an existing password")
	}
}

func TestSyncNewerUserConfigOnlyFromInstallingUser(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys.json")
	installer := filepath.Join(dir, "installer.json")
	other := filepath.Join(dir, "other.json")
	writeJSONFile(t, sys, map[string]any{
		"device_id": "595514895", "permanent_password_hash": "old", "require_approval": true,
		"migrated_from": installer,
	})
	if uid := fileOwnerUID(sys); uid >= 0 {
		m := readJSONFile(t, sys)
		m["migrated_from_uid"] = uid
		writeJSONFile(t, sys, m)
	}
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(sys, past, past)

	// Another user's newer file is never read.
	writeJSONFile(t, other, map[string]any{"device_id": "595514895", "permanent_password_hash": "attacker"})
	if got := SyncNewerUserConfig(sys); len(got) != 0 {
		t.Fatalf("synced from a file that is not the installing user's: %v", got)
	}

	// The installer's file without a device_id is refused.
	writeJSONFile(t, installer, map[string]any{"permanent_password_hash": "attacker"})
	if got := SyncNewerUserConfig(sys); len(got) != 0 {
		t.Fatalf("synced a file without device_id: %v", got)
	}

	// The installer's own file with the same device id is merged, but cannot turn approval off.
	writeJSONFile(t, installer, map[string]any{"device_id": "595514895", "permanent_password_hash": "new", "require_approval": false})
	if got := SyncNewerUserConfig(sys); len(got) != 1 {
		t.Fatalf("installing user's newer config not synced: %v", got)
	}
	m := readJSONFile(t, sys)
	if m["permanent_password_hash"] != "new" || m["require_approval"] != true {
		t.Fatalf("after sync: hash=%v approval=%v, want new/true", m["permanent_password_hash"], m["require_approval"])
	}
}

func TestSyncWithoutRecordedSourceDoesNothing(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys.json")
	writeJSONFile(t, sys, map[string]any{"device_id": "1", "permanent_password_hash": "keep"})
	if got := SyncNewerUserConfig(sys); len(got) != 0 {
		t.Fatalf("synced without a recorded install source: %v", got)
	}
}
