package service

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// Info describes the live OS-level System Service state (Windows Service / Linux systemd system unit).
type Info struct {
	Supported        bool   `json:"supported"`
	Installed        bool   `json:"installed"`
	Running          bool   `json:"running"`
	RunningAsService bool   `json:"running_as_service"`
	ServiceName      string `json:"service_name,omitempty"`
	BinaryPath       string `json:"binary_path,omitempty"`
	ConfigPath       string `json:"config_path,omitempty"`
}

func copyFileAtomic(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		old := dst + ".old"
		_ = os.Remove(old)
		if rerr := os.Rename(dst, old); rerr == nil {
			if err2 := os.Rename(tmp, dst); err2 == nil {
				return nil
			}
		}
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// migrateConfigDir copies user peer config & TLS certs into system-wide service directories.
// If dst peer.json already exists with the same device_id (or no permanent password yet),
// it merges permanent_password_hash & known_peers from src so upgrading/reinstalling never loses passwords!
func migrateConfigDir(srcCfgPath, dstCfgDir string) {
	if srcCfgPath == "" {
		return
	}
	srcDir := filepath.Dir(srcCfgPath)
	_ = os.MkdirAll(dstCfgDir, 0o700)
	for _, name := range []string{"peer.json", "peer.crt", "peer.key"} {
		src := filepath.Join(srcDir, name)
		dst := filepath.Join(dstCfgDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			if name == "peer.json" {
				mergePeerPasswordIfMissing(src, dst)
			}
			continue
		}
		_ = copyFileAtomic(src, dst, 0o600)
	}
}

func mergePeerPasswordIfMissing(srcPath, dstPath string) {
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		return
	}
	dstBytes, err := os.ReadFile(dstPath)
	if err != nil {
		return
	}
	var srcMap, dstMap map[string]any
	if json.Unmarshal(srcBytes, &srcMap) != nil || json.Unmarshal(dstBytes, &dstMap) != nil {
		return
	}
	srcHash, _ := srcMap["permanent_password_hash"].(string)
	dstHash, _ := dstMap["permanent_password_hash"].(string)
	changed := false
	if dstHash == "" && srcHash != "" {
		dstMap["permanent_password_hash"] = srcHash
		changed = true
	}
	if _, hasKnown := dstMap["known_peers"]; !hasKnown {
		if srcKnown, ok := srcMap["known_peers"]; ok {
			dstMap["known_peers"] = srcKnown
			changed = true
		}
	}
	if !changed {
		return
	}
	out, err := json.MarshalIndent(dstMap, "", "  ")
	if err != nil {
		return
	}
	tmp := dstPath + ".tmp"
	if os.WriteFile(tmp, out, 0o600) == nil {
		_ = os.Rename(tmp, dstPath)
	}
}

func migrateBinDir(srcBinDir, dstBinDir string) {
	if srcBinDir == "" {
		return
	}
	_ = os.MkdirAll(dstBinDir, 0o755)
	entries, err := os.ReadDir(srcBinDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(srcBinDir, e.Name())
		dst := filepath.Join(dstBinDir, e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		_ = copyFileAtomic(src, dst, 0o755)
	}
}
