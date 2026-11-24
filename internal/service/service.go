package service

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	// Remember which user config this service was installed from. SyncNewerUserConfig only ever
	// reads that one file, never other users' files.
	if abs, err := filepath.Abs(srcCfgPath); err == nil {
		recordMigrationSource(filepath.Join(dstCfgDir, "peer.json"), abs)
	}
}

// recordMigrationSource stores the installing user's config path (and on Linux its owner uid)
// in the system peer.json.
func recordMigrationSource(dstPath, srcPath string) {
	b, err := os.ReadFile(dstPath)
	if err != nil {
		return
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return
	}
	m["migrated_from"] = srcPath
	if uid := fileOwnerUID(srcPath); uid >= 0 {
		m["migrated_from_uid"] = uid
	} else {
		delete(m, "migrated_from_uid")
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	tmp := dstPath + ".tmp"
	if os.WriteFile(tmp, out, 0o600) == nil {
		_ = os.Rename(tmp, dstPath)
	}
}

// mergePeerPasswordIfMissing is used at install time: the user-mode config being migrated is the
// current truth, so its permanent password and known peers win over an older system config.
func mergePeerPasswordIfMissing(srcPath, dstPath string) {
	_, _ = mergePeerConfig(srcPath, dstPath, true, false)
}

// SyncNewerUserConfig pulls settings into the system service config (systemCfgPath) from any
// user-mode peer.json of the same device that was saved more recently.
//
// The service and the user-mode app keep separate peer.json files. A permanent password or
// peer name changed while the user-mode app owned the UI used to be lost at the next boot,
// when the service started with its older copy: the viewer's saved password then no longer
// matched ("saved password does not match"). Call this before the service loads its config.
// It returns the user config paths that were merged.
//
// Security: only the config of the user who installed the service is read (recorded at install
// as "migrated_from", with its owner uid on Linux), it must carry the same non-empty device_id,
// and it can never switch "require approval" off. Reading every user's peer.json let any local
// user set the service's password.
func SyncNewerUserConfig(systemCfgPath string) []string {
	if systemCfgPath == "" {
		return nil
	}
	sysInfo, err := os.Stat(systemCfgPath)
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(systemCfgPath)
	if err != nil {
		return nil
	}
	var sysMap map[string]any
	if json.Unmarshal(b, &sysMap) != nil {
		return nil
	}
	src, _ := sysMap["migrated_from"].(string)
	if src == "" || filepath.Clean(src) == filepath.Clean(systemCfgPath) {
		return nil
	}
	st, err := os.Lstat(src)
	if err != nil || !st.Mode().IsRegular() || !st.ModTime().After(sysInfo.ModTime()) {
		return nil
	}
	if want, ok := sysMap["migrated_from_uid"].(float64); ok && fileOwnerUID(src) != int(want) {
		return nil // the file is no longer owned by the installing user
	}
	if ok, _ := mergePeerConfig(src, systemCfgPath, true, true); ok {
		return []string{src}
	}
	return nil
}

// mergePeerConfig merges the permanent password, approval setting and known peers of srcPath
// into dstPath when both belong to the same device ID. With srcWins, src values replace dst
// values; otherwise only missing values are filled in. It reports whether dst changed.
//
// strict (used for the automatic sync at service start) also requires both files to carry the
// same non-empty device_id and never turns require_approval off.
func mergePeerConfig(srcPath, dstPath string, srcWins, strict bool) (bool, error) {
	srcBytes, err := os.ReadFile(srcPath)
	if err != nil {
		return false, err
	}
	dstBytes, err := os.ReadFile(dstPath)
	if err != nil {
		return false, err
	}
	var srcMap, dstMap map[string]any
	if err := json.Unmarshal(srcBytes, &srcMap); err != nil {
		return false, err
	}
	if err := json.Unmarshal(dstBytes, &dstMap); err != nil {
		return false, err
	}
	srcID, _ := srcMap["device_id"].(string)
	dstID, _ := dstMap["device_id"].(string)
	if srcID != "" && dstID != "" && srcID != dstID {
		// A different device's config: never mix passwords between machines.
		return false, nil
	}
	if strict && (srcID == "" || dstID == "") {
		return false, nil
	}

	changed := false
	srcHash, _ := srcMap["permanent_password_hash"].(string)
	dstHash, _ := dstMap["permanent_password_hash"].(string)
	if srcHash != "" && srcHash != dstHash && (srcWins || dstHash == "") {
		dstMap["permanent_password_hash"] = srcHash
		changed = true
	}
	if srcWins {
		if v, ok := srcMap["require_approval"].(bool); ok {
			if cur, _ := dstMap["require_approval"].(bool); cur != v && !(strict && cur && !v) {
				dstMap["require_approval"] = v
				changed = true
			}
		}
	}
	if mergedPeers, ok := mergeKnownPeers(srcMap["known_peers"], dstMap["known_peers"], srcWins); ok {
		dstMap["known_peers"] = mergedPeers
		changed = true
	}
	if !changed {
		return false, nil
	}
	out, err := json.MarshalIndent(dstMap, "", "  ")
	if err != nil {
		return false, err
	}
	tmp := dstPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// mergeKnownPeers unions two known_peers lists by device_id. For a device in both lists, src
// fields replace dst fields when srcWins; otherwise dst keeps its values and only gains missing
// ones. It reports whether the result differs from dst.
func mergeKnownPeers(srcRaw, dstRaw any, srcWins bool) ([]any, bool) {
	srcList, _ := srcRaw.([]any)
	dstList, _ := dstRaw.([]any)
	if len(srcList) == 0 {
		return nil, false
	}
	out := make([]any, 0, len(dstList)+len(srcList))
	index := map[string]int{}
	for _, p := range dstList {
		m, ok := p.(map[string]any)
		if !ok {
			out = append(out, p)
			continue
		}
		cp := make(map[string]any, len(m))
		for k, v := range m {
			cp[k] = v
		}
		if id, _ := cp["device_id"].(string); id != "" {
			index[id] = len(out)
		}
		out = append(out, cp)
	}
	changed := false
	for _, p := range srcList {
		sm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		id, _ := sm["device_id"].(string)
		if id == "" {
			continue
		}
		pos, exists := index[id]
		if !exists {
			cp := make(map[string]any, len(sm))
			for k, v := range sm {
				cp[k] = v
			}
			index[id] = len(out)
			out = append(out, cp)
			changed = true
			continue
		}
		dm := out[pos].(map[string]any)
		for k, v := range sm {
			cur, has := dm[k]
			if !has || isEmptyJSON(cur) || (srcWins && !isEmptyJSON(v)) {
				if !has || !jsonEqual(cur, v) {
					dm[k] = v
					changed = true
				}
			}
		}
	}
	return out, changed
}

func isEmptyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	}
	return false
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
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
		// Only the known helper tools, and only regular files (no symlinks): this directory is
		// later used by the root/SYSTEM service, so copying arbitrary user files (e.g. a fake
		// "ip" or "netsh") into it would let a local user run code with service privileges.
		if !migratableBinNames[strings.ToLower(e.Name())] || e.Type()&os.ModeType != 0 {
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

var migratableBinNames = map[string]bool{
	"ffmpeg": true, "ffmpeg.exe": true, "cloudflared": true, "cloudflared.exe": true,
}
