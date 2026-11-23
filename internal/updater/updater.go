package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"relayvpn/internal/version"
)

// Asset describes a downloadable platform binary in the update manifest.
type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
}

// Manifest is the JSON payload returned by /api/releases/latest.
type Manifest struct {
	Version      string           `json:"version"`
	ReleaseNotes string           `json:"release_notes,omitempty"`
	Assets       map[string]Asset `json:"assets"`
}

// Status exposes live auto-update state to the Dashboard UI.
type Status struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseNotes    string `json:"release_notes,omitempty"`
	HasBinary       bool   `json:"has_binary"`
	Checking        bool   `json:"checking"`
	Updating        bool   `json:"updating"`
	Progress        int    `json:"progress"`
	DownloadedBytes int64  `json:"downloaded_bytes,omitempty"`
	TotalBytes      int64  `json:"total_bytes,omitempty"`
	Stage           string `json:"stage,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	CheckedAt       string `json:"checked_at,omitempty"`
}

// Manager checks for new APN versions and performs verified in-place binary self-updates.
type Manager struct {
	client      *http.Client
	manifestURL string

	mu          sync.Mutex
	status      Status
	targetAsset Asset
}

// NewManager creates an auto-updater bound to the given manifest URL and resilient HTTP client.
func NewManager(manifestURL string, hc *http.Client) *Manager {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Manager{
		client:      hc,
		manifestURL: strings.TrimSpace(manifestURL),
		status: Status{
			CurrentVersion: version.Version,
		},
	}
}

// CleanupOldBinary removes any leftover .old executable renamed during a previous Windows self-update.
func CleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}

// Status returns a snapshot of the updater state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Check queries the release manifest and checks if a newer version is available for this OS/arch.
func (m *Manager) Check(ctx context.Context) Status {
	m.mu.Lock()
	if m.manifestURL == "" {
		m.mu.Unlock()
		return m.Status()
	}
	m.status.Checking = true
	m.status.LastError = ""
	url := m.manifestURL
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.status.Checking = false
		m.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
		m.mu.Unlock()
	}()

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		m.setErr(err.Error())
		return m.Status()
	}
	resp, err := m.client.Do(req)
	if err != nil {
		m.setErr("เช็กอัปเดตไม่สำเร็จ: " + err.Error())
		return m.Status()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.setErr(fmt.Sprintf("เซิร์ฟเวอร์อัปเดตตอบกลับ HTTP %d", resp.StatusCode))
		return m.Status()
	}

	var mf Manifest
	if err := json.NewDecoder(resp.Body).Decode(&mf); err != nil {
		m.setErr("อ่านข้อมูลเวอร์ชันไม่ได้: " + err.Error())
		return m.Status()
	}

	platKey := platformKey()
	asset, hasAsset := mf.Assets[platKey]

	m.mu.Lock()
	m.status.LatestVersion = strings.TrimPrefix(strings.TrimSpace(mf.Version), "v")
	m.status.ReleaseNotes = mf.ReleaseNotes
	m.status.HasBinary = hasAsset && asset.URL != ""
	m.status.UpdateAvailable = isNewerVersion(m.status.LatestVersion, version.Version) && m.status.HasBinary
	m.targetAsset = asset
	m.mu.Unlock()

	return m.Status()
}

// Apply downloads the latest binary, verifies SHA-256, replaces the running executable in place,
// spawns the updated process, and invokes onRestart to exit the old process cleanly.
func (m *Manager) Apply(ctx context.Context, onRestart func()) error {
	m.mu.Lock()
	if m.status.Updating {
		m.mu.Unlock()
		return errors.New("กำลังอัปเดตอยู่แล้ว")
	}
	if !m.status.UpdateAvailable || m.targetAsset.URL == "" {
		m.mu.Unlock()
		return errors.New("คุณใช้เวอร์ชันล่าสุดอยู่แล้ว หรือยังไม่มีไฟล์อัปเดตสำหรับแพลตฟอร์มนี้")
	}
	asset := m.targetAsset
	m.status.Updating = true
	m.status.Progress = 2
	m.status.Stage = "กำลังดาวน์โหลด APN v" + m.status.LatestVersion + "..."
	m.status.LastError = ""
	m.mu.Unlock()

	go func() {
		if err := m.doApply(ctx, asset, onRestart); err != nil {
			m.mu.Lock()
			m.status.Updating = false
			m.status.LastError = err.Error()
			m.status.Stage = ""
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *Manager) doApply(ctx context.Context, asset Asset, onRestart func()) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	dlClient := &http.Client{
		Transport: m.client.Transport,
		Timeout:   5 * time.Minute,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return err
	}
	resp, err := dlClient.Do(req)
	if err != nil {
		return fmt.Errorf("ดาวน์โหลดไม่สำเร็จ: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ดาวน์โหลดไม่สำเร็จ (HTTP %d)", resp.StatusCode)
	}

	tmpPath := exePath + ".new"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("สร้างไฟล์อัปเดตไม่ได้: %w", err)
	}

	hasher := sha256.New()
	total := resp.ContentLength
	m.mu.Lock()
	m.status.TotalBytes = total
	m.status.DownloadedBytes = 0
	m.mu.Unlock()

	var written int64
	buf := make([]byte, 64*1024)
	lastTick := time.Now()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				_ = out.Close()
				_ = os.Remove(tmpPath)
				return werr
			}
			_, _ = hasher.Write(buf[:n])
			written += int64(n)
			if time.Since(lastTick) >= 120*time.Millisecond || rerr == io.EOF {
				lastTick = time.Now()
				pct := 10
				if total > 0 {
					pct = int(written * 90 / total)
					if pct < 5 {
						pct = 5
					}
				}
				m.mu.Lock()
				m.status.Progress = pct
				m.status.DownloadedBytes = written
				m.mu.Unlock()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = out.Close()
			_ = os.Remove(tmpPath)
			return rerr
		}
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	m.mu.Lock()
	m.status.Progress = 93
	m.status.DownloadedBytes = written
	m.status.Stage = "กำลังตรวจสอบความถูกต้องไฟล์ (SHA-256)..."
	m.mu.Unlock()

	if expected := strings.TrimSpace(strings.ToLower(asset.SHA256)); expected != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != expected {
			_ = os.Remove(tmpPath)
			return errors.New("ไฟล์อัปเดตไม่ผ่านการตรวจ SHA-256 (ยกเลิกเพื่อความปลอดภัย)")
		}
	}

	m.mu.Lock()
	m.status.Progress = 97
	m.status.Stage = "กำลังสลับไฟล์และรีสตาร์ทเป็นเวอร์ชันใหม่..."
	m.mu.Unlock()

	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("สลับไฟล์เดิมไม่ได้: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		return fmt.Errorf("วางไฟล์ใหม่ไม่ได้: %w", err)
	}

	m.mu.Lock()
	m.status.Progress = 100
	m.status.Stage = "อัปเดตสำเร็จ! กำลังเปิดเวอร์ชันใหม่..."
	m.mu.Unlock()

	// Spawn the updated binary with -wait-old so it waits cleanly for THIS old process
	// to release port 8080/4433/8444 BEFORE checking single-instance & starting up!
	// (Fixes the race where the new exe saw old port 8080 still open and exited immediately!)
	cmd := exec.Command(exePath, "peer", "-tray-icon", "-wait-old")
	_ = cmd.Start()
	time.Sleep(150 * time.Millisecond)
	if onRestart != nil {
		onRestart()
	}
	return nil
}

func (m *Manager) setErr(msg string) {
	m.mu.Lock()
	m.status.LastError = msg
	m.mu.Unlock()
}

func platformKey() string {
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm" {
		return "linux-armv7"
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

func isNewerVersion(latest, current string) bool {
	parse := func(v string) [3]int {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		parts := strings.Split(v, ".")
		var out [3]int
		for i := 0; i < len(parts) && i < 3; i++ {
			out[i], _ = strconv.Atoi(parts[i])
		}
		return out
	}
	a, b := parse(latest), parse(current)
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
