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
	"path/filepath"
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

	targetPath := exePath
	tmpPath := targetPath + ".new"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil && runtime.GOOS != "windows" && errors.Is(err, os.ErrPermission) {
		// System-installed Linux/macOS binary (e.g. /usr/bin/apn or /usr/lib/apn/apn from .deb owned by root):
		// seamlessly stage & install the verified update into user-writable ~/.local/bin/apn with ZERO root prompt!
		if home, herr := os.UserHomeDir(); herr == nil && home != "" {
			userBinDir := filepath.Join(home, ".local", "bin")
			if mkErr := os.MkdirAll(userBinDir, 0o755); mkErr == nil {
				targetPath = filepath.Join(userBinDir, "apn")
				tmpPath = targetPath + ".new"
				out, err = os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			}
		}
	}
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

	oldPath := targetPath + ".old"
	_ = os.Remove(oldPath)
	if _, statErr := os.Stat(targetPath); statErr == nil {
		if err := os.Rename(targetPath, oldPath); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("สลับไฟล์เดิมไม่ได้: %w", err)
		}
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		if _, statErr := os.Stat(oldPath); statErr == nil {
			_ = os.Rename(oldPath, targetPath)
		}
		return fmt.Errorf("วางไฟล์ใหม่ไม่ได้: %w", err)
	}
	_ = os.Chmod(targetPath, 0o755)

	// If Linux updated from a root-owned /usr/bin/apn into ~/.local/bin/apn, make sure XDG desktop/autostart
	// entries also launch the updated user binary on future clicks & logins!
	if runtime.GOOS == "linux" && filepath.Clean(targetPath) != filepath.Clean(exePath) {
		syncLinuxUserDesktopOverride(targetPath)
	}

	m.mu.Lock()
	m.status.Progress = 100
	m.status.Stage = "อัปเดตสำเร็จ! กำลังเปิดเวอร์ชันใหม่..."
	m.mu.Unlock()

	// If running under Linux systemd user service (INVOCATION_ID set + Restart=always),
	// simply exit cleanly after swapping the binary so systemd restarts the service cleanly
	// with zero duplicate processes! Otherwise spawn the updated binary with -wait-pid handoff.
	if runtime.GOOS == "linux" && os.Getenv("INVOCATION_ID") != "" {
		time.Sleep(150 * time.Millisecond)
		if onRestart != nil {
			onRestart()
		}
		return nil
	}

	// Spawn the updated binary with -wait-old and -wait-pid=<currentPID> (WITHOUT -open, because the
	// user's existing APN app window auto-reloads into the new version seamlessly!).
	// The new process waits until THIS old PID completely terminates & frees port 8080 before starting!
	cmd := exec.Command(targetPath, "peer", "-tray-icon", "-wait-old", "-wait-pid", strconv.Itoa(os.Getpid()))
	_ = cmd.Start()
	time.Sleep(120 * time.Millisecond)
	if onRestart != nil {
		onRestart()
	}
	return nil
}

func syncLinuxUserDesktopOverride(userBin string) {
	// If the new .deb smart launcher (/usr/lib/apn/apn) is present, /usr/bin/apn already
	// auto-chains to ~/.local/bin/apn whenever it is newer — no duplicate user .desktop needed.
	if _, err := os.Stat("/usr/lib/apn/apn"); err == nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	appDir := filepath.Join(home, ".local", "share", "applications")
	if os.MkdirAll(appDir, 0o755) == nil {
		desktop := fmt.Sprintf(`[Desktop Entry]
Version=1.0
Type=Application
Name=APN
GenericName=Remote Desktop & VPN
Comment=High-Speed 60 FPS P2P Remote Desktop & Encrypted L3 VPN
Exec=%s
Icon=apn
Terminal=false
Categories=Network;RemoteAccess;
StartupNotify=true
`, userBin)
		_ = os.WriteFile(filepath.Join(appDir, "apn.desktop"), []byte(desktop), 0o644)
	}
	autoDir := filepath.Join(home, ".config", "autostart")
	if os.MkdirAll(autoDir, 0o755) == nil {
		auto := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=APN Background Service
Comment=Keep APN online for incoming remote access
Exec=%s peer -tray
Icon=apn
Terminal=false
X-GNOME-Autostart-enabled=true
`, userBin)
		_ = os.WriteFile(filepath.Join(autoDir, "apn.desktop"), []byte(auto), 0o644)
	}
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
