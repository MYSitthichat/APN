package bootstrap

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Pinned downloads for zero-setup auto-bootstrap: an exact version from an immutable release URL,
// checked against its SHA-256 before anything is extracted or installed. A "latest" URL would let
// a new upstream build (e.g. FFmpeg raising its NVIDIA driver requirement) reach every machine
// untested, and an unchecked download would run as the System Service.
// To move to a newer build: update URL and SHA256 together, then test on real machines.
var (
	// FFmpeg 9.1 essentials (gyan.dev build, versioned GitHub release).
	FFmpegWindows = pinnedDownload{
		URL:    "https://github.com/GyanD/codexffmpeg/releases/download/9.1/ffmpeg-9.1-essentials_build.zip",
		SHA256: "b9bbbb3acece000cbeec994f856649354e52c773807841e78908374b24d658fd",
	}
	// FFmpeg n9.0.2 static GPL (BtbN month-end autobuild, kept long-term).
	FFmpegLinuxAMD64 = pinnedDownload{
		URL:    "https://github.com/FFmpeg-Builds/FFmpeg-Builds/releases/download/autobuild-2026-10-31-12-59/ffmpeg-n9.0.2-39-g7adfbe40dc-linux64-gpl-9.0.tar.xz",
		SHA256: "73e29a56974ae5a651133a04584c7483b21afe941e17dc91d79814a758b608d3",
	}
	FFmpegLinuxARM64 = pinnedDownload{
		URL:    "https://github.com/FFmpeg-Builds/FFmpeg-Builds/releases/download/autobuild-2026-10-31-12-59/ffmpeg-n9.0.2-39-g7adfbe40dc-linuxarm64-gpl-9.0.tar.xz",
		SHA256: "6cad88ae5bcec356cfc5d7979a036cc4007128201928a0cf243df3db483276cc",
	}
	Wintun = pinnedDownload{
		URL:    "https://www.wintun.net/builds/wintun-0.14.1.zip",
		SHA256: "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
	}
	// cloudflared 2026.11.2.
	CloudflaredWinAMD64 = pinnedDownload{
		URL:    "https://github.com/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-windows-amd64.exe",
		SHA256: "555b46c85582461d189cac30d14ad05480d612613801be9f110b8ce08c5b2113",
	}
	CloudflaredLinuxAMD64 = pinnedDownload{
		URL:    "https://github.com/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-linux-amd64",
		SHA256: "56f13335143ec0e22772963290683a84a04114a35ec64cbc794a4d39ff9bb8cf",
	}
	CloudflaredLinuxARM64 = pinnedDownload{
		URL:    "https://github.com/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-linux-arm64",
		SHA256: "04a7b7f08bce85d56b26ffe1fdbfbb21a074495a363d16f0783c40e25b5c5281",
	}
	CloudflaredLinuxARM = pinnedDownload{
		URL:    "https://github.com/cloudflare/cloudflared/releases/download/2026.11.2/cloudflared-linux-arm",
		SHA256: "d219494581180764c6d2454409691bb06879d01b43cdeae12476070a7e4e4762",
	}
)

// Status describes live runtime dependency state (FFmpeg, Wintun, Cloudflared 443 Bridge) for the UI.
type Status struct {
	BinDir           string `json:"bin_dir"`
	FFmpegReady      bool   `json:"ffmpeg_ready"`
	FFmpegPath       string `json:"ffmpeg_path,omitempty"`
	WintunReady      bool   `json:"wintun_ready"`
	WintunPath       string `json:"wintun_path,omitempty"`
	CloudflaredReady bool   `json:"cloudflared_ready"`
	CloudflaredPath  string `json:"cloudflared_path,omitempty"`
	Installing       bool   `json:"installing"`
	Stage            string `json:"stage,omitempty"`
	Progress         int    `json:"progress"` // 0..100
	DownloadedBytes  int64  `json:"downloaded_bytes,omitempty"`
	TotalBytes       int64  `json:"total_bytes,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

// BinDir returns the persistent user-level RelayVPN helper binary directory so updates
// to RelayVPN.exe reuse already-installed ffmpeg.exe and wintun.dll without re-downloading.
func BinDir() string {
	if custom := strings.TrimSpace(os.Getenv("APN_BIN_DIR")); custom != "" {
		return custom
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "RelayVPN", "bin")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "relayvpn", "bin")
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "bin")
	}
	return filepath.Join(".", "bin")
}

// EnsureRuntimePath adds BinDir() to PATH and registers Windows DLL search path for wintun.dll.
func EnsureRuntimePath() {
	dir := BinDir()
	_ = os.MkdirAll(dir, 0o755)
	registerDLLDir(dir)

	curPath := os.Getenv("PATH")
	sep := string(os.PathListSeparator)
	for _, entry := range filepath.SplitList(curPath) {
		if strings.EqualFold(filepath.Clean(entry), filepath.Clean(dir)) {
			return
		}
	}
	if curPath == "" {
		_ = os.Setenv("PATH", dir)
	} else {
		_ = os.Setenv("PATH", dir+sep+curPath)
	}
}

// FindFFmpeg searches persistent BinDir, executable directory, and system PATH for ffmpeg.
func FindFFmpeg() (string, bool) {
	binName := "ffmpeg"
	if runtime.GOOS == "windows" {
		binName = "ffmpeg.exe"
	}
	candidates := []string{
		filepath.Join(BinDir(), binName),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), binName))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Size() > 100*1024 {
			return p, true
		}
	}
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		return p, true
	}
	return "", false
}

// HasFFmpeg returns true if ffmpeg is ready to stream 60 FPS GPU H.264 video.
func HasFFmpeg() bool {
	_, ok := FindFFmpeg()
	return ok
}

// FindWintun searches persistent BinDir, executable directory, and System32 for wintun.dll on Windows.
func FindWintun() (string, bool) {
	if runtime.GOOS != "windows" {
		return "", true // Linux/macOS use built-in kernel TUN (/dev/net/tun, utun)
	}
	candidates := []string{
		filepath.Join(BinDir(), "wintun.dll"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "wintun.dll"))
	}
	candidates = append(candidates, "wintun.dll")
	if sysRoot := os.Getenv("SystemRoot"); sysRoot != "" {
		candidates = append(candidates, filepath.Join(sysRoot, "System32", "wintun.dll"))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Size() > 50*1024 {
			return p, true
		}
	}
	return "", false
}

// FindCloudflared searches persistent BinDir, executable directory, and system PATH for cloudflared.
func FindCloudflared() (string, bool) {
	binName := "cloudflared"
	if runtime.GOOS == "windows" {
		binName = "cloudflared.exe"
	}
	candidates := []string{
		filepath.Join(BinDir(), binName),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), binName))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Size() > 1*1024*1024 {
			return p, true
		}
	}
	if p, err := exec.LookPath("cloudflared"); err == nil {
		return p, true
	}
	return "", false
}

// Manager coordinates idempotent background installation of runtime helpers (Wintun, Cloudflared, FFmpeg).
type Manager struct {
	logger  *slog.Logger
	onReady func()

	mu         sync.Mutex
	installing bool
	stage      string
	progress   int
	dlBytes    int64
	totalBytes int64
	lastErr    string
}

// NewManager creates a dependency bootstrap manager.
func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	EnsureRuntimePath()
	return &Manager{logger: logger}
}

// SetOnReady registers a callback invoked whenever a component finishes installing.
func (m *Manager) SetOnReady(fn func()) {
	m.mu.Lock()
	m.onReady = fn
	m.mu.Unlock()
}

// Status returns the current live status of FFmpeg, Wintun, Cloudflared, and active download progress.
func (m *Manager) Status() Status {
	ffPath, ffOK := FindFFmpeg()
	wtPath, wtOK := FindWintun()
	cfPath, cfOK := FindCloudflared()

	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		BinDir:           BinDir(),
		FFmpegReady:      ffOK,
		FFmpegPath:       ffPath,
		WintunReady:      wtOK,
		WintunPath:       wtPath,
		CloudflaredReady: cfOK,
		CloudflaredPath:  cfPath,
		Installing:       m.installing,
		Stage:            m.stage,
		Progress:         m.progress,
		DownloadedBytes:  m.dlBytes,
		TotalBytes:       m.totalBytes,
		LastError:        m.lastErr,
	}
}

// StartAutoInstall triggers an idempotent background install of missing runtime helpers.
func (m *Manager) StartAutoInstall(ctx context.Context) bool {
	m.mu.Lock()
	if m.installing {
		m.mu.Unlock()
		return false
	}
	_, ffOK := FindFFmpeg()
	_, wtOK := FindWintun()
	_, cfOK := FindCloudflared()
	if ffOK && wtOK && cfOK {
		m.lastErr = ""
		m.mu.Unlock()
		return false
	}
	m.installing = true
	m.lastErr = ""
	m.progress = 0
	m.dlBytes = 0
	m.totalBytes = 0
	m.stage = "กำลังตรวจสอบคอมโพเนนต์..."
	m.mu.Unlock()

	go m.runInstall(ctx)
	return true
}

func (m *Manager) notifyReady() {
	m.mu.Lock()
	fn := m.onReady
	m.mu.Unlock()
	if fn != nil {
		go fn()
	}
}

func (m *Manager) runInstall(ctx context.Context) {
	defer func() {
		m.mu.Lock()
		m.installing = false
		m.stage = ""
		m.mu.Unlock()
	}()

	dir := BinDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.setErr(fmt.Sprintf("สร้างโฟลเดอร์ %s ไม่สำเร็จ: %v", dir, err))
		return
	}
	EnsureRuntimePath()

	// 1. Windows: Auto-install official signed wintun.dll (~730 KB, instant!)
	if runtime.GOOS == "windows" {
		if _, ok := FindWintun(); !ok {
			m.setProgress("กำลังติดตั้ง Wintun L3 VPN Driver...", 5, 0, 0)
			archSub := "wintun/bin/amd64/wintun.dll"
			if runtime.GOARCH == "arm64" {
				archSub = "wintun/bin/arm64/wintun.dll"
			}
			dest := filepath.Join(dir, "wintun.dll")
			if err := m.downloadAndExtractZipEntry(ctx, Wintun, archSub, dest, "กำลังดาวน์โหลด Wintun Driver..."); err != nil {
				m.logger.Warn("auto-install wintun failed", "err", err)
				m.setErr("ติดตั้ง Wintun ไม่สำเร็จ: " + err.Error())
			} else {
				if exe, err := os.Executable(); err == nil {
					_ = copyFileBestEffort(dest, filepath.Join(filepath.Dir(exe), "wintun.dll"))
				}
				EnsureRuntimePath()
				m.logger.Info("auto-installed official wintun.dll", "path", dest)
				m.notifyReady()
			}
		}
	}

	// 2. Auto-install official cloudflared for zero-VPS Port 443 Internet Bridge
	if _, ok := FindCloudflared(); !ok {
		if cf, binName := cloudflaredDownloadTarget(); cf.URL != "" {
			dest := filepath.Join(dir, binName)
			m.setProgress("กำลังดาวน์โหลด Cloudflared (เชื่อมข้ามเน็ต 443)...", 1, 0, 0)
			if err := m.downloadDirectBinary(ctx, cf, dest, "กำลังดาวน์โหลด Cloudflared (เชื่อมข้ามเน็ต 443)..."); err != nil {
				m.logger.Warn("auto-install cloudflared failed", "err", err)
				m.setErr("ติดตั้ง Cloudflared ไม่สำเร็จ: " + err.Error())
			} else {
				EnsureRuntimePath()
				m.logger.Info("auto-installed official cloudflared", "path", dest)
				m.notifyReady()
			}
		}
	}

	// 3. Auto-install FFmpeg for 60 FPS GPU H.265/H.264 streaming (Windows & Linux!)
	if _, ok := FindFFmpeg(); !ok {
		switch runtime.GOOS {
		case "windows":
			dest := filepath.Join(dir, "ffmpeg.exe")
			m.setProgress("กำลังดาวน์โหลด FFmpeg Stable (60 FPS GPU)...", 1, 0, 0)
			if err := m.downloadAndExtractZipEntry(ctx, FFmpegWindows, "/bin/ffmpeg.exe", dest, "กำลังดาวน์โหลด FFmpeg Stable (60 FPS GPU)..."); err != nil {
				m.logger.Warn("auto-install ffmpeg failed", "err", err)
				m.setErr("ติดตั้ง FFmpeg ไม่สำเร็จ: " + err.Error())
				return
			}
			EnsureRuntimePath()
			m.setProgress("ติดตั้ง FFmpeg 60 FPS GPU สำเร็จ!", 100, 0, 0)
			m.logger.Info("auto-installed stable ffmpeg.exe", "path", dest)
			m.notifyReady()
		case "linux":
			// Fast path if already running as root (System Service): try distro apt-get first (~5s!)
			if os.Geteuid() == 0 {
				if aptPath, aerr := exec.LookPath("apt-get"); aerr == nil {
					m.setProgress("กำลังติดตั้ง FFmpeg ผ่าน apt...", 25, 0, 0)
					_ = exec.CommandContext(ctx, aptPath, "update", "-qq").Run()
					cmd := exec.CommandContext(ctx, aptPath, "install", "-y", "-qq", "ffmpeg")
					cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
					if err := cmd.Run(); err == nil {
						if _, ok := FindFFmpeg(); ok {
							EnsureRuntimePath()
							m.setProgress("ติดตั้ง FFmpeg 60 FPS GPU สำเร็จ!", 100, 0, 0)
							m.notifyReady()
							return
						}
					}
				}
			}
			// Zero-root universal path: download official BtbN static Linux GPL FFmpeg (includes x11grab + VAAPI + NVENC + x264!)
			var ffURL pinnedDownload
			switch runtime.GOARCH {
			case "amd64":
				ffURL = FFmpegLinuxAMD64
			case "arm64":
				ffURL = FFmpegLinuxARM64
			}
			if ffURL.URL == "" {
				m.setErr("กรุณาติดตั้ง ffmpeg ด้วยคำสั่ง: sudo apt install -y ffmpeg")
				return
			}
			dest := filepath.Join(dir, "ffmpeg")
			m.setProgress("กำลังดาวน์โหลด FFmpeg Linux (60 FPS GPU)...", 1, 0, 0)
			if err := m.downloadAndExtractLinuxFFmpeg(ctx, ffURL, dest, "กำลังดาวน์โหลด FFmpeg Linux (60 FPS GPU)..."); err != nil {
				m.logger.Warn("auto-install linux ffmpeg failed", "err", err)
				m.setErr("ติดตั้ง FFmpeg อัตโนมัติไม่สำเร็จ (" + err.Error() + ") — หรือรัน: sudo apt install -y ffmpeg")
				return
			}
			EnsureRuntimePath()
			m.setProgress("ติดตั้ง FFmpeg 60 FPS GPU สำเร็จ!", 100, 0, 0)
			m.logger.Info("auto-installed static linux ffmpeg", "path", dest)
			m.notifyReady()
		default:
			m.setErr("กรุณาติดตั้ง ffmpeg ด้วยแพ็กเกจของ OS (macOS: brew install ffmpeg)")
		}
	}
}

func cloudflaredDownloadTarget() (pinnedDownload, string) {
	switch runtime.GOOS {
	case "windows":
		return CloudflaredWinAMD64, "cloudflared.exe"
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return CloudflaredLinuxAMD64, "cloudflared"
		case "arm64":
			return CloudflaredLinuxARM64, "cloudflared"
		case "arm":
			return CloudflaredLinuxARM, "cloudflared"
		}
	}
	return pinnedDownload{}, ""
}

func (m *Manager) downloadDirectBinary(ctx context.Context, pin pinnedDownload, destPath, stageLabel string) error {
	url := pin.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "RelayVPN-AutoBootstrap/1.0")

	hc := &http.Client{Timeout: 10 * time.Minute}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	tmpPath := destPath + ".tmp"
	outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 128*1024)
	lastReport := time.Now()

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := outFile.Write(buf[:n]); werr != nil {
				_ = outFile.Close()
				_ = os.Remove(tmpPath)
				return werr
			}
			downloaded += int64(n)
			if time.Since(lastReport) >= 200*time.Millisecond {
				lastReport = time.Now()
				pct := 0
				if total > 0 {
					pct = int(downloaded * 100 / total)
				}
				m.setProgress(stageLabel, pct, downloaded, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = outFile.Close()
			_ = os.Remove(tmpPath)
			return rerr
		}
	}
	if err := outFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := verifyFileSHA256(tmpPath, pin.SHA256); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	m.setProgress("ติดตั้ง "+filepath.Base(destPath)+" สำเร็จ!", 100, downloaded, total)
	return nil
}

func (m *Manager) downloadAndExtractZipEntry(ctx context.Context, pin pinnedDownload, entrySuffix, destPath, stageLabel string) error {
	url := pin.URL
	tmpZip := destPath + ".download.zip"
	defer os.Remove(tmpZip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "RelayVPN-AutoBootstrap/1.0")

	hc := &http.Client{
		Timeout: 15 * time.Minute,
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	outFile, err := os.OpenFile(tmpZip, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 128*1024)
	lastReport := time.Now()

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := outFile.Write(buf[:n]); werr != nil {
				_ = outFile.Close()
				return werr
			}
			downloaded += int64(n)
			if time.Since(lastReport) >= 200*time.Millisecond {
				lastReport = time.Now()
				pct := 0
				if total > 0 {
					pct = int(downloaded * 90 / total) // reserve 90..100% for extraction
				}
				m.setProgress(stageLabel, pct, downloaded, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = outFile.Close()
			return rerr
		}
	}
	if err := outFile.Close(); err != nil {
		return err
	}

	if err := verifyFileSHA256(tmpZip, pin.SHA256); err != nil {
		return err
	}
	m.setProgress("กำลังแตกไฟล์ "+filepath.Base(destPath)+"...", 94, downloaded, total)

	zr, err := zip.OpenReader(tmpZip)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	wantSuffix := strings.ToLower(strings.ReplaceAll(entrySuffix, "\\", "/"))
	var target *zip.File
	for _, f := range zr.File {
		norm := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		if norm == wantSuffix || strings.HasSuffix(norm, wantSuffix) {
			target = f
			break
		}
	}
	if target == nil {
		return errors.New("ไม่พบไฟล์ " + entrySuffix + " ภายในไฟล์ zip")
	}

	rc, err := target.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	tmpBin := destPath + ".tmp"
	binFile, err := os.OpenFile(tmpBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(binFile, rc); err != nil {
		_ = binFile.Close()
		_ = os.Remove(tmpBin)
		return err
	}
	if err := binFile.Close(); err != nil {
		_ = os.Remove(tmpBin)
		return err
	}

	if err := os.Rename(tmpBin, destPath); err != nil {
		_ = os.Remove(tmpBin)
		return err
	}
	m.setProgress("ติดตั้ง "+filepath.Base(destPath)+" สำเร็จ!", 100, downloaded, total)
	return nil
}

func (m *Manager) downloadAndExtractLinuxFFmpeg(ctx context.Context, pin pinnedDownload, destPath, stageLabel string) error {
	rawURL := pin.URL
	client := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "APN-Bootstrap/1.3")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmpArc := destPath + ".tar.xz"
	defer os.Remove(tmpArc)

	outFile, err := os.OpenFile(tmpArc, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)
	lastUI := time.Now()
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := outFile.Write(buf[:n]); werr != nil {
				_ = outFile.Close()
				return werr
			}
			downloaded += int64(n)
			if time.Since(lastUI) >= 150*time.Millisecond {
				lastUI = time.Now()
				pct := 10
				if total > 0 {
					pct = int(downloaded * 90 / total)
				}
				m.setProgress(stageLabel, pct, downloaded, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = outFile.Close()
			return rerr
		}
	}
	if err := outFile.Close(); err != nil {
		return err
	}
	if err := verifyFileSHA256(tmpArc, pin.SHA256); err != nil {
		return err
	}

	m.setProgress("กำลังแตกไฟล์ ffmpeg...", 94, downloaded, total)
	tmpDir := destPath + ".extract"
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.CommandContext(ctx, "tar", "-xJf", tmpArc, "--wildcards", "--strip-components=2", "-C", tmpDir, "*/bin/ffmpeg")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("แตกไฟล์ tar.xz ไม่สำเร็จ: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	extracted := filepath.Join(tmpDir, "ffmpeg")
	if _, err := os.Stat(extracted); err != nil {
		return errors.New("ไม่พบไบนารี ffmpeg หลังแตกไฟล์")
	}
	_ = os.Chmod(extracted, 0o755)
	if err := os.Rename(extracted, destPath); err != nil {
		if err2 := copyFileBestEffort(extracted, destPath); err2 != nil {
			return err2
		}
		_ = os.Chmod(destPath, 0o755)
	}
	m.setProgress("ติดตั้ง ffmpeg สำเร็จ!", 100, downloaded, total)
	return nil
}

func (m *Manager) setProgress(stage string, pct int, dl, total int64) {
	m.mu.Lock()
	m.stage = stage
	m.progress = pct
	m.dlBytes = dl
	m.totalBytes = total
	m.mu.Unlock()
}

func (m *Manager) setErr(msg string) {
	m.mu.Lock()
	m.lastErr = msg
	m.mu.Unlock()
}

func copyFileBestEffort(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
