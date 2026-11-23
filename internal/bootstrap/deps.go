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

const (
	// Official stable pinned releases for zero-setup auto-bootstrap.
	FFmpegWindowsStableURL   = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"
	WintunOfficialURL        = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	CloudflaredWinAMD64URL   = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
	CloudflaredLinuxAMD64URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
	CloudflaredLinuxARM64URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
	CloudflaredLinuxARMURL   = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
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
			if err := m.downloadAndExtractZipEntry(ctx, WintunOfficialURL, archSub, dest, "กำลังดาวน์โหลด Wintun Driver..."); err != nil {
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
		if cfURL, binName := cloudflaredDownloadTarget(); cfURL != "" {
			dest := filepath.Join(dir, binName)
			m.setProgress("กำลังดาวน์โหลด Cloudflared (เชื่อมข้ามเน็ต 443)...", 1, 0, 0)
			if err := m.downloadDirectBinary(ctx, cfURL, dest, "กำลังดาวน์โหลด Cloudflared (เชื่อมข้ามเน็ต 443)..."); err != nil {
				m.logger.Warn("auto-install cloudflared failed", "err", err)
				m.setErr("ติดตั้ง Cloudflared ไม่สำเร็จ: " + err.Error())
			} else {
				EnsureRuntimePath()
				m.logger.Info("auto-installed official cloudflared", "path", dest)
				m.notifyReady()
			}
		}
	}

	// 3. Auto-install stable FFmpeg for 60 FPS DXGI/GPU H.264 streaming
	if _, ok := FindFFmpeg(); !ok {
		if runtime.GOOS == "windows" {
			dest := filepath.Join(dir, "ffmpeg.exe")
			m.setProgress("กำลังดาวน์โหลด FFmpeg Stable (60 FPS GPU)...", 1, 0, 0)
			if err := m.downloadAndExtractZipEntry(ctx, FFmpegWindowsStableURL, "/bin/ffmpeg.exe", dest, "กำลังดาวน์โหลด FFmpeg Stable (60 FPS GPU)..."); err != nil {
				m.logger.Warn("auto-install ffmpeg failed", "err", err)
				m.setErr("ติดตั้ง FFmpeg ไม่สำเร็จ: " + err.Error())
				return
			}
			EnsureRuntimePath()
			m.setProgress("ติดตั้ง FFmpeg 60 FPS GPU สำเร็จ!", 100, 0, 0)
			m.logger.Info("auto-installed stable ffmpeg.exe", "path", dest)
			m.notifyReady()
		} else {
			m.setErr("กรุณาติดตั้ง ffmpeg ด้วยแพ็กเกจของ OS (macOS: brew install ffmpeg / Linux: sudo apt install ffmpeg)")
		}
	}
}

func cloudflaredDownloadTarget() (url, binName string) {
	switch runtime.GOOS {
	case "windows":
		return CloudflaredWinAMD64URL, "cloudflared.exe"
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return CloudflaredLinuxAMD64URL, "cloudflared"
		case "arm64":
			return CloudflaredLinuxARM64URL, "cloudflared"
		case "arm":
			return CloudflaredLinuxARMURL, "cloudflared"
		}
	}
	return "", ""
}

func (m *Manager) downloadDirectBinary(ctx context.Context, url, destPath, stageLabel string) error {
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
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	m.setProgress("ติดตั้ง "+filepath.Base(destPath)+" สำเร็จ!", 100, downloaded, total)
	return nil
}

func (m *Manager) downloadAndExtractZipEntry(ctx context.Context, url, entrySuffix, destPath, stageLabel string) error {
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
