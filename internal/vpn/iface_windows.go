//go:build windows

package vpn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"relayvpn/internal/bootstrap"
	"relayvpn/internal/executil"
)

func defaultTUNName() string {
	return "RelayVPN"
}

func preflightTUN() error {
	bootstrap.EnsureRuntimePath()
	wtPath, ok := bootstrap.FindWintun()
	if !ok {
		return errors.New("กำลังรอติดตั้ง wintun.dll อัตโนมัติ (หรือกดปุ่ม 'ติดตั้งอัตโนมัติ' ด้านล่าง แล้วรันโปรแกรมแบบ Run as Administrator)")
	}
	// wireguard-go loads wintun.dll with LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
	// which intentionally ignores SetDllDirectoryW & PATH. Ensure wintun.dll is staged right next to the
	// running executable (e.g. C:\ProgramData\APN\wintun.dll for APNService) AND pre-load it into the process.
	if exe, err := os.Executable(); err == nil {
		_ = stageWintunBeside(wtPath, filepath.Dir(exe))
	}
	_, _ = syscall.LoadLibrary(wtPath)
	return nil
}

func stageWintunBeside(srcPath, targetDir string) error {
	if srcPath == "" || targetDir == "" {
		return nil
	}
	dstPath := filepath.Join(targetDir, "wintun.dll")
	if strings.EqualFold(filepath.Clean(srcPath), filepath.Clean(dstPath)) {
		return nil
	}
	srcInfo, err := os.Stat(srcPath)
	if err != nil || srcInfo.IsDir() || srcInfo.Size() == 0 {
		return err
	}
	if dstInfo, derr := os.Stat(dstPath); derr == nil && !dstInfo.IsDir() && dstInfo.Size() == srcInfo.Size() {
		return nil
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpPath := dstPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func formatTUNError(err error) string {
	s := err.Error()
	if strings.Contains(strings.ToLower(s), "access is denied") {
		return "ต้องคลิกขวา Run as Administrator เพื่อสร้างการ์ดแลนจำลอง L3 VPN (Wintun)"
	}
	return fmt.Sprintf("เปิดการ์ดแลน Wintun ไม่สำเร็จ: %v (ต้องรันแบบ Run as Administrator)", err)
}

func configureInterfaceIP(ifName, ip string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+ifName, "source=static", "addr="+ip, "mask=255.255.0.0", "gateway=none")
	executil.HideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	runHidden := func(name string, args ...string) {
		c := exec.Command(name, args...)
		executil.HideWindow(c)
		_ = c.Run()
	}
	runHidden("netsh", "interface", "ipv4", "set", "subinterface",
		ifName, "mtu="+strconv.Itoa(mtu), "store=active")

	// Set RelayVPN adapter to Private profile so Windows services (Sunshine/Moonlight/RDP/SMB) bind cleanly.
	runHidden("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		fmt.Sprintf(`Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction SilentlyContinue`, ifName))

	// Allow inbound traffic strictly inside the encrypted 10.99.0.0/16 Virtual LAN so ping/Moonlight/RDP work
	// without exposing any ports on public Wi-Fi/Ethernet interfaces.
	runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name=RelayVPN Virtual LAN")
	runHidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name=RelayVPN Virtual LAN",
		"dir=in",
		"action=allow",
		"localip=10.99.0.0/16",
		"remoteip=10.99.0.0/16",
		"profile=any",
	)
	return nil
}
