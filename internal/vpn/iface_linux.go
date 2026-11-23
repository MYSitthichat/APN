//go:build linux

package vpn

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func defaultTUNName() string {
	return "relayvpn0"
}

func preflightTUN() error {
	return nil
}

func formatTUNError(err error) string {
	return fmt.Sprintf("เปิด /dev/net/tun ไม่สำเร็จ (ต้องรันด้วย sudo หรือ CAP_NET_ADMIN): %v", err)
}

func configureInterfaceIP(ifName, ip string, mtu int) error {
	if out, err := exec.Command("ip", "addr", "replace", ip+"/16", "dev", ifName).CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "link", "set", "dev", ifName, "mtu", strconv.Itoa(mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
