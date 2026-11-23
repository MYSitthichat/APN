//go:build darwin

package vpn

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func defaultTUNName() string {
	return "utun"
}

func preflightTUN() error {
	return nil
}

func formatTUNError(err error) string {
	return fmt.Sprintf("เปิด utun บน macOS ไม่สำเร็จ (ต้องรันด้วย sudo): %v", err)
}

func configureInterfaceIP(ifName, ip string, mtu int) error {
	if out, err := exec.Command("ifconfig", ifName, "inet", ip, ip, "netmask", "255.255.0.0", "mtu", strconv.Itoa(mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("route", "-n", "delete", "-net", "10.99.0.0/16").Run()
	if out, err := exec.Command("route", "-n", "add", "-net", "10.99.0.0/16", "-interface", ifName).CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
