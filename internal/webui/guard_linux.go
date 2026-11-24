//go:build linux

package webui

import (
	"fmt"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"

	"relayvpn/internal/remote"
)

// callerAllowed identifies the account owning the client end of a loopback TCP connection from
// /proc/net/tcp and allows this process's uid, root, and (when we run as root) the user logged in
// on the screen.
func callerAllowed(r *http.Request) (bool, string) {
	ip, cport, sport, ok := localConnPorts(r)
	if !ok {
		return false, "not a loopback connection"
	}
	files := []string{"/proc/net/tcp"}
	if ip.To4() == nil {
		files = []string{"/proc/net/tcp6"}
	}
	uid, found := -1, false
	for _, f := range files {
		if uid, found = tcpOwnerUID(f, cport, sport); found {
			break
		}
	}
	if !found {
		return false, "cannot identify the calling account"
	}
	self := os.Geteuid()
	if uid == 0 || uid == self {
		return true, ""
	}
	if self == 0 {
		if du, ok := remote.ActiveDesktopUID(); ok && uid == du {
			return true, ""
		}
		// Administrators (sudo/wheel/admin) could become root anyway; allowing them keeps
		// "ssh -L 18480:127.0.0.1:18480" access to a headless service working.
		if isAdminUID(uid) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("uid %d is not allowed", uid)
}

var adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true}

func isAdminUID(uid int) bool {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, gid := range gids {
		if g, err := user.LookupGroupId(gid); err == nil && adminGroups[g.Name] {
			return true
		}
	}
	return false
}

// tcpOwnerUID finds the socket whose local port is clientPort and remote port is serverPort
// (the client's end) and returns its owner uid.
func tcpOwnerUID(path string, clientPort, serverPort int) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1, false
	}
	return parseTCPOwnerUID(string(data), clientPort, serverPort)
}

func parseTCPOwnerUID(table string, clientPort, serverPort int) (int, bool) {
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || !strings.Contains(f[1], ":") {
			continue
		}
		if hexPort(f[1]) != clientPort || hexPort(f[2]) != serverPort {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			return -1, false
		}
		return uid, true
	}
	return -1, false
}

func hexPort(addr string) int {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return -1
	}
	n, err := strconv.ParseUint(addr[i+1:], 16, 16)
	if err != nil {
		return -1
	}
	return int(n)
}
