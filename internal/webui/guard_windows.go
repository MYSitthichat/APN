//go:build windows

package webui

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const (
	afINET                     = 2
	tcpTableOwnerPIDConnection = 4
	sidLocalSystem             = "S-1-5-18"
	sidAdministrators          = "S-1-5-32-544"
)

// callerAllowed finds the process owning the client end of a loopback TCP connection
// (GetExtendedTcpTable) and allows this process, processes of this process's account, SYSTEM,
// and the user logged on to the active console session.
func callerAllowed(r *http.Request) (bool, string) {
	ip, cport, sport, ok := localConnPorts(r)
	if !ok || ip.To4() == nil {
		return false, "not an IPv4 loopback connection"
	}
	pid, ok := tcpOwnerPID(cport, sport)
	if !ok {
		return false, "cannot identify the calling process"
	}
	if int(pid) == os.Getpid() {
		return true, ""
	}
	sid, admin, err := processUser(pid)
	if err != nil {
		return false, "cannot read the calling account: " + err.Error()
	}
	for _, a := range allowedSIDs() {
		if sid == a {
			return true, ""
		}
	}
	// Members of Administrators (even non-elevated, e.g. over RDP) could take over the SYSTEM
	// service anyway, so they are allowed too.
	if admin {
		return true, ""
	}
	return false, fmt.Sprintf("account %s is not allowed", sid)
}

var (
	allowedMu   sync.Mutex
	allowedList []string
	allowedAt   time.Time
)

// allowedSIDs: our own account, SYSTEM, and the active console user (resolved only when we run as
// SYSTEM, which is what WTSQueryUserToken requires). Cached briefly; the console user can change.
func allowedSIDs() []string {
	allowedMu.Lock()
	defer allowedMu.Unlock()
	if time.Since(allowedAt) < 5*time.Second && allowedList != nil {
		return allowedList
	}
	list := []string{sidLocalSystem}
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		list = append(list, tu.User.Sid.String())
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(windows.WTSGetActiveConsoleSessionId(), &tok); err == nil {
		if tu, err := tok.GetTokenUser(); err == nil {
			list = append(list, tu.User.Sid.String())
		}
		_ = tok.Close()
	}
	allowedList, allowedAt = list, time.Now()
	return list
}

// processUser returns the caller's account SID and whether its token lists the Administrators
// group (enabled or deny-only, i.e. elevated or not).
func processUser(pid uint32) (string, bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", false, err
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	admin := false
	if tg, err := tok.GetTokenGroups(); err == nil {
		for _, g := range tg.AllGroups() {
			if g.Sid.String() == sidAdministrators {
				admin = true
				break
			}
		}
	}
	return tu.User.Sid.String(), admin, nil
}

// tcpOwnerPID returns the PID owning the IPv4 TCP connection 127.0.0.1:clientPort -> :serverPort.
func tcpOwnerPID(clientPort, serverPort int) (uint32, bool) {
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDConnection, 0)
	for attempt := 0; attempt < 3 && size > 0; attempt++ {
		buf := make([]byte, size+4096)
		size = uint32(len(buf))
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDConnection, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return 0, false
		}
		return findOwnerPID(buf, clientPort, serverPort)
	}
	return 0, false
}

// findOwnerPID parses MIB_TCPTABLE_OWNER_PID: a uint32 count followed by rows of six uint32
// (state, localAddr, localPort, remoteAddr, remotePort, owningPid); ports are in network byte order.
func findOwnerPID(buf []byte, clientPort, serverPort int) (uint32, bool) {
	if len(buf) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	const rowSize = 24
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		lport := int(netPort(binary.LittleEndian.Uint32(row[8:12])))
		rport := int(netPort(binary.LittleEndian.Uint32(row[16:20])))
		if lport == clientPort && rport == serverPort {
			return binary.LittleEndian.Uint32(row[20:24]), true
		}
	}
	return 0, false
}

func netPort(v uint32) uint16 {
	return uint16(v&0xff)<<8 | uint16(v>>8&0xff)
}
