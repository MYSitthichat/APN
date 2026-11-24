//go:build linux

package webui

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParseTCPOwnerUID(t *testing.T) {
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4850 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C350 0100007F:4850 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:4850 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 -1
`
	// client 127.0.0.1:50000 (0xC350) -> server :18512 (0x4850): the client row is owned by uid 1001.
	if uid, ok := parseTCPOwnerUID(table, 50000, 0x4850); !ok || uid != 1001 {
		t.Fatalf("got uid=%d ok=%v, want 1001", uid, ok)
	}
	if _, ok := parseTCPOwnerUID(table, 50001, 0x4850); ok {
		t.Fatal("found a non-existent connection")
	}
}

// TestGuardFetchHelper is the client half of TestLocalGuardRefusesOtherLinuxUser, run in a child
// process under another uid.
func TestGuardFetchHelper(t *testing.T) {
	url := os.Getenv("APN_GUARD_FETCH_URL")
	if url == "" {
		t.Skip("helper")
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fmt.Println("STATUS=" + strconv.Itoa(resp.StatusCode))
}

func fetchAs(t *testing.T, url string, cred *syscall.Credential) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGuardFetchHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "APN_GUARD_FETCH_URL="+url)
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	for _, l := range strings.Fields(string(out)) {
		if strings.HasPrefix(l, "STATUS=") {
			return strings.TrimPrefix(l, "STATUS=")
		}
	}
	t.Fatalf("no status in helper output: %s", out)
	return ""
}

func TestLocalGuardRefusesOtherLinuxUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a client as another uid")
	}
	srv, _ := newGuardedServer(t)
	if got := fetchAs(t, srv.URL+"/api/state", &syscall.Credential{Uid: 65534, Gid: 65534}); got != "403" {
		t.Fatalf("uid 65534 got %s, want 403", got)
	}
	if got := fetchAs(t, srv.URL+"/api/state", nil); got != "200" {
		t.Fatalf("root (another process) got %s, want 200", got)
	}
}
