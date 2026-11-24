package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func runShellScript(t *testing.T, script string) string {
	t.Helper()
	client, host := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeShellSession(context.Background(), host, nil, nil)
	}()
	go func() { _, _ = client.Write([]byte(script)) }()
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	out, _ := io.ReadAll(client)
	_ = client.Close()
	<-done
	return string(out)
}

// TestShellSessionKeepsLastOutput runs many short sessions at once: the output printed right
// before the shell exits must always arrive (cmd.Wait used to close the pipe before it was read).
func TestShellSessionKeepsLastOutput(t *testing.T) {
	n := 24
	if runtime.GOOS == "windows" {
		n = 4 // powershell starts slowly
	}
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			marker := fmt.Sprintf("DONE_%d_OK", i)
			if out := runShellScript(t, "echo "+marker+"\nexit\n"); !strings.Contains(out, marker) {
				errs <- fmt.Sprintf("session %d lost its output: %q", i, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestShellSessionBackgroundJobDoesNotHang: a background job that keeps the output pipe open
// must not keep the session open after the shell itself exits.
func TestShellSessionBackgroundJobDoesNotHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX background job")
	}
	start := time.Now()
	out := runShellScript(t, "sleep 30 &\necho BG_OK\nexit\n")
	if !strings.Contains(out, "BG_OK") {
		t.Fatalf("output %q", out)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("session stayed open %v after the shell exited", d)
	}
}
