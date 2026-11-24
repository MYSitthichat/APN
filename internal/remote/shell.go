package remote

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ServeShellSession runs an interactive local shell and pipes stdin/stdout/stderr over stream.
func ServeShellSession(ctx context.Context, stream io.ReadWriteCloser, bytesSent, bytesRecv *atomic.Int64) error {
	shellCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(shellCtx, "powershell.exe", "-NoLogo", "-NoProfile", "-Command", "-")
	} else {
		shellBin := "/bin/sh"
		if _, err := exec.LookPath("/bin/bash"); err == nil {
			shellBin = "/bin/bash"
		}
		cmd = exec.CommandContext(shellCtx, shellBin)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("shell stdin pipe: %w", err)
	}
	// Own pipes instead of StdoutPipe/StderrPipe: cmd.Wait closes those as soon as the shell
	// exits, which could drop the last output (e.g. "echo done; exit") before it was read.
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("shell stdout pipe: %w", err)
	}
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdout.Close()
		_ = stdoutW.Close()
		return fmt.Errorf("shell stderr pipe: %w", err)
	}
	defer stdout.Close()
	defer stderr.Close()
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	err = cmd.Start()
	// The shell holds its own copies of the write ends; ours must close so reads reach EOF.
	_ = stdoutW.Close()
	_ = stderrW.Close()
	if err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	var writeMu sync.Mutex
	writeOut := func(r io.Reader) {
		buf := make([]byte, 8192)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				writeMu.Lock()
				_, werr := stream.Write(buf[:n])
				writeMu.Unlock()
				if bytesSent != nil {
					bytesSent.Add(int64(n))
				}
				if werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		writeOut(stdout)
	}()
	go func() {
		defer wg.Done()
		writeOut(stderr)
	}()

	// Copy incoming commands from client to shell stdin
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if bytesRecv != nil {
					bytesRecv.Add(int64(n))
				}
				if _, werr := stdin.Write(buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				_ = stdin.Close()
				cancel()
				return
			}
		}
	}()

	err = cmd.Wait()
	// Send everything the shell printed before it exited. A background job that inherited the
	// output pipes could keep them open forever, so stop waiting after a short grace period.
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		_ = stdout.Close()
		_ = stderr.Close()
		<-drained
	}
	_ = stream.Close()
	return err
}
