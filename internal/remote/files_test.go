package remote

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"relayvpn/internal/protocol"
)

func TestFileTransferListUploadDownload(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Test Upload
	c1, s1 := net.Pipe()
	go func() { _ = ServeFileStream(s1, nil, nil) }()

	payload := bytes.Repeat([]byte("APN-P2P-FILE-TEST-"), 4096) // ~73 KB
	if err := protocol.WriteMessage(c1, FileRequest{
		Action: "upload",
		Path:   tmpDir,
		Name:   "hello.bin",
		Size:   int64(len(payload)),
	}); err != nil {
		t.Fatalf("write upload req: %v", err)
	}
	var ready FileResponse
	if err := protocol.ReadMessage(c1, &ready); err != nil || !ready.OK {
		t.Fatalf("upload ready failed: resp=%+v err=%v", ready, err)
	}
	if _, err := c1.Write(payload); err != nil {
		t.Fatalf("write upload bytes: %v", err)
	}
	var done FileResponse
	if err := protocol.ReadMessage(c1, &done); err != nil || !done.OK || done.Bytes != int64(len(payload)) {
		t.Fatalf("upload finish failed: resp=%+v err=%v", done, err)
	}
	_ = c1.Close()

	// 2. Test List
	c2, s2 := net.Pipe()
	go func() { _ = ServeFileStream(s2, nil, nil) }()
	if err := protocol.WriteMessage(c2, FileRequest{Action: "list", Path: tmpDir}); err != nil {
		t.Fatalf("write list req: %v", err)
	}
	var listResp FileResponse
	if err := protocol.ReadMessage(c2, &listResp); err != nil || !listResp.OK || len(listResp.Entries) != 1 || listResp.Entries[0].Name != "hello.bin" {
		t.Fatalf("unexpected list response: %+v err=%v", listResp, err)
	}
	_ = c2.Close()

	// 3. Test Download
	c3, s3 := net.Pipe()
	go func() { _ = ServeFileStream(s3, nil, nil) }()
	if err := protocol.WriteMessage(c3, FileRequest{Action: "download", Path: filepath.Join(tmpDir, "hello.bin")}); err != nil {
		t.Fatalf("write download req: %v", err)
	}
	var dlHdr FileResponse
	if err := protocol.ReadMessage(c3, &dlHdr); err != nil || !dlHdr.OK || dlHdr.Size != int64(len(payload)) {
		t.Fatalf("download header failed: %+v err=%v", dlHdr, err)
	}
	got, err := io.ReadAll(io.LimitReader(c3, dlHdr.Size))
	if err != nil {
		t.Fatalf("read download body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded content mismatch: got %d bytes want %d", len(got), len(payload))
	}
	_ = c3.Close()

	// 4. Test Delete
	c4, s4 := net.Pipe()
	go func() { _ = ServeFileStream(s4, nil, nil) }()
	if err := protocol.WriteMessage(c4, FileRequest{Action: "delete", Path: filepath.Join(tmpDir, "hello.bin")}); err != nil {
		t.Fatalf("write delete req: %v", err)
	}
	var delResp FileResponse
	if err := protocol.ReadMessage(c4, &delResp); err != nil || !delResp.OK {
		t.Fatalf("delete failed: %+v err=%v", delResp, err)
	}
	_ = c4.Close()
	if _, err := os.Stat(filepath.Join(tmpDir, "hello.bin")); !os.IsNotExist(err) {
		t.Fatalf("expected file deleted, got err=%v", err)
	}
}
