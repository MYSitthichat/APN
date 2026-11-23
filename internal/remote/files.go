package remote

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"relayvpn/internal/protocol"
)

// FileRequest is sent right after StreamOpenResponse{OK:true} on a ModeFiles stream.
type FileRequest struct {
	Action string `json:"action"`          // "list", "download", "upload", "mkdir", "delete"
	Path   string `json:"path,omitempty"`  // directory or file path (empty = user home, "__roots__" = drives/root)
	Name   string `json:"name,omitempty"`  // filename for upload / folder name for mkdir
	Size   int64  `json:"size,omitempty"`  // byte size for upload (-1 if unknown/stream-to-EOF)
}

// FileEntry describes a single file or directory on the remote peer.
type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time,omitempty"`
}

// FileShortcut provides 1-click navigation pills (Home, Desktop, Downloads, Drives).
type FileShortcut struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

// FileResponse is the JSON header returned on a ModeFiles stream (followed by raw bytes for "download").
type FileResponse struct {
	OK        bool           `json:"ok"`
	Error     string         `json:"error,omitempty"`
	Path      string         `json:"path,omitempty"`
	Parent    string         `json:"parent,omitempty"`
	OS        string         `json:"os,omitempty"`
	Name      string         `json:"name,omitempty"`
	Size      int64          `json:"size,omitempty"`
	Bytes     int64          `json:"bytes,omitempty"`
	Entries   []FileEntry    `json:"entries,omitempty"`
	Shortcuts []FileShortcut `json:"shortcuts,omitempty"`
}

// ServeFileStream handles one encrypted P2P file operation (list, download, upload, mkdir, delete)
// with zero-RAM 256 KB streaming so multi-GB files transfer at full QUIC/LAN speed!
func ServeFileStream(stream io.ReadWriteCloser, sentCounter, recvCounter *atomic.Int64) error {
	defer stream.Close()

	var req FileRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		return err
	}

	switch req.Action {
	case "list":
		resp := buildListResponse(req.Path)
		return protocol.WriteMessage(stream, resp)

	case "download":
		return handleRemoteDownload(stream, req.Path, sentCounter)

	case "upload":
		return handleRemoteUpload(stream, req, recvCounter)

	case "mkdir":
		if strings.TrimSpace(req.Path) == "" {
			return protocol.WriteMessage(stream, FileResponse{OK: false, Error: "กรุณาระบุโฟลเดอร์ปลายทาง"})
		}
		target := req.Path
		if strings.TrimSpace(req.Name) != "" {
			target = filepath.Join(req.Path, filepath.Base(strings.TrimSpace(req.Name)))
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
		}
		return protocol.WriteMessage(stream, FileResponse{OK: true, Path: target})

	case "delete":
		target := filepath.Clean(strings.TrimSpace(req.Path))
		if target == "" || target == "." || target == "/" || (len(target) <= 3 && strings.HasSuffix(target, `:\`)) {
			return protocol.WriteMessage(stream, FileResponse{OK: false, Error: "ไม่อนุญาตให้ลบโฟลเดอร์หลักของระบบ"})
		}
		if err := os.RemoveAll(target); err != nil {
			return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
		}
		return protocol.WriteMessage(stream, FileResponse{OK: true, Path: target})

	default:
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: "unsupported file action"})
	}
}

func defaultShortcuts() []FileShortcut {
	var out []FileShortcut
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, FileShortcut{Label: "🏠 Home", Path: home})
		for _, sub := range []struct{ label, dir string }{
			{"🖥 Desktop", "Desktop"},
			{"📥 Downloads", "Downloads"},
			{"📄 Documents", "Documents"},
		} {
			p := filepath.Join(home, sub.dir)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				out = append(out, FileShortcut{Label: sub.label, Path: p})
			}
		}
	}
	if runtime.GOOS == "windows" {
		out = append(out, FileShortcut{Label: "💾 Drives", Path: "__roots__"})
	} else {
		out = append(out, FileShortcut{Label: "💾 /", Path: "/"})
	}
	return out
}

func buildListResponse(rawPath string) FileResponse {
	shortcuts := defaultShortcuts()
	p := strings.TrimSpace(rawPath)

	if p == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			p = home
		} else if runtime.GOOS == "windows" {
			p = "__roots__"
		} else {
			p = "/"
		}
	}

	// Windows drive root picker
	if p == "__roots__" && runtime.GOOS == "windows" {
		var drives []FileEntry
		for ch := 'A'; ch <= 'Z'; ch++ {
			root := fmt.Sprintf("%c:\\", ch)
			if _, err := os.Stat(root); err == nil {
				drives = append(drives, FileEntry{
					Name:  fmt.Sprintf("Drive (%c:)", ch),
					Path:  root,
					IsDir: true,
				})
			}
		}
		return FileResponse{
			OK:        true,
			Path:      "__roots__",
			Parent:    "",
			OS:        runtime.GOOS,
			Entries:   drives,
			Shortcuts: shortcuts,
		}
	}

	cleanPath := filepath.Clean(p)
	dirEntries, err := os.ReadDir(cleanPath)
	if err != nil {
		return FileResponse{OK: false, Error: err.Error(), Path: cleanPath, OS: runtime.GOOS, Shortcuts: shortcuts}
	}

	entries := make([]FileEntry, 0, len(dirEntries))
	for _, de := range dirEntries {
		info, ierr := de.Info()
		var sz int64
		var mod string
		if ierr == nil && info != nil {
			sz = info.Size()
			mod = info.ModTime().UTC().Format(time.RFC3339)
		}
		entries = append(entries, FileEntry{
			Name:    de.Name(),
			Path:    filepath.Join(cleanPath, de.Name()),
			IsDir:   de.IsDir(),
			Size:    sz,
			ModTime: mod,
		})
	}
	slices.SortFunc(entries, func(a, b FileEntry) int {
		if a.IsDir != b.IsDir {
			if a.IsDir {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})

	parent := filepath.Dir(cleanPath)
	if parent == cleanPath {
		if runtime.GOOS == "windows" {
			parent = "__roots__"
		} else {
			parent = ""
		}
	}

	return FileResponse{
		OK:        true,
		Path:      cleanPath,
		Parent:    parent,
		OS:        runtime.GOOS,
		Entries:   entries,
		Shortcuts: shortcuts,
	}
}

func handleRemoteDownload(stream io.ReadWriteCloser, filePath string, sentCounter *atomic.Int64) error {
	clean := filepath.Clean(strings.TrimSpace(filePath))
	f, err := os.Open(clean)
	if err != nil {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
	}
	if st.IsDir() {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: "ไม่สามารถดาวน์โหลดโฟลเดอร์โดยตรงได้ (เลือกไฟล์ภายในโฟลเดอร์แทน)"})
	}

	if err := protocol.WriteMessage(stream, FileResponse{
		OK:   true,
		Path: clean,
		Name: st.Name(),
		Size: st.Size(),
	}); err != nil {
		return err
	}

	buf := make([]byte, 256*1024)
	n, err := io.CopyBuffer(stream, f, buf)
	if sentCounter != nil && n > 0 {
		sentCounter.Add(n)
	}
	return err
}

func handleRemoteUpload(stream io.ReadWriteCloser, req FileRequest, recvCounter *atomic.Int64) error {
	dir := strings.TrimSpace(req.Path)
	if dir == "" || dir == "__roots__" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, "Downloads")
		} else {
			dir = os.TempDir()
		}
	}
	name := filepath.Base(strings.TrimSpace(req.Name))
	if name == "" || name == "." || name == "/" || name == `\` {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: "ชื่อไฟล์ไม่ถูกต้อง"})
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
	}

	finalPath := filepath.Join(dir, name)
	tmpPath := finalPath + ".apnpart"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
	}

	// Signal ready-to-receive so client begins streaming raw file bytes!
	if err := protocol.WriteMessage(stream, FileResponse{OK: true, Path: finalPath, Name: name}); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	buf := make([]byte, 256*1024)
	var written int64
	var copyErr error
	if req.Size >= 0 {
		written, copyErr = io.CopyBuffer(out, io.LimitReader(stream, req.Size), buf)
	} else {
		written, copyErr = io.CopyBuffer(out, stream, buf)
	}
	if recvCounter != nil && written > 0 {
		recvCounter.Add(written)
	}
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || (req.Size >= 0 && written != req.Size) {
		_ = os.Remove(tmpPath)
		if copyErr == nil && closeErr != nil {
			copyErr = closeErr
		}
		if copyErr == nil {
			copyErr = fmt.Errorf("incomplete upload: received %d of %d bytes", written, req.Size)
		}
		_ = protocol.WriteMessage(stream, FileResponse{OK: false, Error: copyErr.Error()})
		return copyErr
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		_ = protocol.WriteMessage(stream, FileResponse{OK: false, Error: err.Error()})
		return err
	}
	return protocol.WriteMessage(stream, FileResponse{OK: true, Path: finalPath, Name: name, Bytes: written})
}
