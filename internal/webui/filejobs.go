package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relayvpn/internal/protocol"
	"relayvpn/internal/remote"
)

// File transfer jobs: send or fetch any mix of files and folders in one request.
//
// A folder is expanded into its files (local: a directory walk; remote: repeated "list"
// requests, which every host version answers), and each file travels over its own stream
// with the existing "upload"/"download" actions, so no host update is needed. Up to
// fileJobWorkers files move at once: small files no longer wait one round trip each.
//
// Progress belongs to the job (fileJobs), not to a process-wide counter: two transfers at the
// same time used to add their bytes to one total, which showed e.g. 575 MB of a 389 MB file.

const (
	fileJobWorkers  = 4
	fileJobMaxFiles = 200_000
	fileJobMaxDepth = 64
)

// fileStreamOpener opens one ModeFiles stream to the peer.
type fileStreamOpener func(ctx context.Context) (io.ReadWriteCloser, error)

// fileJobItem is one entry the user selected.
type fileJobItem struct {
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

// fileJobPlanEntry is one file to move, or (Size < 0) an empty folder to create.
type fileJobPlanEntry struct {
	src     string // local path (push) or remote path (pull)
	destDir string // remote dir (push) or local dir (pull)
	name    string
	size    int64
	mkdir   bool // create destDir only (empty folder)
}

type fileJob struct {
	ID        string
	Direction string // "push" or "pull"

	mu        sync.Mutex
	active    bool
	files     int
	done      int
	failed    int
	current   string
	firstErr  string
	total     int64
	startedAt time.Time
	cancel    context.CancelFunc

	bytes      atomic.Int64
	rateAt     time.Time
	rateBytes  int64
	rateBPS    float64
	finishedAt time.Time
}

// fileJobStatus is what the viewer polls.
type fileJobStatus struct {
	ID          string  `json:"id"`
	Active      bool    `json:"active"`
	Direction   string  `json:"direction"`
	Files       int     `json:"files"`
	Done        int     `json:"done"`
	Failed      int     `json:"failed"`
	Current     string  `json:"current,omitempty"`
	Bytes       int64   `json:"bytes"`
	Total       int64   `json:"total"`
	BytesPerSec float64 `json:"bytes_per_sec"`
	Error       string  `json:"error,omitempty"`
}

var fileJobs = struct {
	mu sync.Mutex
	m  map[string]*fileJob
}{m: map[string]*fileJob{}}

func newFileJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func registerFileJob(id, dir string, cancel context.CancelFunc) *fileJob {
	if id == "" {
		id = newFileJobID()
	}
	j := &fileJob{ID: id, Direction: dir, active: true, startedAt: time.Now(), cancel: cancel}
	j.rateAt = j.startedAt
	fileJobs.mu.Lock()
	// Forget jobs that ended more than 10 minutes ago.
	for k, old := range fileJobs.m {
		old.mu.Lock()
		stale := !old.active && time.Since(old.finishedAt) > 10*time.Minute
		old.mu.Unlock()
		if stale {
			delete(fileJobs.m, k)
		}
	}
	fileJobs.m[id] = j
	fileJobs.mu.Unlock()
	return j
}

func lookupFileJob(id string) *fileJob {
	fileJobs.mu.Lock()
	defer fileJobs.mu.Unlock()
	return fileJobs.m[id]
}

func (j *fileJob) status() fileJobStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	b := j.bytes.Load()
	// Speed over the last second or more, so it follows the link instead of the job average.
	if now := time.Now(); now.Sub(j.rateAt) >= time.Second {
		j.rateBPS = float64(b-j.rateBytes) / now.Sub(j.rateAt).Seconds()
		j.rateAt, j.rateBytes = now, b
	} else if j.rateBPS == 0 && b > 0 {
		// First second: the average so far, instead of showing 0 B/s.
		if el := now.Sub(j.startedAt).Seconds(); el > 0.05 {
			j.rateBPS = float64(b) / el
		}
	}
	return fileJobStatus{
		ID: j.ID, Active: j.active, Direction: j.Direction, Files: j.files, Done: j.done, Failed: j.failed,
		Current: j.current, Bytes: b, Total: j.total, BytesPerSec: j.rateBPS, Error: j.firstErr,
	}
}

func (j *fileJob) fileDone(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		j.failed++
		if j.firstErr == "" {
			j.firstErr = err.Error()
		}
		return
	}
	j.done++
}

func (j *fileJob) finish() {
	j.mu.Lock()
	j.active = false
	j.finishedAt = time.Now()
	j.mu.Unlock()
}

// countingWriter adds every write to the job's byte count.
type countingWriter struct {
	w io.Writer
	j *fileJob
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.j.bytes.Add(int64(n))
	}
	return n, err
}

// joinRemotePath joins path parts in the remote machine's style. base is an absolute path from
// a remote listing, so a backslash or a drive letter means Windows.
func joinRemotePath(base string, parts ...string) string {
	sep := "/"
	if strings.Contains(base, `\`) || (len(base) >= 2 && base[1] == ':') {
		sep = `\`
	}
	b := strings.TrimRight(base, `\/`)
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		b += sep + p
	}
	if b == "" {
		return "/"
	}
	if len(b) == 2 && b[1] == ':' {
		return b + `\`
	}
	return b
}

// remoteBaseName is the last element of a remote path in either style.
func remoteBaseName(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// safeName refuses names that would leave the destination folder.
func safeName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, `/\`) && !strings.Contains(n, "\x00")
}

// planPush expands the selected local files and folders. Each folder lands as a folder of the
// same name inside remoteDir.
func planPush(items []fileJobItem, remoteDir string) ([]fileJobPlanEntry, error) {
	var plan []fileJobPlanEntry
	seen := map[string]bool{}
	for _, it := range items {
		src := filepath.Clean(it.Path)
		if seen[src] {
			continue
		}
		seen[src] = true
		st, err := os.Stat(src)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			plan = append(plan, fileJobPlanEntry{src: src, destDir: remoteDir, name: st.Name(), size: st.Size()})
			continue
		}
		root := filepath.Base(src)
		hasFile := map[string]bool{}
		var dirs []string
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return nil // unreadable entry: skip it, keep the rest
			}
			rel, _ := filepath.Rel(src, p)
			parts := []string{root}
			if rel != "." {
				parts = append(parts, strings.Split(filepath.ToSlash(rel), "/")...)
			}
			if len(parts) > fileJobMaxDepth {
				return filepath.SkipDir
			}
			if d.IsDir() {
				dirs = append(dirs, strings.Join(parts, "/"))
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // symlinks, devices, sockets
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if len(plan) >= fileJobMaxFiles {
				return errors.New("โฟลเดอร์มีไฟล์มากเกินไป (เกิน 200,000 ไฟล์)")
			}
			dirParts := parts[:len(parts)-1]
			for i := range dirParts {
				hasFile[strings.Join(dirParts[:i+1], "/")] = true
			}
			plan = append(plan, fileJobPlanEntry{src: p, destDir: joinRemotePath(remoteDir, dirParts...), name: d.Name(), size: info.Size()})
			return nil
		})
		if err != nil {
			return nil, err
		}
		for _, d := range dirs {
			if !hasFile[d] {
				plan = append(plan, fileJobPlanEntry{destDir: joinRemotePath(remoteDir, strings.Split(d, "/")...), mkdir: true, size: -1})
			}
		}
	}
	return plan, nil
}

// remoteList runs one "list" request.
func remoteList(ctx context.Context, open fileStreamOpener, dir string) (remote.FileResponse, error) {
	st, err := open(ctx)
	if err != nil {
		return remote.FileResponse{}, err
	}
	defer st.Close()
	if err := protocol.WriteMessage(st, remote.FileRequest{Action: "list", Path: dir}); err != nil {
		return remote.FileResponse{}, err
	}
	var resp remote.FileResponse
	if err := protocol.ReadMessage(st, &resp); err != nil {
		return remote.FileResponse{}, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// planPull expands the selected remote files and folders by listing remote folders.
func planPull(ctx context.Context, open fileStreamOpener, items []fileJobItem, localDir string) ([]fileJobPlanEntry, error) {
	var plan []fileJobPlanEntry
	seen := map[string]bool{}
	var walk func(remoteDir string, parts []string) error
	walk = func(remoteDir string, parts []string) error {
		if len(parts) > fileJobMaxDepth {
			return nil
		}
		resp, err := remoteList(ctx, open, remoteDir)
		if err != nil {
			return fmt.Errorf("เปิดโฟลเดอร์ %s ไม่ได้: %w", remoteDir, err)
		}
		dest := filepath.Join(append([]string{localDir}, parts...)...)
		if len(resp.Entries) == 0 {
			plan = append(plan, fileJobPlanEntry{destDir: dest, mkdir: true, size: -1})
		}
		for _, e := range resp.Entries {
			if !safeName(e.Name) {
				continue
			}
			if e.IsDir {
				if err := walk(e.Path, append(append([]string{}, parts...), e.Name)); err != nil {
					return err
				}
				continue
			}
			if len(plan) >= fileJobMaxFiles {
				return errors.New("โฟลเดอร์มีไฟล์มากเกินไป (เกิน 200,000 ไฟล์)")
			}
			plan = append(plan, fileJobPlanEntry{src: e.Path, destDir: dest, name: e.Name, size: e.Size})
		}
		return nil
	}
	for _, it := range items {
		if seen[it.Path] {
			continue
		}
		seen[it.Path] = true
		name := remoteBaseName(it.Path)
		if !safeName(name) {
			return nil, fmt.Errorf("ชื่อไม่ถูกต้อง: %s", it.Path)
		}
		if !it.IsDir {
			plan = append(plan, fileJobPlanEntry{src: it.Path, destDir: localDir, name: name, size: -2})
			continue
		}
		if err := walk(it.Path, []string{name}); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

// closeOnCancel closes c when ctx ends, so a cancelled job stops copying at once.
func closeOnCancel(ctx context.Context, c io.Closer) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// pushFile sends one local file into remoteDir over a new stream.
func pushFile(ctx context.Context, open fileStreamOpener, j *fileJob, e fileJobPlanEntry) error {
	st, err := open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	defer closeOnCancel(ctx, st)()
	if e.mkdir {
		if err := protocol.WriteMessage(st, remote.FileRequest{Action: "mkdir", Path: e.destDir}); err != nil {
			return err
		}
		var resp remote.FileResponse
		if err := protocol.ReadMessage(st, &resp); err != nil {
			return err
		}
		if !resp.OK {
			return errors.New(resp.Error)
		}
		return nil
	}
	src, err := os.Open(e.src)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	if err := protocol.WriteMessage(st, remote.FileRequest{Action: "upload", Path: e.destDir, Name: e.name, Size: info.Size()}); err != nil {
		return err
	}
	var ready remote.FileResponse
	if err := protocol.ReadMessage(st, &ready); err != nil {
		return err
	}
	if !ready.OK {
		return fmt.Errorf("%s: %s", e.name, ready.Error)
	}
	buf := make([]byte, 256*1024)
	// LimitReader: a file that grows while it is sent must not overrun the size announced above.
	if _, err := io.CopyBuffer(countingWriter{w: st, j: j}, io.LimitReader(src, info.Size()), buf); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %w", e.name, err)
	}
	var done remote.FileResponse
	if err := protocol.ReadMessage(st, &done); err != nil {
		return fmt.Errorf("%s: %w", e.name, err)
	}
	if !done.OK {
		return fmt.Errorf("%s: %s", e.name, done.Error)
	}
	return nil
}

// pullFile fetches one remote file into localDir over a new stream.
func pullFile(ctx context.Context, open fileStreamOpener, j *fileJob, e fileJobPlanEntry) error {
	if err := os.MkdirAll(e.destDir, 0o755); err != nil {
		return err
	}
	if e.mkdir {
		return nil
	}
	st, err := open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	defer closeOnCancel(ctx, st)()
	if err := protocol.WriteMessage(st, remote.FileRequest{Action: "download", Path: e.src}); err != nil {
		return err
	}
	var hdr remote.FileResponse
	if err := protocol.ReadMessage(st, &hdr); err != nil {
		return err
	}
	if !hdr.OK {
		return fmt.Errorf("%s: %s", e.name, hdr.Error)
	}
	if e.size == -2 { // a single selected file: its size is known only now
		j.mu.Lock()
		j.total += hdr.Size
		j.mu.Unlock()
	}
	finalPath := filepath.Join(e.destDir, e.name)
	tmpPath := finalPath + "." + newFileJobID()[:6] + ".apnpart"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	buf := make([]byte, 256*1024)
	written, copyErr := io.CopyBuffer(countingWriter{w: out, j: j}, io.LimitReader(st, hdr.Size), buf)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || written != hdr.Size {
		_ = os.Remove(tmpPath)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case copyErr != nil:
			return fmt.Errorf("%s: %w", e.name, copyErr)
		case closeErr != nil:
			return fmt.Errorf("%s: %w", e.name, closeErr)
		}
		return fmt.Errorf("%s: ดาวน์โหลดไม่ครบ (%d จาก %d ไบต์)", e.name, written, hdr.Size)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// runFileJob plans and runs a transfer job. It returns when every file is done, failed or the
// job was cancelled.
func runFileJob(ctx context.Context, j *fileJob, open fileStreamOpener, items []fileJobItem, destDir string) error {
	defer j.finish()
	var plan []fileJobPlanEntry
	var err error
	if j.Direction == "push" {
		plan, err = planPush(items, destDir)
	} else {
		plan, err = planPull(ctx, open, items, destDir)
	}
	if err != nil {
		j.fileDone(err)
		return err
	}
	// Folders first so empty ones exist even when the job is cancelled early; then large files
	// last, so many small files finish quickly and the counter moves.
	sort.SliceStable(plan, func(a, b int) bool {
		if plan[a].mkdir != plan[b].mkdir {
			return plan[a].mkdir
		}
		return plan[a].size < plan[b].size
	})
	var total int64
	files := 0
	for _, e := range plan {
		if !e.mkdir {
			files++
			if e.size > 0 {
				total += e.size
			}
		}
	}
	j.mu.Lock()
	j.files, j.total = files, total
	j.mu.Unlock()

	work := make(chan fileJobPlanEntry)
	var wg sync.WaitGroup
	workers := fileJobWorkers
	if len(plan) < workers {
		workers = len(plan)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range work {
				if ctx.Err() != nil {
					continue
				}
				if !e.mkdir {
					j.mu.Lock()
					j.current = e.name
					j.mu.Unlock()
				}
				var ferr error
				if j.Direction == "push" {
					ferr = pushFile(ctx, open, j, e)
				} else {
					ferr = pullFile(ctx, open, j, e)
				}
				if e.mkdir {
					if ferr != nil {
						j.fileDone(ferr) // counts as a failure, not as a file done
					}
					continue
				}
				if ctx.Err() != nil {
					continue
				}
				j.fileDone(ferr)
			}
		}()
	}
	for _, e := range plan {
		if ctx.Err() != nil {
			break
		}
		work <- e
	}
	close(work)
	wg.Wait()
	if ctx.Err() != nil {
		return errors.New("ยกเลิกการโอนแล้ว")
	}
	return nil
}
