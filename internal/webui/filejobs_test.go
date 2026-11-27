package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"relayvpn/internal/remote"
)

// inProcessHost serves every opened stream with the real host-side file handler.
func inProcessHost(t *testing.T) fileStreamOpener {
	t.Helper()
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { _ = remote.ServeFileStream(b, nil, nil) }()
		return a, nil
	}
}

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// treeOf lists every file (with content) and every directory under root, relative to it.
func treeOf(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // removed while walking (a part file being cleaned up)
			}
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, ".apnpart") {
			out[rel] = "LEFTOVER PART FILE"
			return nil
		}
		if info.IsDir() {
			if rel != "." {
				out[rel+"/"] = ""
			}
			return nil
		}
		b, _ := os.ReadFile(p)
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, want, got map[string]string) {
	t.Helper()
	var missing, extra, differ []string
	for k, v := range want {
		g, ok := got[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case g != v:
			differ = append(differ, k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing)+len(extra)+len(differ) > 0 {
		t.Fatalf("trees differ: missing %v, extra %v, different content %v", missing, extra, differ)
	}
}

func makeSourceTree(t *testing.T, root string) {
	big := make([]byte, 3<<20+12345) // larger than the 256 KB copy buffer
	_, _ = rand.Read(big)
	writeFile(t, filepath.Join(root, "Installers", "postgres.exe"), big)
	writeFile(t, filepath.Join(root, "Installers", "README.txt"), []byte("อ่านก่อนติดตั้ง\n"))
	writeFile(t, filepath.Join(root, "Installers", "scripts", "setup.ps1"), []byte("Write-Host hi"))
	writeFile(t, filepath.Join(root, "Installers", "scripts", "deep", "a", "b", "c.txt"), []byte("deep"))
	if err := os.MkdirAll(filepath.Join(root, "Installers", "empty-folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "loose.txt"), []byte("single file"))
}

func TestFileJobPushAndPullFolders(t *testing.T) {
	open := inProcessHost(t)
	src := t.TempDir()
	remoteDir := t.TempDir() // the "remote" machine's folder (same process, real host handler)
	back := t.TempDir()
	makeSourceTree(t, src)

	// Push a folder and a loose file together, as one selection.
	ctx := context.Background()
	push := registerFileJob("", "push", func() {})
	items := []fileJobItem{
		{Path: filepath.Join(src, "Installers"), IsDir: true},
		{Path: filepath.Join(src, "loose.txt")},
		{Path: filepath.Join(src, "loose.txt")}, // selected twice: sent once
	}
	if err := runFileJob(ctx, push, open, items, remoteDir); err != nil {
		t.Fatalf("push: %v", err)
	}
	ps := push.status()
	if ps.Active || ps.Files != 5 || ps.Done != 5 || ps.Failed != 0 || ps.Bytes != ps.Total || ps.Total == 0 {
		t.Fatalf("push status: %+v", ps)
	}
	sameTree(t, treeOf(t, src), treeOf(t, remoteDir))

	// Pull the folder back through remote listings.
	pull := registerFileJob("", "pull", func() {})
	if err := runFileJob(ctx, pull, open, []fileJobItem{
		{Path: filepath.Join(remoteDir, "Installers"), IsDir: true},
		{Path: filepath.Join(remoteDir, "loose.txt")},
	}, back); err != nil {
		t.Fatalf("pull: %v", err)
	}
	ls := pull.status()
	if ls.Files != 5 || ls.Done != 5 || ls.Failed != 0 || ls.Bytes != ls.Total {
		t.Fatalf("pull status: %+v", ls)
	}
	sameTree(t, treeOf(t, src), treeOf(t, back))
}

// TestFileJobsKeepTheirOwnProgress: two transfers at the same time used to add into one counter
// (575 MB shown for a 389 MB file). Each job must count only its own bytes.
func TestFileJobsKeepTheirOwnProgress(t *testing.T) {
	open := inProcessHost(t)
	src := t.TempDir()
	data := make([]byte, 2<<20)
	_, _ = rand.Read(data)
	writeFile(t, filepath.Join(src, "same.bin"), data)
	dst := t.TempDir()

	var wg sync.WaitGroup
	jobs := []*fileJob{registerFileJob("", "push", func() {}), registerFileJob("", "push", func() {})}
	for _, j := range jobs {
		wg.Add(1)
		go func(j *fileJob) {
			defer wg.Done()
			if err := runFileJob(context.Background(), j, open, []fileJobItem{{Path: filepath.Join(src, "same.bin")}}, dst); err != nil {
				t.Errorf("job %s: %v", j.ID, err)
			}
		}(j)
	}
	wg.Wait()
	for _, j := range jobs {
		if st := j.status(); st.Bytes != int64(len(data)) || st.Total != int64(len(data)) {
			t.Fatalf("job %s counted %d of %d bytes", j.ID, st.Bytes, st.Total)
		}
	}
	got, err := os.ReadFile(filepath.Join(dst, "same.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the file uploaded twice at once is damaged (err %v)", err)
	}
	if tree := treeOf(t, dst); len(tree) != 1 {
		t.Fatalf("leftovers next to the uploaded file: %v", tree)
	}
}

func TestFileJobCancel(t *testing.T) {
	open := inProcessHost(t)
	src := t.TempDir()
	for i := 0; i < 30; i++ {
		writeFile(t, filepath.Join(src, "many", strings.Repeat("x", i+1)+".bin"), make([]byte, 512<<10))
	}
	dst := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	j := registerFileJob("", "push", cancel)
	j.bytes.Store(0)
	go func() {
		for j.bytes.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	err := runFileJob(ctx, j, open, []fileJobItem{{Path: filepath.Join(src, "many"), IsDir: true}}, dst)
	if err == nil {
		t.Fatal("a cancelled job reported success")
	}
	if st := j.status(); st.Done >= 30 || st.Active {
		t.Fatalf("status after cancel: %+v", st)
	}
	// The host side removes its part file when the stream breaks; in this test the host runs in
	// goroutines of the same process, so give them a moment to finish.
	leftover := ""
	for i := 0; i < 100; i++ {
		leftover = ""
		for k := range treeOf(t, dst) {
			if strings.Contains(k, ".apnpart") {
				leftover = k
			}
		}
		if leftover == "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if leftover != "" {
		t.Fatalf("partial file left behind: %s", leftover)
	}
}

func TestJoinRemotePath(t *testing.T) {
	cases := []struct {
		base  string
		parts []string
		want  string
	}{
		{`D:\SetUP-DB\Installer`, []string{"Installers", "scripts"}, `D:\SetUP-DB\Installer\Installers\scripts`},
		{`D:\`, []string{"a"}, `D:\a`},
		{`D:`, nil, `D:\`},
		{"/home/air", []string{"Installers", "deep"}, "/home/air/Installers/deep"},
		{"/", []string{"tmp"}, "/tmp"},
		{"/", nil, "/"},
		{`C:\Users\x\`, []string{"", ".", "f"}, `C:\Users\x\f`},
	}
	for _, c := range cases {
		if got := joinRemotePath(c.base, c.parts...); got != c.want {
			t.Errorf("joinRemotePath(%q, %q) = %q, want %q", c.base, c.parts, got, c.want)
		}
	}
	if remoteBaseName(`D:\a\b\`) != "b" || remoteBaseName("/x/y") != "y" {
		t.Error("remoteBaseName")
	}
}
