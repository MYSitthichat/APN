package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilterListed(t *testing.T) {
	out := `Filters:
  T.. = Timeline support
 ... ddagrab           |->V       Grab Windows Desktop images using Desktop Duplication API
 ... gfxcapture        |->V       Capture graphics/screen content as video frames
 TSC scale             V->V       Scale the input video size and/or convert the image format.
`
	if !filterListed(out, "gfxcapture") || !filterListed(out, "ddagrab") || !filterListed(out, "scale") {
		t.Fatal("expected filters to be found")
	}
	if filterListed(out, "gfx") || filterListed(out, "Capture") {
		t.Fatal("matched a partial name or a description word")
	}
}

func TestReplaceFFmpeg(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "ffmpeg.exe")
	newPath := filepath.Join(dir, "ffmpeg-update.exe")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceFFmpeg(dir, newPath); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "new" {
		t.Fatalf("ffmpeg.exe = %q, want new", b)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("update file should have been moved")
	}
	if old, _ := filepath.Glob(filepath.Join(dir, "ffmpeg-old-*.exe")); len(old) != 0 {
		t.Fatalf("old binary left behind: %v", old)
	}

	// First install (no existing ffmpeg.exe).
	dir2 := t.TempDir()
	np := filepath.Join(dir2, "ffmpeg-update.exe")
	_ = os.WriteFile(np, []byte("x"), 0o755)
	if err := replaceFFmpeg(dir2, np); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "ffmpeg.exe")); err != nil {
		t.Fatal(err)
	}
}
