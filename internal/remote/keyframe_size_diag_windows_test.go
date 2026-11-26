//go:build windows && capturediag

package remote

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"relayvpn/internal/bootstrap"
)

// TestKeyframeSizeDiag runs encoder candidates for a few seconds and reports how large their
// keyframes are, with the production rate buffer and with APN_DIAG_BUFSIZE (e.g. "1400k") in
// its place. A keyframe is sent in one burst, so its size decides how long the stream stalls.
// APN_DIAG_MATCH filters candidates by name (comma-separated substrings).
func TestKeyframeSizeDiag(t *testing.T) {
	ff, ok := bootstrap.FindFFmpeg()
	if !ok {
		t.Fatal("ffmpeg not found")
	}
	match := strings.Split(os.Getenv("APN_DIAG_MATCH"), ",")
	override := os.Getenv("APN_DIAG_BUFSIZE")
	w, h := ScreenSize()
	measure := func(args []string) (keys []int, deltas, total int, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, ff, append([]string{"-nostdin", "-hide_banner"}, args...)...)
		release := prepareCaptureCmd(cmd)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		runErr := cmd.Run()
		release()
		b := out.Bytes()
		if len(b) < 13 {
			return nil, 0, 0, runErr
		}
		for p := 13; p+11 <= len(b); {
			typ := b[p]
			size := int(b[p+1])<<16 | int(b[p+2])<<8 | int(b[p+3])
			body := p + 11
			if body+size > len(b) {
				break
			}
			if typ == 9 && size > 64 {
				ft := (b[body] >> 4) & 0x7
				total += size
				if ft == 1 {
					keys = append(keys, size)
				} else {
					deltas++
				}
			}
			p = body + size + 4
		}
		return keys, deltas, total, nil
	}
	for _, codec := range []string{"h264", "hevc"} {
		for _, c := range videoEncoderCandidates(codec, 60, w, h, w&^1, h&^1, 82, true) {
			hit := len(match) == 1 && match[0] == ""
			for _, m := range match {
				if m != "" && strings.Contains(c.name, m) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			variants := [][]string{c.args}
			if override != "" {
				alt := append([]string{}, c.args...)
				for i := range alt {
					if alt[i] == "-bufsize" && i+1 < len(alt) {
						alt[i+1] = override
					}
				}
				variants = append(variants, alt)
			}
			for vi, args := range variants {
				label := "production"
				if vi == 1 {
					label = "bufsize " + override
				}
				keys, deltas, total, _ := measure(args)
				if len(keys) == 0 {
					t.Logf("%-5s %-34s %-16s no frames", codec, c.name, label)
					continue
				}
				sort.Ints(keys)
				t.Logf("%-5s %-34s %-16s keyframes %d: first %d KB, others max %d KB | %d delta frames, avg %d kbps",
					codec, c.name, label, len(keys), keys[len(keys)-1]/1024, keys[max(len(keys)-2, 0)]/1024, deltas, total*8/6500)
			}
		}
	}
}
