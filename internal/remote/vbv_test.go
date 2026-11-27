package remote

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSendQueueDepth(t *testing.T) {
	for fps, want := range map[int]int{60: 30, 30: 15, 24: 12, 10: 12} {
		if got := sendQueueDepth(fps); got != want {
			t.Errorf("sendQueueDepth(%d) = %d, want %d", fps, got, want)
		}
	}
}

// rateKbit parses an FFmpeg rate such as "7M" or "3500k".
func rateKbit(t *testing.T, v string) int {
	t.Helper()
	switch {
	case strings.HasSuffix(v, "M"):
		f, err := strconv.ParseFloat(strings.TrimSuffix(v, "M"), 64)
		if err == nil {
			return int(f * 1000)
		}
	case strings.HasSuffix(v, "k"):
		n, err := strconv.Atoi(strings.TrimSuffix(v, "k"))
		if err == nil {
			return n
		}
	}
	t.Fatalf("cannot parse rate %q", v)
	return 0
}

// TestCandidatesKeepFullRateBuffer: every encoder that takes a rate buffer gets about a second
// of its maximum bitrate. A buffer of 150 ms (v1.3.31-v1.3.32) left the lower part of every
// keyframe unreadable, because the encoder ran out of bits partway down the picture.
func TestCandidatesKeepFullRateBuffer(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("candidate list differs on this OS")
	}
	checked := 0
	for _, codec := range []string{"h264", "hevc"} {
		for _, q := range []int{60, 82, 90, 95} {
			for _, c := range videoEncoderCandidates(codec, 60, 1920, 1080, 1920, 1080, q, true) {
				maxRate, buf := "", ""
				for i, a := range c.args {
					if i+1 >= len(c.args) {
						break
					}
					switch a {
					case "-maxrate":
						maxRate = c.args[i+1]
					case "-bufsize":
						buf = c.args[i+1]
					}
				}
				if buf == "" {
					continue
				}
				if maxRate == "" {
					t.Errorf("%s q%d %s: -bufsize %s without -maxrate", codec, q, c.name, buf)
					continue
				}
				checked++
				if b, m := rateKbit(t, buf), rateKbit(t, maxRate); b*100 < m*85 {
					t.Errorf("%s q%d %s: -bufsize %s is under 85%% of -maxrate %s", codec, q, c.name, buf, maxRate)
				}
			}
		}
	}
	if checked == 0 {
		t.Error("no candidate with a rate buffer was checked")
	}
}
