package remote

import (
	"runtime"
	"testing"
	"time"
)

func TestLowLatencyVBV(t *testing.T) {
	cases := []struct {
		rate  string
		burst time.Duration
		want  string
	}{
		{"7M", 150 * time.Millisecond, "1050k"},
		{"3500k", 150 * time.Millisecond, "525k"},
		{"18M", 300 * time.Millisecond, "5400k"},
		{"2600k", 150 * time.Millisecond, "390k"},
		{"bogus", 150 * time.Millisecond, "bogus"},
	}
	for _, c := range cases {
		if got := lowLatencyVBV(c.rate, c.burst); got != c.want {
			t.Errorf("lowLatencyVBV(%q, %v) = %q, want %q", c.rate, c.burst, got, c.want)
		}
	}
}

func TestSendQueueDepth(t *testing.T) {
	for fps, want := range map[int]int{60: 30, 30: 15, 24: 12, 10: 12} {
		if got := sendQueueDepth(fps); got != want {
			t.Errorf("sendQueueDepth(%d) = %d, want %d", fps, got, want)
		}
	}
}

// TestCandidatesUseSmallRateBuffer: no encoder may keep a rate buffer of a second or more, which
// lets one keyframe grow into a burst that stalls the stream.
func TestCandidatesUseSmallRateBuffer(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("candidate list differs on this OS")
	}
	for _, codec := range []string{"h264", "hevc"} {
		for _, q := range []int{60, 82, 90, 95} {
			for _, c := range videoEncoderCandidates(codec, 60, 1920, 1080, 1920, 1080, q, true) {
				for i, a := range c.args {
					if a != "-bufsize" || i+1 >= len(c.args) {
						continue
					}
					v := c.args[i+1]
					if len(v) < 2 || v[len(v)-1] != 'k' {
						t.Errorf("%s q%d %s: -bufsize %s is not a small kbit value", codec, q, c.name, v)
					}
				}
			}
		}
	}
}
