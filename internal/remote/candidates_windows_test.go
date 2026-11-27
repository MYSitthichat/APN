package remote

import (
	"strings"
	"testing"
)

// TestWindowsCandidateArgs guards two failures found with the in-app capture check:
// h264_amf rejects "-profile:v baseline" outright, and NVENC/AMF behind DXGI capture must not
// inherit the capture adapter's D3D11 device (it may belong to another vendor's GPU).
func TestWindowsCandidateArgs(t *testing.T) {
	seenDDA := 0
	for _, codec := range []string{"h264", "hevc"} {
		for _, c := range videoEncoderCandidates(codec, 60, 1920, 1080, 1920, 1080, 82, true) {
			joined := strings.Join(c.args, " ")
			if strings.Contains(joined, "-c:v h264_amf") && strings.Contains(joined, "-profile:v baseline") {
				t.Errorf("%s: h264_amf has no profile named baseline", c.name)
			}
			devices := strings.Count(joined, "-init_hw_device d3d11va=")
			if devices == 0 || c.tier != "DXGI" {
				continue
			}
			seenDDA++
			takesD3D11 := strings.Contains(joined, "_nvenc") || strings.Contains(joined, "_amf")
			if takesD3D11 && devices != 2 {
				t.Errorf("%s: %d D3D11 devices, want 2 so the encoder does not inherit the capture adapter", c.name, devices)
			}
			if !takesD3D11 && devices != 1 {
				t.Errorf("%s: %d D3D11 devices, want 1", c.name, devices)
			}
		}
	}
	t.Logf("checked %d DXGI candidates with an explicit adapter", seenDDA)
}
