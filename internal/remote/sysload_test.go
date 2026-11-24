package remote

import (
	"runtime"
	"testing"
	"time"
)

func TestBusiestGPUEngine(t *testing.T) {
	values := map[string]float64{
		// Two processes share the 3D engine of one adapter; their loads add up.
		"pid_100_luid_0x00000000_0x0000D1A3_phys_0_eng_0_engtype_3D":          55,
		"pid_200_luid_0x00000000_0x0000D1A3_phys_0_eng_0_engtype_3D":          37,
		"pid_200_luid_0x00000000_0x0000D1A3_phys_0_eng_5_engtype_VideoEncode": 40,
		"pid_300_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D":          10,
		"garbage": 99,
	}
	pct, typ, ok := busiestGPUEngine(values)
	if !ok || pct != 92 || typ != "3D" {
		t.Fatalf("got %v %q %v, want 92 3D", pct, typ, ok)
	}
	if _, _, ok := busiestGPUEngine(map[string]float64{}); ok {
		t.Fatal("no engines must report unknown")
	}
	if pct, _, _ := busiestGPUEngine(map[string]float64{"pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D": 130}); pct != 100 {
		t.Fatalf("not clamped: %v", pct)
	}
}

func TestCPUTimes(t *testing.T) {
	busy, total, ok := cpuTimes("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5\n")
	if !ok || total != 1000 || busy != 150 {
		t.Fatalf("busy=%d total=%d ok=%v, want 150/1000", busy, total, ok)
	}
	if _, _, ok := cpuTimes("intr 1 2 3"); ok {
		t.Fatal("parsed a non-cpu line")
	}
}

func TestParseNvidiaSMI(t *testing.T) {
	pct, typ, ok := parseNvidiaSMI("35, 12\n20, 81\n")
	if !ok || pct != 81 || typ != "NVENC" {
		t.Fatalf("got %v %q %v, want 81 NVENC", pct, typ, ok)
	}
	if _, _, ok := parseNvidiaSMI("[N/A], [N/A]"); ok {
		t.Fatal("N/A must be unknown")
	}
}

// TestSysLoadSamplerLive reads the real counters of this machine.
func TestSysLoadSamplerLive(t *testing.T) {
	s := newSysLoadSampler()
	defer s.Close()
	time.Sleep(1100 * time.Millisecond)
	cpu, gpu, eng := s.Sample()
	t.Logf("cpu=%.1f%% gpu=%.1f%% engine=%q", cpu, gpu, eng)
	if (runtime.GOOS == "windows" || runtime.GOOS == "linux") && (cpu < 0 || cpu > 100) {
		t.Fatalf("cpu = %v, want 0..100", cpu)
	}
	if gpu > 100 {
		t.Fatalf("gpu = %v", gpu)
	}
}
