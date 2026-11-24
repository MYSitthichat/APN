//go:build !windows

package remote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// sysLoadSampler reads CPU load from /proc/stat and GPU load from nvidia-smi (NVIDIA) or
// gpu_busy_percent (AMD) on Linux. Elsewhere it reports unknown (-1).
type sysLoadSampler struct {
	lastBusy, lastTotal uint64
	haveCPU             bool
	nvidiaSMI           string
}

func newSysLoadSampler() *sysLoadSampler {
	s := &sysLoadSampler{}
	if runtime.GOOS != "linux" {
		return s
	}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		s.lastBusy, s.lastTotal, s.haveCPU = cpuTimes(string(data))
	}
	if p, err := exec.LookPath("nvidia-smi"); err == nil {
		s.nvidiaSMI = p
	}
	return s
}

func (s *sysLoadSampler) Sample() (cpu, gpu float64, engine string) {
	cpu, gpu = -1, -1
	if runtime.GOOS != "linux" {
		return cpu, gpu, ""
	}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		if busy, total, ok := cpuTimes(string(data)); ok {
			if s.haveCPU && total > s.lastTotal {
				cpu = clampPct(float64(busy-s.lastBusy) / float64(total-s.lastTotal) * 100)
			}
			s.lastBusy, s.lastTotal, s.haveCPU = busy, total, true
		}
	}
	if s.nvidiaSMI != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		out, err := exec.CommandContext(ctx, s.nvidiaSMI, "--query-gpu=utilization.gpu,utilization.encoder", "--format=csv,noheader,nounits").Output()
		cancel()
		if err == nil {
			if pct, typ, ok := parseNvidiaSMI(string(out)); ok {
				return cpu, pct, typ
			}
		}
	}
	// AMD (amdgpu) exposes a busy percentage per card.
	paths, _ := filepath.Glob("/sys/class/drm/card*/device/gpu_busy_percent")
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			if v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil && v > gpu {
				gpu, engine = clampPct(v), "3D"
			}
		}
	}
	return cpu, gpu, engine
}

func (s *sysLoadSampler) Close() {}
