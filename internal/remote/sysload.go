package remote

import (
	"strconv"
	"strings"
)

// Host load sampling for the stats panel: it tells "the remote PC is too busy" (GPU/CPU near
// 100%) apart from "the screen simply changes less often" when the encoded FPS is low.
// Each platform provides newSysLoadSampler; Sample returns -1 for values it cannot measure.

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// gpuEngineKey splits a Windows "GPU Engine" counter instance such as
// "pid_1234_luid_0x00000000_0x0000D1A3_phys_0_eng_3_engtype_3D" into the engine it belongs to
// (adapter + engine number, shared by every process) and the engine type ("3D", "VideoEncode").
func gpuEngineKey(instance string) (key, engType string, ok bool) {
	i := strings.Index(instance, "luid_")
	j := strings.Index(instance, "_engtype_")
	if i < 0 || j < i {
		return "", "", false
	}
	return instance[i:j], instance[j+len("_engtype_"):], true
}

// busiestGPUEngine sums utilisation per engine across processes and returns the busiest engine,
// which is how Task Manager reports GPU load.
func busiestGPUEngine(values map[string]float64) (pct float64, engType string, ok bool) {
	perEngine := map[string]float64{}
	types := map[string]string{}
	for inst, v := range values {
		key, typ, good := gpuEngineKey(inst)
		if !good {
			continue
		}
		perEngine[key] += v
		types[key] = typ
	}
	pct = -1
	for key, v := range perEngine {
		if v > pct {
			pct, engType = v, types[key]
		}
	}
	if pct < 0 {
		return 0, "", false
	}
	return clampPct(pct), engType, true
}

// cpuTimes parses the aggregate "cpu" line of /proc/stat into busy and total jiffies.
func cpuTimes(procStat string) (busy, total uint64, ok bool) {
	line := procStat
	if i := strings.IndexByte(procStat, '\n'); i >= 0 {
		line = procStat[:i]
	}
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	var idle uint64
	for i, s := range f[1:] {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if i >= 8 { // guest and guest_nice are already counted in user and nice
			break
		}
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return total - idle, total, true
}

// parseNvidiaSMI reads `nvidia-smi --query-gpu=utilization.gpu,utilization.encoder
// --format=csv,noheader,nounits` and returns the busiest GPU and whether its encoder (NVENC) or
// its graphics engine is the busier part.
func parseNvidiaSMI(out string) (pct float64, engType string, ok bool) {
	pct = -1
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		g, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		e, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if g > pct {
			pct, engType = g, "3D"
		}
		if e > pct {
			pct, engType = e, "NVENC"
		}
	}
	if pct < 0 {
		return 0, "", false
	}
	return clampPct(pct), engType, true
}
