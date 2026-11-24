//go:build windows

package remote

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPDH                           = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW                = modPDH.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW        = modPDH.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData          = modPDH.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterArrayW = modPDH.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery                = modPDH.NewProc("PdhCloseQuery")
	procGetSystemTimes               = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes")
)

const (
	pdhFmtDouble = 0x00000200
	pdhMoreData  = 0x800007D2
)

// pdhFmtCounterValueItem mirrors PDH_FMT_COUNTERVALUE_ITEM_W on 64-bit Windows: name pointer,
// CStatus, padding, then the double value.
type pdhFmtCounterValueItem struct {
	name   *uint16
	status uint32
	_      uint32
	value  float64
}

// sysLoadSampler reads total CPU load (GetSystemTimes) and the busiest GPU engine from the
// "GPU Engine" performance counters (Windows 10 1709+, the numbers Task Manager shows).
type sysLoadSampler struct {
	query   uintptr
	counter uintptr

	lastIdle, lastTotal uint64
	haveCPU             bool
}

func newSysLoadSampler() *sysLoadSampler {
	s := &sysLoadSampler{}
	s.lastIdle, s.lastTotal, s.haveCPU = systemTimes()
	if modPDH.Load() != nil {
		return s
	}
	var q uintptr
	if r, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&q))); r != 0 {
		return s
	}
	path, _ := windows.UTF16PtrFromString(`\GPU Engine(*)\Utilization Percentage`)
	var c uintptr
	if r, _, _ := procPdhAddEnglishCounterW.Call(q, uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&c))); r != 0 {
		_, _, _ = procPdhCloseQuery.Call(q)
		return s
	}
	// Utilization is a rate: the first collection is the baseline for the next Sample.
	_, _, _ = procPdhCollectQueryData.Call(q)
	s.query, s.counter = q, c
	return s
}

// Sample returns CPU % and GPU % since the previous call (-1 when unknown) and the GPU engine
// type that is busiest ("3D", "VideoEncode", "Copy", ...).
func (s *sysLoadSampler) Sample() (cpu, gpu float64, engine string) {
	cpu, gpu = -1, -1
	if idle, total, ok := systemTimes(); ok {
		if s.haveCPU && total > s.lastTotal {
			dt := float64(total - s.lastTotal)
			di := float64(idle - s.lastIdle)
			cpu = clampPct((dt - di) / dt * 100)
		}
		s.lastIdle, s.lastTotal, s.haveCPU = idle, total, true
	}
	if s.query == 0 {
		return cpu, gpu, ""
	}
	if r, _, _ := procPdhCollectQueryData.Call(s.query); r != 0 {
		return cpu, gpu, ""
	}
	values, ok := s.counterValues()
	if !ok {
		return cpu, gpu, ""
	}
	if pct, typ, ok := busiestGPUEngine(values); ok {
		gpu, engine = pct, typ
	}
	return cpu, gpu, engine
}

func (s *sysLoadSampler) counterValues() (map[string]float64, bool) {
	var size, count uint32
	r, _, _ := procPdhGetFormattedCounterArrayW.Call(s.counter, pdhFmtDouble, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	if uint32(r) != pdhMoreData || size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	r, _, _ = procPdhGetFormattedCounterArrayW.Call(s.counter, pdhFmtDouble, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return nil, false
	}
	itemSize := unsafe.Sizeof(pdhFmtCounterValueItem{})
	if uintptr(count)*itemSize > uintptr(len(buf)) {
		return nil, false
	}
	out := make(map[string]float64, count)
	for i := uint32(0); i < count; i++ {
		item := (*pdhFmtCounterValueItem)(unsafe.Pointer(&buf[uintptr(i)*itemSize]))
		if item.name == nil || (item.status != 0 && item.status != 1) { // PDH_CSTATUS_VALID_DATA / NEW_DATA
			continue
		}
		out[windows.UTF16PtrToString(item.name)] = item.value
	}
	return out, true
}

func (s *sysLoadSampler) Close() {
	if s.query != 0 {
		_, _, _ = procPdhCloseQuery.Call(s.query)
		s.query = 0
	}
}

// systemTimes returns idle and total (kernel+user, kernel already includes idle) CPU time.
func systemTimes() (idle, total uint64, ok bool) {
	var i, k, u windows.Filetime
	if r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r == 0 {
		return 0, 0, false
	}
	ft := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	return ft(i), ft(k) + ft(u), true
}
