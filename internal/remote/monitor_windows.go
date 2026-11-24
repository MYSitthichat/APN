//go:build windows

package remote

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Capture target: the primary monitor, identified the same way for every capture method.
//
// FFmpeg's gfxcapture monitor_idx counts monitors in EnumDisplayMonitors order and ddagrab's
// output_idx counts outputs of one adapter, so "0" is not necessarily the primary screen. On PCs
// with virtual displays (Parsec, USB/indirect displays, dummy plugs) it can be a screen that
// never updates: DXGI then waits forever for a first frame. Mouse input is mapped to the primary
// monitor (ScreenSize), so capture has to show exactly that monitor.

var (
	procMonitorFromPoint  = user32.NewProc("MonitorFromPoint")
	procCreateDXGIFactory = syscall.NewLazyDLL("dxgi.dll").NewProc("CreateDXGIFactory1")
)

const monitorDefaultToPrimary = 0x00000001

// iidIDXGIFactory1 = {770aae78-f26f-4dba-a829-253c83d1b387}
var iidIDXGIFactory1 = syscall.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}

type dxgiOutputDesc struct {
	DeviceName         [32]uint16
	DesktopCoordinates struct{ Left, Top, Right, Bottom int32 }
	AttachedToDesktop  int32
	Rotation           uint32
	Monitor            uintptr
}

type captureTarget struct {
	hmonitor   uintptr // primary HMONITOR (gfxcapture hmonitor=)
	dxgiFound  bool
	dxgiAdapt  int // adapter index for -init_hw_device d3d11va=dda:<n>
	dxgiOutput int // ddagrab output_idx
}

var (
	targetMu    sync.Mutex
	targetCache captureTarget
	targetAt    time.Time
)

// primaryCaptureTarget returns the primary monitor's handle and its DXGI adapter/output indexes.
// Cached briefly: display changes are rare and every encoder candidate asks.
func primaryCaptureTarget() captureTarget {
	targetMu.Lock()
	defer targetMu.Unlock()
	if time.Since(targetAt) < 5*time.Second && targetCache.hmonitor != 0 {
		return targetCache
	}
	t := captureTarget{}
	t.hmonitor, _, _ = procMonitorFromPoint.Call(0, monitorDefaultToPrimary) // POINT{0,0} packed in one arg
	if t.hmonitor != 0 {
		t.dxgiAdapt, t.dxgiOutput, t.dxgiFound = findDXGIOutput(t.hmonitor)
	}
	targetCache, targetAt = t, time.Now()
	return t
}

// comCall invokes method index idx of the COM object obj.
func comCall(obj unsafe.Pointer, idx int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

func comRelease(obj unsafe.Pointer) {
	if obj != nil {
		comCall(obj, 2)
	}
}

// findDXGIOutput walks IDXGIFactory1 adapters and outputs for the one showing hmonitor.
func findDXGIOutput(hmonitor uintptr) (adapter, output int, ok bool) {
	if procCreateDXGIFactory.Find() != nil {
		return 0, 0, false
	}
	var factory unsafe.Pointer
	if hr, _, _ := procCreateDXGIFactory.Call(uintptr(unsafe.Pointer(&iidIDXGIFactory1)), uintptr(unsafe.Pointer(&factory))); hr != 0 || factory == nil {
		return 0, 0, false
	}
	defer comRelease(factory)
	const (
		factoryEnumAdapters = 7 // IDXGIFactory::EnumAdapters
		adapterEnumOutputs  = 7 // IDXGIAdapter::EnumOutputs
		outputGetDesc       = 7 // IDXGIOutput::GetDesc
	)
	for a := 0; a < 16; a++ {
		var adp unsafe.Pointer
		if hr := comCall(factory, factoryEnumAdapters, uintptr(a), uintptr(unsafe.Pointer(&adp))); hr != 0 || adp == nil {
			break // DXGI_ERROR_NOT_FOUND: no more adapters
		}
		for o := 0; o < 16; o++ {
			var out unsafe.Pointer
			if hr := comCall(adp, adapterEnumOutputs, uintptr(o), uintptr(unsafe.Pointer(&out))); hr != 0 || out == nil {
				break
			}
			var desc dxgiOutputDesc
			hr := comCall(out, outputGetDesc, uintptr(unsafe.Pointer(&desc)))
			comRelease(out)
			if hr == 0 && desc.Monitor == hmonitor {
				comRelease(adp)
				return a, o, true
			}
		}
		comRelease(adp)
	}
	return 0, 0, false
}
