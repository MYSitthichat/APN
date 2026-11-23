//go:build windows

package bootstrap

import (
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDirW     = kernel32.NewProc("SetDllDirectoryW")
)

func registerDLLDir(dir string) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	_, _, _ = procSetDllDirW.Call(uintptr(unsafe.Pointer(p)))
}
