//go:build !windows

package service

import (
	"os"
	"syscall"
)

// fileOwnerUID returns the owner uid of path, or -1.
func fileOwnerUID(path string) int {
	st, err := os.Lstat(path)
	if err != nil {
		return -1
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}
