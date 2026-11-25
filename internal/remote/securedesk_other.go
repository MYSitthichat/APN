//go:build !windows

package remote

func secureDesktop() (active, reachable bool) { return false, false }
