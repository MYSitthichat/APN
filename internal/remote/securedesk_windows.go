//go:build windows

package remote

import "strings"

// secureDesktop reports whether Windows shows a secure desktop (UAC prompt, lock screen or
// sign-in screen on the "Winlogon" desktop) instead of the normal one. reachable is true when this
// process can open it, i.e. it runs as LocalSystem (System Service worker) and can capture it and
// send input to it. A user-mode process cannot open the secure desktop at all.
func secureDesktop() (active, reachable bool) {
	name := inputDesktopName()
	switch {
	case strings.EqualFold(name, "Default"):
		return false, false
	case name == "":
		return true, false
	default:
		return true, true
	}
}
