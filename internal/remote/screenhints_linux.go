//go:build linux

package remote

// hostScreenHints lists reasons the captured screen may be black or blank (see screenhints.go).
func hostScreenHints() []string {
	var hints []string
	// Wayland is a cause of a black picture only when capture could not use Mutter's screen cast.
	if (isLinuxWayland() || waylandDesktop()) && !waylandCaptureActive() {
		hints = append(hints, hintWayland)
	}
	if s := getActiveLinuxSession(); s.HasUserCred && s.UID < 1000 {
		hints = append(hints, hintLoginScreen)
	}
	return append(hints, linuxDisplayHints("/")...)
}
