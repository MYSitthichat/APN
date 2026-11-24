//go:build windows

package service

// fileOwnerUID is not used on Windows: the installing user's %APPDATA% is not writable by other
// standard users, so the recorded path alone identifies the source.
func fileOwnerUID(string) int { return -1 }
