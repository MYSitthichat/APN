//go:build !linux

package remote

import "errors"

// Wayland capture exists only on Linux (see wayland_mutter_linux.go).

func waylandCaptureSource(_, _, _ int) (*candidateSource, []string, bool) { return nil, nil, false }

func applyWaylandInput(_ InputEvent) (bool, error) { return false, nil }

func waylandCaptureActive() bool { return false }

func waylandDesktop() bool { return false }

func waylandStreamSize() (int, int, bool) { return 0, 0, false }

func waylandToolsMissing() bool { return false }

func waylandCaptureError() string { return "" }

// RunWaylandCastHelper is "apn wayland-cast", which only exists on Linux.
func RunWaylandCastHelper() error { return errors.New("wayland-cast runs only on Linux") }
