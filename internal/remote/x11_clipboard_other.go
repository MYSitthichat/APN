//go:build !linux && !windows

package remote

import "errors"

func x11WriteClipboard(_ bool, _ []byte) error {
	return errors.New("x11 clipboard not supported on this OS")
}

func x11ReadClipboard() (byte, []byte, error) {
	return 0, nil, errors.New("x11 clipboard not supported on this OS")
}
