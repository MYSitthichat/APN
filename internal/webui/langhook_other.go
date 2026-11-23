//go:build !windows

package webui

func registerRemoteLangHook(_ func()) func() {
	return func() {}
}
