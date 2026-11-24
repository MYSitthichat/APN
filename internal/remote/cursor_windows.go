//go:build windows

package remote

import (
	"context"
	"runtime"
	"time"
	"unsafe"
)

// systemCursorCSS maps the standard Windows cursors (IDC_*) to CSS cursor names. System cursor
// handles are shared by every process in the session, so the handle GetCursorInfo reports can be
// compared with LoadCursor(NULL, IDC_*).
var systemCursorCSS = []struct {
	id  uintptr
	css string
}{
	{32512, "default"},     // IDC_ARROW
	{32513, "text"},        // IDC_IBEAM
	{32514, "wait"},        // IDC_WAIT
	{32515, "crosshair"},   // IDC_CROSS
	{32516, "default"},     // IDC_UPARROW
	{32642, "nwse-resize"}, // IDC_SIZENWSE
	{32643, "nesw-resize"}, // IDC_SIZENESW
	{32644, "ew-resize"},   // IDC_SIZEWE
	{32645, "ns-resize"},   // IDC_SIZENS
	{32646, "move"},        // IDC_SIZEALL
	{32648, "not-allowed"}, // IDC_NO
	{32649, "pointer"},     // IDC_HAND
	{32650, "progress"},    // IDC_APPSTARTING
	{32651, "help"},        // IDC_HELP
}

func cursorShapeSupported() bool { return true }

// watchCursorShape polls the host cursor and calls send with its CSS name whenever it changes.
// Custom application cursors map to "default". A hidden cursor also maps to "default": Windows
// reports the cursor hidden on PCs without a mouse, and the viewer still needs a pointer there.
func watchCursorShape(ctx context.Context, send func(shape string)) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	handles := map[uintptr]string{}
	for _, c := range systemCursorCSS {
		if h, _, _ := procLoadCursorW.Call(0, c.id); h != 0 {
			handles[h] = c.css
		}
	}

	last := ""
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var lastAttach time.Time
	for {
		// Follow desktop switches (Default <-> Winlogon) like input injection does.
		if time.Since(lastAttach) > time.Second {
			attachToInputDesktop()
			lastAttach = time.Now()
		}
		shape := "default"
		ci := cursorInfoStruct{}
		ci.Size = uint32(unsafe.Sizeof(ci))
		if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r != 0 {
			if css, ok := handles[ci.Cursor]; ok && ci.Flags&cursorShowing != 0 {
				shape = css
			}
		}
		if shape != last {
			last = shape
			send(shape)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
