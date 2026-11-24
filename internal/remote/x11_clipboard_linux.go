//go:build linux

package remote

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// Pure-Go X11 CLIPBOARD owner and reader (no xclip/xsel needed).
//
// Large data uses the ICCCM INCR protocol in both directions. A single X request carries at most
// MaximumRequestLength*4 bytes (usually 256 KiB) and xgb encodes the request length in 16 bits, so
// writing a screenshot (often 0.3-3 MB of PNG) in one ChangeProperty would corrupt the request.

const (
	clipChunkMax      = 64 * 1024        // bytes per INCR chunk
	clipMaxRead       = 64 * 1024 * 1024 // refuse to read more than this from another app
	clipNotifyTimeout = 1500 * time.Millisecond
	clipChunkTimeout  = 3 * time.Second
	clipTransferIdle  = 30 * time.Second
)

type x11ClipOwner struct {
	mu         sync.Mutex
	conn       *xgb.Conn
	win        xproto.Window
	atoms      x11ClipAtoms
	displayKey string
	maxInline  int
	owned      bool
	isImage    bool
	data       []byte
	transfers  map[incrKey]*incrTransfer
}

type incrKey struct {
	win  xproto.Window
	prop xproto.Atom
}

// incrTransfer is one INCR send in progress to a requestor window.
type incrTransfer struct {
	typ    xproto.Atom
	data   []byte
	offset int
	last   time.Time
}

type x11ClipAtoms struct {
	clipboard xproto.Atom
	targets   xproto.Atom
	utf8      xproto.Atom
	str       xproto.Atom
	text      xproto.Atom
	textPlain xproto.Atom
	textUTF8  xproto.Atom
	imagePNG  xproto.Atom
	atom      xproto.Atom
	incr      xproto.Atom
	prop      xproto.Atom
}

var linuxX11Clip x11ClipOwner

func internAtom(conn *xgb.Conn, name string) (xproto.Atom, error) {
	rep, err := xproto.InternAtom(conn, false, uint16(len(name)), name).Reply()
	if err != nil {
		return 0, err
	}
	return rep.Atom, nil
}

func loadClipAtoms(conn *xgb.Conn) (x11ClipAtoms, error) {
	var a x11ClipAtoms
	for _, it := range []struct {
		dst  *xproto.Atom
		name string
	}{
		{&a.clipboard, "CLIPBOARD"},
		{&a.targets, "TARGETS"},
		{&a.utf8, "UTF8_STRING"},
		{&a.str, "STRING"},
		{&a.text, "TEXT"},
		{&a.textPlain, "text/plain"},
		{&a.textUTF8, "text/plain;charset=utf-8"},
		{&a.imagePNG, "image/png"},
		{&a.atom, "ATOM"},
		{&a.incr, "INCR"},
		{&a.prop, "APN_CLIP_DATA"},
	} {
		v, err := internAtom(conn, it.name)
		if err != nil {
			return a, err
		}
		*it.dst = v
	}
	return a, nil
}

// dialActiveX11ForClip connects to the X display of the active session and returns the
// connection with the display key it belongs to (see captureDisplayKey).
func dialActiveX11ForClip() (*xgb.Conn, string, error) {
	s := getActiveLinuxSession()
	cands := []linuxSessionEnv{}
	if s.Display != "" {
		cands = append(cands, s)
	}
	cands = append(cands, discoverLinuxSessions()...)

	xauthEnvMu.Lock()
	defer xauthEnvMu.Unlock()

	var lastErr error
	for _, c := range cands {
		if c.Display == "" {
			continue
		}
		if c.XAuthority != "" {
			_ = os.Setenv("XAUTHORITY", c.XAuthority)
		} else {
			_ = os.Unsetenv("XAUTHORITY")
		}
		conn, err := xgb.NewConnDisplay(c.Display)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, c.Display + "|" + c.XAuthority, nil
	}
	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", errors.New("X11 display not available")
}

// maxInlineBytes is the largest property value that fits in one request on this server.
func maxInlineBytes(setup *xproto.SetupInfo) int {
	n := int(setup.MaximumRequestLength)*4 - 64 // ChangeProperty header + margin
	if n <= 0 || n > 256*1024 {
		n = 256*1024 - 64
	}
	return n
}

func (c *x11ClipOwner) closeConnLocked() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	c.win = 0
	c.owned = false
	c.transfers = nil
}

func (c *x11ClipOwner) ensureConnLocked() error {
	// Follow the active session: after logging in through the remote session the clipboard must
	// live on the user's desktop display, not on the login screen's.
	if c.conn != nil {
		if key := captureDisplayKey(); key != "" && key != c.displayKey {
			c.closeConnLocked()
		}
	}
	if c.conn != nil {
		return nil
	}
	conn, key, err := dialActiveX11ForClip()
	if err != nil {
		return err
	}
	setup := xproto.Setup(conn)
	if setup == nil || len(setup.Roots) == 0 {
		conn.Close()
		return errors.New("X11 server has no screens")
	}
	atoms, err := loadClipAtoms(conn)
	if err != nil {
		conn.Close()
		return err
	}
	win, err := xproto.NewWindowId(conn)
	if err != nil {
		conn.Close()
		return err
	}
	root := setup.DefaultScreen(conn).Root
	if err := xproto.CreateWindowChecked(conn, 0, win, root, 0, 0, 1, 1, 0,
		xproto.WindowClassInputOnly, 0, 0, nil).Check(); err != nil {
		conn.Close()
		return err
	}

	c.conn = conn
	c.win = win
	c.atoms = atoms
	c.displayKey = key
	c.maxInline = maxInlineBytes(setup)
	c.transfers = map[incrKey]*incrTransfer{}
	go c.serveLoop(conn, atoms)
	return nil
}

func (c *x11ClipOwner) serveLoop(conn *xgb.Conn, atoms x11ClipAtoms) {
	defer func() {
		conn.Close()
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
			c.win = 0
			c.owned = false
			c.transfers = nil
		}
		c.mu.Unlock()
	}()

	for {
		ev, xerr := conn.WaitForEvent()
		if ev == nil && xerr == nil {
			return // connection closed
		}
		if ev == nil {
			continue
		}
		switch e := ev.(type) {
		case xproto.SelectionClearEvent:
			if e.Selection == atoms.clipboard {
				c.mu.Lock()
				if c.conn == conn {
					c.owned = false
				}
				c.mu.Unlock()
			}
		case xproto.SelectionRequestEvent:
			c.handleSelectionRequest(conn, atoms, e)
		case xproto.PropertyNotifyEvent:
			if e.State == xproto.PropertyDelete {
				c.continueIncr(conn, e.Window, e.Atom)
			}
		}
	}
}

func (c *x11ClipOwner) handleSelectionRequest(conn *xgb.Conn, atoms x11ClipAtoms, req xproto.SelectionRequestEvent) {
	prop := req.Property
	if prop == 0 {
		prop = req.Target
	}

	c.mu.Lock()
	owned := c.owned && c.conn == conn
	isImg := c.isImage
	payload := c.data // never mutated in place; x11WriteClipboard replaces the slice
	maxInline := c.maxInline
	c.mu.Unlock()

	notify := xproto.SelectionNotifyEvent{
		Time:      req.Time,
		Requestor: req.Requestor,
		Selection: req.Selection,
		Target:    req.Target,
		Property:  xproto.AtomNone,
	}

	if owned && req.Selection == atoms.clipboard {
		var dataType xproto.Atom
		switch {
		case req.Target == atoms.targets:
			var supported []xproto.Atom
			if isImg {
				supported = []xproto.Atom{atoms.targets, atoms.imagePNG}
			} else {
				supported = []xproto.Atom{atoms.targets, atoms.utf8, atoms.textUTF8, atoms.textPlain, atoms.text, atoms.str}
			}
			buf := make([]byte, len(supported)*4)
			for i, a := range supported {
				binary.LittleEndian.PutUint32(buf[i*4:], uint32(a))
			}
			if xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, req.Requestor, prop, atoms.atom, 32, uint32(len(supported)), buf).Check() == nil {
				notify.Property = prop
			}
		case isImg && req.Target == atoms.imagePNG:
			dataType = atoms.imagePNG
		case !isImg && (req.Target == atoms.utf8 || req.Target == atoms.str || req.Target == atoms.text || req.Target == atoms.textPlain || req.Target == atoms.textUTF8):
			dataType = req.Target
		}

		if dataType != 0 {
			if len(payload) <= maxInline {
				if xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, req.Requestor, prop, dataType, 8, uint32(len(payload)), payload).Check() == nil {
					notify.Property = prop
				}
			} else if c.startIncr(conn, atoms, req.Requestor, prop, dataType, payload) {
				notify.Property = prop
			}
		}
	}

	_ = xproto.SendEventChecked(conn, false, req.Requestor, 0, string(notify.Bytes())).Check()
}

// startIncr begins an INCR transfer: it announces the total size with an INCR-typed property
// and then sends chunks each time the requestor deletes the property (see continueIncr).
func (c *x11ClipOwner) startIncr(conn *xgb.Conn, atoms x11ClipAtoms, requestor xproto.Window, prop, typ xproto.Atom, data []byte) bool {
	if xproto.ChangeWindowAttributesChecked(conn, requestor, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check() != nil {
		return false
	}
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(data)))
	if xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, requestor, prop, atoms.incr, 32, 1, size).Check() != nil {
		return false
	}
	c.mu.Lock()
	if c.conn == conn && c.transfers != nil {
		now := time.Now()
		for k, t := range c.transfers {
			if now.Sub(t.last) > clipTransferIdle {
				delete(c.transfers, k)
			}
		}
		c.transfers[incrKey{requestor, prop}] = &incrTransfer{typ: typ, data: data, last: now}
	}
	c.mu.Unlock()
	return true
}

func (c *x11ClipOwner) continueIncr(conn *xgb.Conn, win xproto.Window, prop xproto.Atom) {
	key := incrKey{win, prop}
	c.mu.Lock()
	t := c.transfers[key]
	if t == nil || c.conn != conn {
		c.mu.Unlock()
		return
	}
	end := t.offset + clipChunkMax
	if end > len(t.data) {
		end = len(t.data)
	}
	chunk := t.data[t.offset:end]
	t.offset = end
	t.last = time.Now()
	done := len(chunk) == 0
	if done {
		delete(c.transfers, key)
	}
	c.mu.Unlock()

	// A zero-length chunk tells the requestor the transfer is complete.
	_ = xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, win, prop, t.typ, 8, uint32(len(chunk)), chunk).Check()
	if done {
		_ = xproto.ChangeWindowAttributesChecked(conn, win, xproto.CwEventMask, []uint32{0}).Check()
	}
}

// x11WriteClipboard sets the Linux X11 CLIPBOARD selection in pure Go (no xclip/xsel needed).
func x11WriteClipboard(isImage bool, data []byte) error {
	linuxX11Clip.mu.Lock()
	defer linuxX11Clip.mu.Unlock()

	if err := linuxX11Clip.ensureConnLocked(); err != nil {
		return err
	}
	linuxX11Clip.isImage = isImage
	linuxX11Clip.data = append([]byte(nil), data...)
	linuxX11Clip.owned = true

	if err := xproto.SetSelectionOwnerChecked(
		linuxX11Clip.conn,
		linuxX11Clip.win,
		linuxX11Clip.atoms.clipboard,
		xproto.TimeCurrentTime,
	).Check(); err != nil {
		linuxX11Clip.closeConnLocked()
		return err
	}
	// Confirm we actually became the owner before reporting success.
	if rep, err := xproto.GetSelectionOwner(linuxX11Clip.conn, linuxX11Clip.atoms.clipboard).Reply(); err != nil || rep.Owner != linuxX11Clip.win {
		linuxX11Clip.owned = false
		return errors.New("could not take X11 clipboard ownership")
	}
	return nil
}

// clipReader reads the CLIPBOARD selection owned by another application over its own connection.
type clipReader struct {
	conn   *xgb.Conn
	win    xproto.Window
	atoms  x11ClipAtoms
	events chan xgb.Event
	done   chan struct{}
}

// pump forwards every X event into r.events until the connection closes, so each step below
// waits on one ordered stream instead of racing several WaitForEvent goroutines.
func (r *clipReader) pump() {
	defer close(r.events)
	for {
		ev, xerr := r.conn.WaitForEvent()
		if ev == nil && xerr == nil {
			return
		}
		if ev == nil {
			continue
		}
		select {
		case r.events <- ev:
		case <-r.done:
			return
		}
	}
}

// waitNotify waits for the SelectionNotify answering a ConvertSelection for target.
// Answers to earlier, timed-out requests carry another target and are skipped.
func (r *clipReader) waitNotify(target xproto.Atom) (xproto.Atom, bool) {
	deadline := time.NewTimer(clipNotifyTimeout)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-r.events:
			if !ok {
				return 0, false
			}
			if sn, ok := ev.(xproto.SelectionNotifyEvent); ok && sn.Requestor == r.win && sn.Selection == r.atoms.clipboard && sn.Target == target {
				return sn.Property, sn.Property != xproto.AtomNone
			}
		case <-deadline.C:
			return 0, false
		}
	}
}

// waitNewValue waits for the next PropertyNotify(NewValue) on our window (INCR chunks).
func (r *clipReader) waitNewValue() bool {
	deadline := time.NewTimer(clipChunkTimeout)
	defer deadline.Stop()
	for {
		select {
		case ev, ok := <-r.events:
			if !ok {
				return false
			}
			if pn, ok := ev.(xproto.PropertyNotifyEvent); ok && pn.Window == r.win && pn.Atom == r.atoms.prop && pn.State == xproto.PropertyNewValue {
				return true
			}
		case <-deadline.C:
			return false
		}
	}
}

// readProperty reads and deletes our property, following BytesAfter for long values.
func (r *clipReader) readProperty() (xproto.Atom, []byte, bool) {
	var out []byte
	var typ xproto.Atom
	offset := uint32(0)
	for {
		rep, err := xproto.GetProperty(r.conn, false, r.win, r.atoms.prop, xproto.GetPropertyTypeAny, offset, 1<<20).Reply()
		if err != nil || rep == nil {
			return 0, nil, false
		}
		typ = rep.Type
		n := int(rep.ValueLen) * int(rep.Format) / 8
		if n > len(rep.Value) {
			n = len(rep.Value)
		}
		out = append(out, rep.Value[:n]...)
		if len(out) > clipMaxRead {
			return 0, nil, false
		}
		if rep.BytesAfter == 0 {
			break
		}
		offset += uint32(n / 4)
	}
	_ = xproto.DeletePropertyChecked(r.conn, r.win, r.atoms.prop).Check()
	return typ, out, true
}

func (r *clipReader) readTarget(target xproto.Atom) ([]byte, bool) {
	_ = xproto.DeletePropertyChecked(r.conn, r.win, r.atoms.prop).Check()
	if err := xproto.ConvertSelectionChecked(r.conn, r.win, r.atoms.clipboard, target, r.atoms.prop, xproto.TimeCurrentTime).Check(); err != nil {
		return nil, false
	}
	if _, ok := r.waitNotify(target); !ok {
		return nil, false
	}
	typ, data, ok := r.readProperty() // deleting it also starts an INCR transfer
	if !ok {
		return nil, false
	}
	if typ != r.atoms.incr {
		return data, len(data) > 0
	}
	// INCR: the owner sends chunks; each one is read and deleted, and an empty one ends it.
	var out []byte
	for {
		if !r.waitNewValue() {
			return nil, false
		}
		_, chunk, ok := r.readProperty()
		if !ok {
			return nil, false
		}
		if len(chunk) == 0 {
			return out, len(out) > 0
		}
		out = append(out, chunk...)
		if len(out) > clipMaxRead {
			return nil, false
		}
	}
}

// x11ReadClipboard reads the Linux X11 CLIPBOARD selection (PNG image or UTF-8 text) in pure Go.
func x11ReadClipboard() (byte, []byte, error) {
	// Fast path: if APN itself currently owns the clipboard, return directly.
	linuxX11Clip.mu.Lock()
	if linuxX11Clip.owned && len(linuxX11Clip.data) > 0 {
		kind := byte(0)
		if linuxX11Clip.isImage {
			kind = 1
		}
		out := append([]byte(nil), linuxX11Clip.data...)
		linuxX11Clip.mu.Unlock()
		return kind, out, nil
	}
	linuxX11Clip.mu.Unlock()

	conn, _, err := dialActiveX11ForClip()
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()

	setup := xproto.Setup(conn)
	if setup == nil || len(setup.Roots) == 0 {
		return 0, nil, errors.New("X11 server has no screens")
	}
	atoms, err := loadClipAtoms(conn)
	if err != nil {
		return 0, nil, err
	}
	ownerRep, err := xproto.GetSelectionOwner(conn, atoms.clipboard).Reply()
	if err != nil || ownerRep.Owner == 0 {
		return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า")
	}

	win, err := xproto.NewWindowId(conn)
	if err != nil {
		return 0, nil, err
	}
	root := setup.DefaultScreen(conn).Root
	// PropertyChange events on our window are needed to receive INCR chunks.
	if err := xproto.CreateWindowChecked(conn, 0, win, root, 0, 0, 1, 1, 0, xproto.WindowClassInputOnly, 0,
		xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check(); err != nil {
		return 0, nil, err
	}
	defer xproto.DestroyWindow(conn, win)

	r := &clipReader{conn: conn, win: win, atoms: atoms, events: make(chan xgb.Event, 256), done: make(chan struct{})}
	defer close(r.done) // runs before conn.Close, so pump never stays blocked on a full channel
	go r.pump()

	// Probe TARGETS first so a PNG image is preferred, otherwise UTF8_STRING/STRING text.
	hasPNG := false
	if rawTargets, ok := r.readTarget(atoms.targets); ok && len(rawTargets) >= 4 {
		for i := 0; i+4 <= len(rawTargets); i += 4 {
			if xproto.Atom(binary.LittleEndian.Uint32(rawTargets[i:i+4])) == atoms.imagePNG {
				hasPNG = true
				break
			}
		}
	}
	if hasPNG {
		if pngBytes, ok := r.readTarget(atoms.imagePNG); ok && len(pngBytes) > 16 {
			return 1, pngBytes, nil
		}
	}
	if txtBytes, ok := r.readTarget(atoms.utf8); ok && len(txtBytes) > 0 {
		return 0, txtBytes, nil
	}
	if txtBytes, ok := r.readTarget(atoms.str); ok && len(txtBytes) > 0 {
		return 0, txtBytes, nil
	}
	return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า")
}
