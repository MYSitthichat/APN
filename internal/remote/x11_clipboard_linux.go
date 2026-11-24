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

type x11ClipOwner struct {
	mu      sync.Mutex
	conn    *xgb.Conn
	win     xproto.Window
	atoms   x11ClipAtoms
	owned   bool
	isImage bool
	data    []byte
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
	var err error
	if a.clipboard, err = internAtom(conn, "CLIPBOARD"); err != nil {
		return a, err
	}
	if a.targets, err = internAtom(conn, "TARGETS"); err != nil {
		return a, err
	}
	if a.utf8, err = internAtom(conn, "UTF8_STRING"); err != nil {
		return a, err
	}
	if a.str, err = internAtom(conn, "STRING"); err != nil {
		return a, err
	}
	if a.text, err = internAtom(conn, "TEXT"); err != nil {
		return a, err
	}
	if a.textPlain, err = internAtom(conn, "text/plain"); err != nil {
		return a, err
	}
	if a.textUTF8, err = internAtom(conn, "text/plain;charset=utf-8"); err != nil {
		return a, err
	}
	if a.imagePNG, err = internAtom(conn, "image/png"); err != nil {
		return a, err
	}
	if a.atom, err = internAtom(conn, "ATOM"); err != nil {
		return a, err
	}
	if a.prop, err = internAtom(conn, "APN_CLIP_DATA"); err != nil {
		return a, err
	}
	return a, nil
}

func dialActiveX11ForClip() (*xgb.Conn, error) {
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
		return conn, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("X11 display not available")
}

func (c *x11ClipOwner) ensureConnLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := dialActiveX11ForClip()
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
	if err := xproto.CreateWindowChecked(
		conn,
		0,
		win,
		root,
		0, 0, 1, 1, 0,
		xproto.WindowClassInputOnly,
		0,
		0,
		nil,
	).Check(); err != nil {
		conn.Close()
		return err
	}

	c.conn = conn
	c.win = win
	c.atoms = atoms
	go c.serveLoop(conn, win, atoms)
	return nil
}

func (c *x11ClipOwner) serveLoop(conn *xgb.Conn, win xproto.Window, atoms x11ClipAtoms) {
	defer func() {
		conn.Close()
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
			c.win = 0
			c.owned = false
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
		}
	}
}

func (c *x11ClipOwner) handleSelectionRequest(conn *xgb.Conn, atoms x11ClipAtoms, req xproto.SelectionRequestEvent) {
	prop := req.Property
	if prop == 0 {
		prop = req.Target
	}

	c.mu.Lock()
	owned := c.owned
	isImg := c.isImage
	payload := append([]byte(nil), c.data...)
	c.mu.Unlock()

	notify := xproto.SelectionNotifyEvent{
		Time:      req.Time,
		Requestor: req.Requestor,
		Selection: req.Selection,
		Target:    req.Target,
		Property:  xproto.AtomNone,
	}

	if owned && req.Selection == atoms.clipboard {
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
			if xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, req.Requestor, prop, atoms.imagePNG, 8, uint32(len(payload)), payload).Check() == nil {
				notify.Property = prop
			}
		case !isImg && (req.Target == atoms.utf8 || req.Target == atoms.str || req.Target == atoms.text || req.Target == atoms.textPlain || req.Target == atoms.textUTF8):
			if xproto.ChangePropertyChecked(conn, xproto.PropModeReplace, req.Requestor, prop, req.Target, 8, uint32(len(payload)), payload).Check() == nil {
				notify.Property = prop
			}
		}
	}

	_ = xproto.SendEventChecked(conn, false, req.Requestor, 0, string(notify.Bytes())).Check()
}

// x11WriteClipboard sets the Linux X11 CLIPBOARD selection in 100% pure Go (zero xclip/xsel needed!).
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
		linuxX11Clip.conn.Close()
		linuxX11Clip.conn = nil
		linuxX11Clip.owned = false
		return err
	}
	return nil
}

// x11ReadClipboard reads the Linux X11 CLIPBOARD selection (PNG image or UTF-8 text) in 100% pure Go!
func x11ReadClipboard() (byte, []byte, error) {
	// Fast path: if APN itself currently owns the clipboard, return directly!
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

	conn, err := dialActiveX11ForClip()
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
	if err := xproto.CreateWindowChecked(conn, 0, win, root, 0, 0, 1, 1, 0, xproto.WindowClassInputOnly, 0, 0, nil).Check(); err != nil {
		return 0, nil, err
	}
	defer xproto.DestroyWindow(conn, win)

	readTarget := func(target xproto.Atom) ([]byte, bool) {
		_ = xproto.DeletePropertyChecked(conn, win, atoms.prop).Check()
		if err := xproto.ConvertSelectionChecked(conn, win, atoms.clipboard, target, atoms.prop, xproto.TimeCurrentTime).Check(); err != nil {
			return nil, false
		}
		ch := make(chan xproto.Atom, 1)
		go func() {
			for {
				ev, xerr := conn.WaitForEvent()
				if ev == nil && xerr == nil {
					ch <- 0
					return
				}
				if sn, ok := ev.(xproto.SelectionNotifyEvent); ok && sn.Selection == atoms.clipboard {
					ch <- sn.Property
					return
				}
			}
		}()
		select {
		case prop := <-ch:
			if prop == 0 {
				return nil, false
			}
		case <-time.After(700 * time.Millisecond):
			return nil, false
		}
		rep, err := xproto.GetProperty(conn, true, win, atoms.prop, xproto.GetPropertyTypeAny, 0, 4*1024*1024).Reply()
		if err != nil || rep == nil || len(rep.Value) == 0 {
			return nil, false
		}
		return rep.Value, true
	}

	// Probe TARGETS first so we prefer PNG image when available, otherwise UTF8_STRING/STRING text.
	hasPNG := false
	if rawTargets, ok := readTarget(atoms.targets); ok && len(rawTargets) >= 4 {
		for i := 0; i+4 <= len(rawTargets); i += 4 {
			if xproto.Atom(binary.LittleEndian.Uint32(rawTargets[i:i+4])) == atoms.imagePNG {
				hasPNG = true
				break
			}
		}
	}
	if hasPNG {
		if pngBytes, ok := readTarget(atoms.imagePNG); ok && len(pngBytes) > 16 {
			return 1, pngBytes, nil
		}
	}
	if txtBytes, ok := readTarget(atoms.utf8); ok && len(txtBytes) > 0 {
		return 0, txtBytes, nil
	}
	if txtBytes, ok := readTarget(atoms.str); ok && len(txtBytes) > 0 {
		return 0, txtBytes, nil
	}
	return 0, nil, errors.New("คลิปบอร์ดว่างเปล่า")
}
