//go:build linux

package remote

import (
	"context"
	"errors"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"
)

// ClipboardSeq is not available on Linux; callers compare content hashes instead.
func ClipboardSeq() uint32 { return 0 }

// WatchClipboardChanges signals when another application takes the X11 CLIPBOARD (any copy,
// including right-click -> Copy in a terminal). It uses XFixes selection-owner events, so it
// costs nothing while idle, and reconnects when the active display changes (login -> desktop).
// Copies made by APN's own clipboard window are ignored.
func WatchClipboardChanges(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for ctx.Err() == nil {
			if err := watchX11ClipboardOnce(ctx, ch); err != nil {
				sleepCtx(ctx, 3*time.Second)
			}
		}
	}()
	return ch
}

func ownClipWindow(displayKey string) xproto.Window {
	linuxX11Clip.mu.Lock()
	defer linuxX11Clip.mu.Unlock()
	if linuxX11Clip.conn != nil && linuxX11Clip.displayKey == displayKey {
		return linuxX11Clip.win
	}
	return 0
}

func watchX11ClipboardOnce(ctx context.Context, ch chan<- struct{}) error {
	conn, key, err := dialActiveX11ForClip()
	if err != nil {
		return err
	}
	defer conn.Close()

	setup := xproto.Setup(conn)
	if setup == nil || len(setup.Roots) == 0 {
		return errors.New("X11 server has no screens")
	}
	if err := xfixes.Init(conn); err != nil {
		return err
	}
	if _, err := xfixes.QueryVersion(conn, 5, 0).Reply(); err != nil {
		return err
	}
	clip, err := internAtom(conn, "CLIPBOARD")
	if err != nil {
		return err
	}
	root := setup.DefaultScreen(conn).Root
	if err := xfixes.SelectSelectionInputChecked(conn, root, clip, xfixes.SelectionEventMaskSetSelectionOwner).Check(); err != nil {
		return err
	}

	events := make(chan xgb.Event, 16)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(events)
		for {
			ev, xerr := conn.WaitForEvent()
			if ev == nil && xerr == nil {
				return
			}
			if ev == nil {
				continue
			}
			select {
			case events <- ev:
			case <-done:
				return
			}
		}
	}()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if k := captureDisplayKey(); k != "" && k != key {
				return nil // follow the active session to its display
			}
		case ev, ok := <-events:
			if !ok {
				return errors.New("X11 connection closed")
			}
			sn, isSel := ev.(xfixes.SelectionNotifyEvent)
			if !isSel || sn.Selection != clip || sn.Owner == 0 {
				continue
			}
			if own := ownClipWindow(key); own != 0 && sn.Owner == own {
				continue // our own write (viewer -> host); not a new copy
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}
