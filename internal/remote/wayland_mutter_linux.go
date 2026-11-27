//go:build linux

package remote

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"relayvpn/internal/bootstrap"
)

// requestWaylandCaptureTools starts the background install of GStreamer's PipeWire source.
func requestWaylandCaptureTools() {
	bootstrap.EnsureWaylandCaptureTools(context.Background(), nil)
}

// GNOME on Wayland: capture and input through Mutter's own remote-desktop D-Bus API.
//
// x11grab and XTest only reach Xwayland, which on a Wayland session is an empty root window: the
// picture is black and the mouse cannot reach native Wayland windows. Mutter offers the same API
// that GNOME's built-in Remote Desktop uses (org.gnome.Mutter.RemoteDesktop + ScreenCast). It needs
// no confirmation on the remote screen, so unattended access keeps working. GNOME marks it private,
// so other desktops (KDE, wlroots) fall back to the X11 path.
//
// The D-Bus calls have to come from the desktop user's session, so APN (often the root service)
// starts itself as "apn wayland-cast" under that user. The helper owns one remote-desktop session
// with a linked screen-cast stream of the primary monitor, reports the PipeWire node, and applies
// input events it reads as JSON lines on stdin. Video comes from that node through
// gst-launch-1.0 (pipewiresrc), started per FFmpeg launch with the same user rights, and reaches
// FFmpeg as raw BGRx frames on its stdin: the same pixel format x11grab delivers, so every
// existing encoder candidate works unchanged.

const (
	mutterRDName = "org.gnome.Mutter.RemoteDesktop"
	mutterRDPath = "/org/gnome/Mutter/RemoteDesktop"
	mutterSCName = "org.gnome.Mutter.ScreenCast"
	mutterSCPath = "/org/gnome/Mutter/ScreenCast"

	mutterRDSession = "org.gnome.Mutter.RemoteDesktop.Session"
	mutterSCSession = "org.gnome.Mutter.ScreenCast.Session"
	mutterSCStream  = "org.gnome.Mutter.ScreenCast.Stream"

	// evdev codes (linux/input-event-codes.h)
	evBtnLeft      = 0x110
	evBtnRight     = 0x111
	evBtnMiddle    = 0x112
	evKeySpace     = 57
	evKeyLeftShift = 42
	evKeyMeta      = 125

	waylandHelperStartTimeout = 8 * time.Second
	waylandRetryAfterFailure  = 20 * time.Second
	// waylandIdleStop ends the Mutter session this long after the last video or input. While it
	// runs, GNOME shows its remote-desktop indicator in the top bar.
	waylandIdleStop = 45 * time.Second
)

// waylandReady is the helper's first line on stdout.
type waylandReady struct {
	Node   uint32 `json:"node"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Error  string `json:"error,omitempty"`
}

// waylandInputMsg is one input event from APN to the helper.
type waylandInputMsg struct {
	T    string  `json:"t"` // move, button, axis, key, keysym
	X    float64 `json:"x,omitempty"`
	Y    float64 `json:"y,omitempty"`
	Code uint32  `json:"c,omitempty"`
	Down bool    `json:"d,omitempty"`
	N    int32   `json:"n,omitempty"`
}

// ---- helper process (runs as the desktop user) ----

type mutterSession struct {
	conn       *dbus.Conn
	rd         dbus.BusObject
	stream     dbus.ObjectPath
	node       uint32
	w, h       int
	closedSigs chan *dbus.Signal
}

func startMutterSession(conn *dbus.Conn) (*mutterSession, error) {
	var rdPath dbus.ObjectPath
	if err := conn.Object(mutterRDName, mutterRDPath).Call("org.gnome.Mutter.RemoteDesktop.CreateSession", 0).Store(&rdPath); err != nil {
		return nil, fmt.Errorf("Mutter RemoteDesktop.CreateSession: %w", err)
	}
	rd := conn.Object(mutterRDName, rdPath)
	idv, err := rd.GetProperty(mutterRDSession + ".SessionId")
	if err != nil {
		return nil, fmt.Errorf("Mutter remote desktop SessionId: %w", err)
	}
	sessionID, _ := idv.Value().(string)

	var scPath dbus.ObjectPath
	if err := conn.Object(mutterSCName, mutterSCPath).Call("org.gnome.Mutter.ScreenCast.CreateSession", 0,
		map[string]dbus.Variant{"remote-desktop-session-id": dbus.MakeVariant(sessionID)}).Store(&scPath); err != nil {
		return nil, fmt.Errorf("Mutter ScreenCast.CreateSession: %w", err)
	}
	// "" = the primary monitor; cursor-mode 1 = cursor drawn into the picture.
	var streamPath dbus.ObjectPath
	if err := conn.Object(mutterSCName, scPath).Call(mutterSCSession+".RecordMonitor", 0, "",
		map[string]dbus.Variant{"cursor-mode": dbus.MakeVariant(uint32(1))}).Store(&streamPath); err != nil {
		return nil, fmt.Errorf("Mutter ScreenCast.RecordMonitor: %w", err)
	}

	// Mutter sends PipeWireStreamAdded during Start, so listen first. A linked screen-cast session
	// is started through the remote-desktop session (Mutter refuses ScreenCast.Session.Start).
	sigs := make(chan *dbus.Signal, 16)
	conn.Signal(sigs)
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(streamPath), dbus.WithMatchInterface(mutterSCStream),
		dbus.WithMatchMember("PipeWireStreamAdded")); err != nil {
		return nil, err
	}
	_ = conn.AddMatchSignal(dbus.WithMatchObjectPath(rdPath), dbus.WithMatchInterface(mutterRDSession), dbus.WithMatchMember("Closed"))
	if err := rd.Call(mutterRDSession+".Start", 0).Err; err != nil {
		return nil, fmt.Errorf("Mutter RemoteDesktop.Session.Start: %w", err)
	}
	s := &mutterSession{conn: conn, rd: rd, stream: streamPath, closedSigs: sigs}
	deadline := time.After(6 * time.Second)
	for s.node == 0 {
		select {
		case sig := <-sigs:
			if sig.Name == mutterSCStream+".PipeWireStreamAdded" && sig.Path == streamPath && len(sig.Body) > 0 {
				if n, ok := sig.Body[0].(uint32); ok {
					s.node = n
				}
			}
		case <-deadline:
			_ = rd.Call(mutterRDSession+".Stop", 0).Err
			return nil, errors.New("Mutter did not announce the PipeWire stream within 6 s")
		}
	}
	s.w, s.h = mutterStreamSize(conn.Object(mutterSCName, streamPath))
	s.primeInputDevices()
	return s, nil
}

// mutterStreamSize reads the stream's "size" parameter (logical pixels of the recorded monitor).
func mutterStreamSize(obj dbus.BusObject) (int, int) {
	v, err := obj.GetProperty(mutterSCStream + ".Parameters")
	if err != nil {
		return 0, 0
	}
	params, ok := v.Value().(map[string]dbus.Variant)
	if !ok {
		return 0, 0
	}
	size, ok := params["size"]
	if !ok {
		return 0, 0
	}
	if pair, ok := size.Value().([]interface{}); ok && len(pair) == 2 {
		w, _ := pair[0].(int32)
		h, _ := pair[1].(int32)
		return int(w), int(h)
	}
	return 0, 0
}

// primeInputDevices makes Mutter create its virtual pointer and keyboard now. Mutter creates each
// device on its first event and drops that event: in tests the first pointer move and the first
// key of a session did nothing. A 1-pixel move and back, and a Shift tap, are harmless.
func (s *mutterSession) primeInputDevices() {
	call := func(method string, args ...interface{}) {
		_ = s.rd.Call(mutterRDSession+"."+method, 0, args...).Err
	}
	call("NotifyPointerMotionRelative", 1.0, 0.0)
	call("NotifyPointerMotionRelative", -1.0, 0.0)
	call("NotifyKeyboardKeycode", uint32(evKeyLeftShift), true)
	call("NotifyKeyboardKeycode", uint32(evKeyLeftShift), false)
	time.Sleep(150 * time.Millisecond)
}

func (s *mutterSession) apply(m waylandInputMsg) error {
	call := func(method string, args ...interface{}) error {
		return s.rd.Call(mutterRDSession+"."+method, 0, args...).Err
	}
	switch m.T {
	case "move":
		return call("NotifyPointerMotionAbsolute", string(s.stream), m.X, m.Y)
	case "button":
		return call("NotifyPointerButton", int32(m.Code), m.Down)
	case "axis":
		return call("NotifyPointerAxisDiscrete", m.Code, m.N)
	case "key":
		return call("NotifyKeyboardKeycode", m.Code, m.Down)
	case "keysym":
		return call("NotifyKeyboardKeysym", m.Code, m.Down)
	}
	return nil
}

// RunWaylandCastHelper is "apn wayland-cast": it must run as the desktop user, with that
// session's DBUS_SESSION_BUS_ADDRESS. It prints one JSON line (waylandReady) and then applies the
// input events read from stdin until stdin closes or Mutter ends the session.
func RunWaylandCastHelper() error {
	out := json.NewEncoder(os.Stdout)
	fail := func(err error) error {
		_ = out.Encode(waylandReady{Error: err.Error()})
		return err
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fail(fmt.Errorf("connect to the session bus: %w", err))
	}
	defer conn.Close()
	s, err := startMutterSession(conn)
	if err != nil {
		return fail(err)
	}
	if err := out.Encode(waylandReady{Node: s.node, Width: s.w, Height: s.h}); err != nil {
		return err
	}
	var stopping atomic.Bool
	go func() {
		for sig := range s.closedSigs {
			if sig.Name == mutterRDSession+".Closed" {
				if stopping.Load() {
					os.Exit(0)
				}
				fmt.Fprintln(os.Stderr, "Mutter closed the remote desktop session")
				os.Exit(3)
			}
		}
	}()
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var m waylandInputMsg
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if err := s.apply(m); err != nil {
			fmt.Fprintln(os.Stderr, "input:", err)
		}
	}
	stopping.Store(true)
	_ = s.rd.Call(mutterRDSession+".Stop", 0).Err
	return nil
}

// ---- APN side ----

type waylandCastState struct {
	mu      sync.Mutex
	key     string // session the helper belongs to
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	exited  chan struct{}
	ready   waylandReady
	session linuxSessionEnv

	failKey string
	failAt  time.Time
	failErr string

	lastUse   time.Time // last input event or video start
	readers   int       // running GStreamer readers (video streams)
	reaperRun bool
}

var wlCast waylandCastState

var wlSessionCache struct {
	mu sync.Mutex
	at time.Time
	s  linuxSessionEnv
	ok bool
}

// waylandSession returns the active desktop session when it is a Wayland session. Cached for a
// few seconds: input events call it for every mouse move.
func waylandSession() (linuxSessionEnv, bool) {
	wlSessionCache.mu.Lock()
	defer wlSessionCache.mu.Unlock()
	if time.Since(wlSessionCache.at) < 3*time.Second {
		return wlSessionCache.s, wlSessionCache.ok
	}
	s, ok := detectWaylandSession()
	wlSessionCache.at, wlSessionCache.s, wlSessionCache.ok = time.Now(), s, ok
	return s, ok
}

// detectWaylandSession decides from the active session. Session discovery often ends on the
// Xwayland server (found from its command line, typed "x11"): the compositor itself (gnome-shell)
// is started without DISPLAY or WAYLAND_DISPLAY in its environment, so it is not picked. An X
// display served by Xwayland means the real desktop is Wayland.
func detectWaylandSession() (linuxSessionEnv, bool) {
	s := getActiveLinuxSession()
	isWayland := s.SessionType == "wayland" || s.WaylandDisplay != ""
	if !isWayland && s.Display != "" && isXwaylandDisplay(s.Display) {
		isWayland = true
		s.SessionType = "wayland"
	}
	if !isWayland {
		return s, false
	}
	if os.Geteuid() == 0 && !s.HasUserCred {
		return s, false // cannot act as the session's user
	}
	if s.RuntimeDir == "" && s.HasUserCred {
		s.RuntimeDir = "/run/user/" + strconv.Itoa(int(s.UID))
	}
	if s.DBusAddr == "" && s.RuntimeDir != "" {
		s.DBusAddr = "unix:path=" + s.RuntimeDir + "/bus"
	}
	return s, s.DBusAddr != ""
}

// isXwaylandDisplay reports whether an Xwayland process serves the X display disp (e.g. ":0").
func isXwaylandDisplay(disp string) bool {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	var sockets map[string]string
	for _, ent := range ents {
		name := ent.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		pidDir := "/proc/" + name
		comm, err := os.ReadFile(pidDir + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "Xwayland" {
			continue
		}
		cmdline, _ := os.ReadFile(pidDir + "/cmdline")
		d, _ := parseXorgCmdline(cmdline)
		if d == "" {
			if sockets == nil {
				sockets = readX11UnixSockets()
			}
			d = xorgDisplayFromSockets(pidDir, sockets)
		}
		if d == disp {
			return true
		}
	}
	return false
}

// waylandDesktop reports whether the active desktop is a Wayland session.
func waylandDesktop() bool {
	_, ok := waylandSession()
	return ok
}

func waylandSessionKey(s linuxSessionEnv) string {
	return fmt.Sprintf("%d|%s|%s", s.UID, s.RuntimeDir, s.DBusAddr)
}

// waylandUserEnv is the environment for processes that act inside the Wayland session.
func waylandUserEnv(s linuxSessionEnv) []string {
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"XDG_RUNTIME_DIR=" + s.RuntimeDir,
		"DBUS_SESSION_BUS_ADDRESS=" + s.DBusAddr,
		"LANG=C.UTF-8",
	}
	if s.Home != "" {
		env = append(env, "HOME="+s.Home)
	}
	if s.WaylandDisplay != "" {
		env = append(env, "WAYLAND_DISPLAY="+s.WaylandDisplay)
	}
	return env
}

// asSessionUser makes cmd run as the session's user when APN runs as root.
func asSessionUser(cmd *exec.Cmd, s linuxSessionEnv) {
	if os.Geteuid() == 0 && s.HasUserCred && s.UID != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: s.UID, Gid: s.GID}}
	}
}

// ensureWaylandCast starts the helper for the current Wayland session (or returns the running
// one). ok is false when the session is not Wayland or Mutter's API is not available; a failure
// is remembered for waylandRetryAfterFailure so callers do not retry on every frame.
func ensureWaylandCast() (waylandReady, linuxSessionEnv, bool) {
	s, isWayland := waylandSession()
	if !isWayland {
		return waylandReady{}, s, false
	}
	key := waylandSessionKey(s)

	wlCast.mu.Lock()
	defer wlCast.mu.Unlock()
	if wlCast.cmd != nil {
		select {
		case <-wlCast.exited:
			wlCast.cmd, wlCast.stdin = nil, nil
		default:
			if wlCast.key == key {
				wlCast.lastUse = time.Now()
				return wlCast.ready, wlCast.session, true
			}
			wlCast.stopLocked()
		}
	}
	if wlCast.failKey == key && time.Since(wlCast.failAt) < waylandRetryAfterFailure {
		return waylandReady{}, s, false
	}
	ready, err := wlCast.startLocked(s, key)
	if err != nil {
		wlCast.failKey, wlCast.failAt, wlCast.failErr = key, time.Now(), err.Error()
		return waylandReady{}, s, false
	}
	wlCast.failKey, wlCast.failErr = "", ""
	wlCast.lastUse = time.Now()
	if !wlCast.reaperRun {
		wlCast.reaperRun = true
		go wlCast.reapIdle()
	}
	return ready, s, true
}

// reapIdle stops the helper when no video has run and no input came for waylandIdleStop, so
// GNOME's "remote desktop active" indicator does not stay on after the viewer has left.
func (w *waylandCastState) reapIdle() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		w.mu.Lock()
		if w.cmd != nil && w.readers == 0 && time.Since(w.lastUse) > waylandIdleStop {
			w.stopLocked()
		}
		w.mu.Unlock()
	}
}

// waylandStreamSize is the size of the recorded monitor when the session is Wayland and the
// screen cast runs (starting it if needed). ScreenSize uses it: Xwayland's root window spans all
// monitors, while the cast records the primary one.
func waylandStreamSize() (int, int, bool) {
	if !waylandDesktop() {
		return 0, 0, false
	}
	ready, _, ok := ensureWaylandCast()
	if !ok || ready.Width <= 0 || ready.Height <= 0 {
		return 0, 0, false
	}
	return ready.Width, ready.Height, true
}

func (w *waylandCastState) stopLocked() {
	if w.stdin != nil {
		_ = w.stdin.Close() // the helper stops the Mutter session and exits
	}
	if w.cmd != nil && w.cmd.Process != nil {
		exited := w.exited
		proc := w.cmd.Process
		go func() {
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				_ = proc.Kill()
			}
		}()
	}
	w.cmd, w.stdin = nil, nil
}

// waylandHelperExe is the APN binary that runs "wayland-cast" ("" = this executable). Tests set it,
// since a test binary does not have the subcommand.
var waylandHelperExe = ""

func (w *waylandCastState) startLocked(s linuxSessionEnv, key string) (waylandReady, error) {
	exe := waylandHelperExe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return waylandReady{}, err
		}
	}
	cmd := exec.Command(exe, "wayland-cast")
	cmd.Env = waylandUserEnv(s)
	cmd.Dir = "/"
	asSessionUser(cmd, s)
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return waylandReady{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return waylandReady{}, err
	}
	if err := cmd.Start(); err != nil {
		return waylandReady{}, err
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	lineCh := make(chan []byte, 1)
	go func() {
		rd := bufio.NewReader(stdout)
		line, _ := rd.ReadBytes('\n')
		lineCh <- line
		_, _ = io.Copy(io.Discard, rd)
	}()
	var ready waylandReady
	select {
	case line := <-lineCh:
		if err := json.Unmarshal(bytes.TrimSpace(line), &ready); err != nil {
			_ = cmd.Process.Kill()
			return waylandReady{}, fmt.Errorf("wayland helper: %s", strings.TrimSpace(stderr.String()+" "+string(line)))
		}
	case <-time.After(waylandHelperStartTimeout):
		_ = cmd.Process.Kill()
		return waylandReady{}, errors.New("wayland helper did not start in time")
	}
	if ready.Error != "" || ready.Node == 0 {
		_ = cmd.Process.Kill()
		if ready.Error == "" {
			ready.Error = "no PipeWire stream"
		}
		return waylandReady{}, errors.New(ready.Error)
	}
	w.key, w.cmd, w.stdin, w.exited, w.ready, w.session = key, cmd, stdin, exited, ready, s
	return ready, nil
}

// waylandCaptureActive reports whether a Mutter screen-cast helper is running right now.
func waylandCaptureActive() bool {
	wlCast.mu.Lock()
	defer wlCast.mu.Unlock()
	if wlCast.cmd == nil {
		return false
	}
	select {
	case <-wlCast.exited:
		return false
	default:
		return true
	}
}

// waylandCaptureError is why the last attempt to start Wayland capture failed ("" if none).
func waylandCaptureError() string {
	wlCast.mu.Lock()
	defer wlCast.mu.Unlock()
	return wlCast.failErr
}

func sendWaylandInput(m waylandInputMsg) error {
	b, _ := json.Marshal(m)
	b = append(b, '\n')
	wlCast.mu.Lock()
	stdin := wlCast.stdin
	wlCast.mu.Unlock()
	if stdin == nil {
		return errors.New("wayland helper not running")
	}
	_, err := stdin.Write(b)
	return err
}

// applyWaylandInput sends an input event to Mutter when the session is Wayland. handled is false
// when the X11 path should take the event (X11 session, or Mutter's API unavailable).
func applyWaylandInput(ev InputEvent) (bool, error) {
	ready, _, ok := ensureWaylandCast()
	if !ok {
		return false, nil
	}
	w, h := ready.Width, ready.Height
	if w <= 0 || h <= 0 {
		w, h = ScreenSize()
	}
	x := clampF(ev.X, 0, 1) * float64(w-1)
	y := clampF(ev.Y, 0, 1) * float64(h-1)
	move := waylandInputMsg{T: "move", X: x, Y: y}
	btn := func() uint32 {
		switch ev.Button {
		case "right":
			return evBtnRight
		case "middle":
			return evBtnMiddle
		}
		return evBtnLeft
	}
	send := func(msgs ...waylandInputMsg) error {
		for _, m := range msgs {
			if err := sendWaylandInput(m); err != nil {
				return err
			}
		}
		return nil
	}
	switch ev.Type {
	case "mouse_move":
		return true, send(move)
	case "mouse_down":
		return true, send(move, waylandInputMsg{T: "button", Code: btn(), Down: true})
	case "mouse_up":
		return true, send(move, waylandInputMsg{T: "button", Code: btn(), Down: false})
	case "mouse_wheel":
		n := int32(wheelNotches(ev.DeltaY))
		if ev.DeltaY < 0 {
			n = -n
		}
		return true, send(move, waylandInputMsg{T: "axis", Code: 0, N: n})
	case "switch_lang":
		return true, send(
			waylandInputMsg{T: "key", Code: evKeyMeta, Down: true},
			waylandInputMsg{T: "key", Code: evKeySpace, Down: true},
			waylandInputMsg{T: "key", Code: evKeySpace, Down: false},
			waylandInputMsg{T: "key", Code: evKeyMeta, Down: false})
	case "key_down", "key_up":
		kc := codeToX11Keycode(ev.Code, ev.Key)
		if kc <= 8 {
			return false, nil
		}
		return true, send(waylandInputMsg{T: "key", Code: uint32(kc) - 8, Down: ev.Type == "key_down"})
	case "key_text":
		var msgs []waylandInputMsg
		for _, r := range ev.Text {
			sym := uint32(r)
			if r >= 0x100 {
				sym = 0x01000000 | uint32(r) // X keysym for a Unicode code point
			}
			switch r {
			case '\n':
				sym = 0xff0d // Return
			case '\t':
				sym = 0xff09 // Tab
			}
			msgs = append(msgs, waylandInputMsg{T: "keysym", Code: sym, Down: true}, waylandInputMsg{T: "keysym", Code: sym, Down: false})
		}
		return true, send(msgs...)
	}
	return false, nil
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// waylandCaptureSource returns FFmpeg input arguments and a stdin source for capturing the
// Wayland session at srcW x srcH, or ok=false to use x11grab.
func waylandCaptureSource(srcW, srcH, fps int) (*candidateSource, []string, bool) {
	if _, _, ok := ensureWaylandCast(); !ok {
		return nil, nil, false
	}
	gst, ok := gstreamerPipeWire()
	if !ok {
		requestWaylandCaptureTools()
		return nil, nil, false
	}
	args := []string{
		"-f", "rawvideo", "-pixel_format", "bgr0", "-video_size", fmt.Sprintf("%dx%d", srcW, srcH),
		"-framerate", strconv.Itoa(fps), "-use_wallclock_as_timestamps", "1", "-thread_queue_size", "8",
		"-i", "pipe:0",
		// Mutter sends a frame only when the screen changes, like WGC: keep its timing.
		"-fps_mode", "passthrough",
	}
	src := &candidateSource{
		name: "Wayland",
		start: func(ctx context.Context) (*os.File, func(), error) {
			return startPipeWireReader(ctx, gst, srcW, srcH)
		},
	}
	return src, args, true
}

// gstreamerPipeWire finds gst-launch-1.0 and checks that the pipewiresrc element is installed.
var gstCheck struct {
	once sync.Mutex
	at   time.Time
	path string
	ok   bool
}

func gstreamerPipeWire() (string, bool) {
	gstCheck.once.Lock()
	defer gstCheck.once.Unlock()
	if !gstCheck.at.IsZero() && (gstCheck.ok || time.Since(gstCheck.at) < 30*time.Second) {
		return gstCheck.path, gstCheck.ok
	}
	gstCheck.at = time.Now()
	gstCheck.path, gstCheck.ok = "", false
	launch, err := exec.LookPath("gst-launch-1.0")
	if err != nil {
		return "", false
	}
	inspect, err := exec.LookPath("gst-inspect-1.0")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, inspect, "--exists", "pipewiresrc").Run() != nil {
			return "", false
		}
	}
	gstCheck.path, gstCheck.ok = launch, true
	return launch, true
}

// startPipeWireReader starts gst-launch-1.0 reading the helper's PipeWire node and returns the
// read end of a pipe carrying raw BGRx frames of exactly w x h. cleanup stops GStreamer.
func startPipeWireReader(ctx context.Context, gst string, w, h int) (*os.File, func(), error) {
	ready, s, ok := ensureWaylandCast()
	if !ok {
		return nil, nil, errors.New("Wayland screen cast is not available")
	}
	r, wpipe, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	// keepalive-time re-sends the last frame on a still screen so periodic keyframes keep coming.
	cmd := exec.CommandContext(ctx, gst, "-q",
		"pipewiresrc", "path="+strconv.FormatUint(uint64(ready.Node), 10), "do-timestamp=true", "keepalive-time=1000", "always-copy=true",
		"!", "videoconvert",
		"!", "videoscale",
		"!", fmt.Sprintf("video/x-raw,format=BGRx,width=%d,height=%d", w, h),
		"!", "fdsink", "fd=1", "sync=false")
	cmd.Env = waylandUserEnv(s)
	cmd.Dir = "/"
	asSessionUser(cmd, s)
	cmd.Stdout = wpipe
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		r.Close()
		wpipe.Close()
		return nil, nil, fmt.Errorf("start gst-launch-1.0: %w", err)
	}
	wpipe.Close() // GStreamer holds the write end now
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	wlCast.mu.Lock()
	wlCast.readers++
	wlCast.lastUse = time.Now()
	wlCast.mu.Unlock()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = cmd.Process.Kill()
			<-done
			wlCast.mu.Lock()
			wlCast.readers--
			wlCast.lastUse = time.Now()
			wlCast.mu.Unlock()
		})
	}
	return r, cleanup, nil
}

// limitedWriter keeps at most n bytes.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, _ = l.w.Write(q)
	return len(p), nil
}
