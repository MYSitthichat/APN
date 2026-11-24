//go:build linux

package remote

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

type linuxSessionEnv struct {
	Display        string
	XAuthority     string
	WaylandDisplay string
	SessionType    string // "x11", "wayland", ""
	RuntimeDir     string
	DBusAddr       string
	Home           string
	UID            uint32
	GID            uint32
	HasUserCred    bool
	Priority       int
}

var (
	xauthEnvMu      sync.Mutex
	activeSessionMu sync.RWMutex
	activeSession   linuxSessionEnv
	activeSessionAt time.Time
)

func getActiveLinuxSession() linuxSessionEnv {
	activeSessionMu.RLock()
	s := activeSession
	at := activeSessionAt
	activeSessionMu.RUnlock()

	// Refresh cached session every 3s if empty or greeter (uid < 1000) so login transitions happen automatically!
	if s.Display != "" && s.XAuthority != "" && (!s.HasUserCred || s.UID >= 1000) && time.Since(at) < 10*time.Second {
		return s
	}
	if s.Display != "" && time.Since(at) < 3*time.Second {
		return s
	}

	cands := discoverLinuxSessions()
	if len(cands) > 0 {
		setActiveLinuxSession(cands[0])
		return cands[0]
	}
	return s
}

func setActiveLinuxSession(s linuxSessionEnv) {
	activeSessionMu.Lock()
	activeSession = s
	activeSessionAt = time.Now()
	activeSessionMu.Unlock()
}

// discoverLinuxSessions finds ALL active graphical sessions on Linux in priority order:
//   1. Active logged-in desktop user's session (uid >= 1000: GNOME, KDE, XFCE, Cinnamon, MATE, etc.)
//   2. Running Xorg server command line (`Xorg :0 -auth /var/run/lightdm/root/:0`, GDM, SDDM)
//   3. Display-manager Login Screen greeter (GDM/LightDM/SDDM, uid < 1000) — enables remote login after reboot!
//   4. Filesystem fallback across /tmp/.X11-unix/X* and all /run/user/* / /home/* Xauthority files.
func discoverLinuxSessions() []linuxSessionEnv {
	var out []linuxSessionEnv
	seen := map[string]bool{}
	add := func(s linuxSessionEnv) {
		s.Display = strings.TrimSpace(s.Display)
		s.XAuthority = strings.TrimSpace(s.XAuthority)
		s.WaylandDisplay = strings.TrimSpace(s.WaylandDisplay)
		s.SessionType = strings.ToLower(strings.TrimSpace(s.SessionType))
		if s.XAuthority != "" {
			if st, err := os.Stat(s.XAuthority); err != nil || st.IsDir() || st.Size() == 0 {
				s.XAuthority = ""
			}
		}
		if s.Display == "" && s.WaylandDisplay == "" {
			return
		}
		key := fmt.Sprintf("%s|%s|%s|%d", s.Display, s.XAuthority, s.WaylandDisplay, s.UID)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}

	// 1. Current process's own desktop environment (when launched directly inside a user's GUI session)
	if disp := strings.TrimSpace(os.Getenv("DISPLAY")); disp != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		uid := uint32(os.Getuid())
		gid := uint32(os.Getgid())
		xauth := strings.TrimSpace(os.Getenv("XAUTHORITY"))
		home, _ := os.UserHomeDir()
		if xauth == "" {
			xauth = findXAuthForUser(uid, home)
		}
		prio := 220
		if uid == 0 {
			prio = 140
		}
		add(linuxSessionEnv{
			Display:        disp,
			XAuthority:     xauth,
			WaylandDisplay: strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")),
			SessionType:    strings.TrimSpace(os.Getenv("XDG_SESSION_TYPE")),
			RuntimeDir:     strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")),
			DBusAddr:       strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")),
			Home:           home,
			UID:            uid,
			GID:            gid,
			HasUserCred:    uid > 0,
			Priority:       prio,
		})
	}

	// 2. Scan /proc/*/environ and /proc/*/cmdline (works seamlessly for apn.service running as root!)
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			pidName := ent.Name()
			if len(pidName) == 0 || pidName[0] < '0' || pidName[0] > '9' {
				continue
			}
			pidDir := filepath.Join("/proc", pidName)
			commBytes, err := os.ReadFile(filepath.Join(pidDir, "comm"))
			if err != nil {
				continue
			}
			comm := strings.TrimSpace(string(commBytes))
			basePrio := desktopProcPriority(comm)
			if basePrio == 0 {
				continue
			}

			var uid, gid uint32
			var hasCred bool
			if fi, err := os.Stat(pidDir); err == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					uid, gid = st.Uid, st.Gid
					hasCred = true
				}
			}

			// Special handling for Xorg / X server: parse `-auth <path>` and `:<N>` from cmdline!
			if comm == "Xorg" || comm == "X" || comm == "Xwayland" {
				if cmdBytes, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil && len(cmdBytes) > 0 {
					disp, xauth := parseXorgCmdline(cmdBytes)
					if disp != "" {
						p := basePrio + displayNumberPriority(disp)
						if xauth != "" {
							p += 30
						}
						if uid >= 1000 || strings.Contains(xauth, "/run/user/1") || strings.Contains(xauth, "/home/") {
							p += 50
						}
						// Real physical console Xorg is always launched with vtN (e.g. vt2 / vt7) or -seat seat0!
						cmdStr := string(bytes.ReplaceAll(cmdBytes, []byte{0}, []byte{' '}))
						if strings.Contains(cmdStr, "seat0") || strings.Contains(cmdStr, " vt") {
							p += 180
						}
						add(linuxSessionEnv{
							Display:     disp,
							XAuthority:  xauth,
							SessionType: "x11",
							UID:         uid,
							GID:         gid,
							HasUserCred: hasCred && uid > 0,
							Priority:    p,
						})
					}
				}
			}

			envBytes, err := os.ReadFile(filepath.Join(pidDir, "environ"))
			if err != nil || len(envBytes) == 0 {
				continue
			}
			envMap := parseProcEnviron(envBytes)
			disp := envMap["DISPLAY"]
			wdisp := envMap["WAYLAND_DISPLAY"]
			if disp == "" && wdisp == "" {
				continue
			}
			xauth := envMap["XAUTHORITY"]
			home := envMap["HOME"]
			runtimeDir := envMap["XDG_RUNTIME_DIR"]
			if xauth == "" {
				xauth = findXAuthForUser(uid, home)
			}
			if runtimeDir == "" && uid > 0 {
				candRD := fmt.Sprintf("/run/user/%d", uid)
				if fi, err := os.Stat(candRD); err == nil && fi.IsDir() {
					runtimeDir = candRD
				}
			}
			dbusAddr := envMap["DBUS_SESSION_BUS_ADDRESS"]
			if dbusAddr == "" && runtimeDir != "" {
				busPath := filepath.Join(runtimeDir, "bus")
				if _, err := os.Stat(busPath); err == nil {
					dbusAddr = "unix:path=" + busPath
				}
			}

			prio := basePrio + displayNumberPriority(disp)
			if uid >= 1000 {
				prio += 80 // Logged-in interactive user ALWAYS beats login greeter (gdm/lightdm/sddm)!
			}
			// Physical console monitor (seat0 / VT) ALWAYS beats virtual headless sessions (xrdp/VNC/CRD :10/:20)!
			if strings.EqualFold(envMap["XDG_SEAT"], "seat0") || envMap["XDG_VTNR"] != "" {
				prio += 200
			}
			if xauth != "" {
				prio += 20
			}
			if disp != "" {
				prio += 10
			}

			add(linuxSessionEnv{
				Display:        disp,
				XAuthority:     xauth,
				WaylandDisplay: wdisp,
				SessionType:    envMap["XDG_SESSION_TYPE"],
				RuntimeDir:     runtimeDir,
				DBusAddr:       dbusAddr,
				Home:           home,
				UID:            uid,
				GID:            gid,
				HasUserCred:    hasCred && uid > 0,
				Priority:       prio,
			})
		}
	}

	// 3. Filesystem fallback: match all live /tmp/.X11-unix/X* sockets with all system Xauthority files
	var displays []string
	if matches, err := filepath.Glob("/tmp/.X11-unix/X*"); err == nil && len(matches) > 0 {
		// Prefer real physical displays (:1, :0, :2..:9) BEFORE virtual displays (:10, :20, :99)
		sort.Slice(matches, func(i, j int) bool {
			ni, nj := displayNumFromSock(matches[i]), displayNumFromSock(matches[j])
			iPhys, jPhys := ni >= 0 && ni < 10, nj >= 0 && nj < 10
			if iPhys != jPhys {
				return iPhys
			}
			if iPhys {
				// Among physical displays, prefer :1 (logged-in user desktop) over :0 (GDM greeter)
				return ni > nj
			}
			return ni < nj
		})
		for _, m := range matches {
			base := filepath.Base(m)
			if strings.HasPrefix(base, "X") && len(base) > 1 {
				displays = append(displays, ":"+base[1:])
			}
		}
	}
	if len(displays) == 0 {
		displays = []string{":0"}
	}

	xauthFiles := discoverAllXAuthFiles()
	for idx, disp := range displays {
		dispBonus := displayNumberPriority(disp)
		if idx == 0 {
			dispBonus += 5
		}
		for _, xa := range xauthFiles {
			p := 30 + dispBonus
			if xa.uid >= 1000 {
				p += 25
			}
			add(linuxSessionEnv{
				Display:     disp,
				XAuthority:  xa.path,
				UID:         xa.uid,
				GID:         xa.gid,
				HasUserCred: xa.uid > 0,
				Priority:    p,
			})
		}
		// Also allow trying the display with no explicit XAUTHORITY (e.g. `xhost +local:` setups)
		add(linuxSessionEnv{
			Display:  disp,
			Priority: 10 + dispBonus,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority > out[j].Priority
	})
	return out
}

func desktopProcPriority(comm string) int {
	switch comm {
	case "gnome-shell", "plasmashell", "kwin_x11", "kwin_wayland",
		"xfce4-session", "xfwm4", "cinnamon", "mate-session",
		"lxqt-session", "lxsession", "budgie-wm", "marco",
		"sway", "Hyprland", "mutter", "openbox", "i3":
		return 120
	case "gnome-session-b", "gnome-session", "gdm-x-session", "gdm-wayland-ses", "startplasma-x11", "startplasma-way":
		return 95
	case "Xorg", "X", "Xwayland":
		return 75
	}
	return 0
}

func parseProcEnviron(data []byte) map[string]string {
	m := make(map[string]string, 16)
	for _, entry := range bytes.Split(data, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		idx := bytes.IndexByte(entry, '=')
		if idx <= 0 {
			continue
		}
		k := string(entry[:idx])
		switch k {
		case "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE",
			"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME",
			"XDG_SEAT", "XDG_VTNR":
			m[k] = string(entry[idx+1:])
		}
	}
	return m
}

func parseXorgCmdline(data []byte) (display, xauth string) {
	parts := bytes.Split(data, []byte{0})
	for i := 0; i < len(parts); i++ {
		arg := strings.TrimSpace(string(parts[i]))
		if arg == "" {
			continue
		}
		if arg == "-auth" && i+1 < len(parts) {
			xauth = strings.TrimSpace(string(parts[i+1]))
			i++
			continue
		}
		if display == "" && strings.HasPrefix(arg, ":") && len(arg) >= 2 && arg[1] >= '0' && arg[1] <= '9' {
			display = arg
		}
	}
	// If Xorg used `-displayfd` without an explicit `:N` arg, match a real physical console socket (:0..:9) first
	if display == "" && xauth != "" {
		if matches, err := filepath.Glob("/tmp/.X11-unix/X*"); err == nil && len(matches) > 0 {
			sort.Slice(matches, func(i, j int) bool {
				ni, nj := displayNumFromSock(matches[i]), displayNumFromSock(matches[j])
				iPhys, jPhys := ni >= 0 && ni < 10, nj >= 0 && nj < 10
				if iPhys != jPhys {
					return iPhys
				}
				if iPhys {
					return ni > nj
				}
				return ni < nj
			})
			base := filepath.Base(matches[0])
			if strings.HasPrefix(base, "X") && len(base) > 1 {
				display = ":" + base[1:]
			}
		}
	}
	return display, xauth
}

func displayNumFromSock(path string) int {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "X") {
		return -1
	}
	n, err := strconv.Atoi(base[1:])
	if err != nil {
		return -1
	}
	return n
}

// displayNumberPriority strongly prefers physical console displays (:0..:4) over
// virtual/headless remote sessions like xrdp (:10), Chrome Remote Desktop (:20), or Xvfb (:99).
func displayNumberPriority(disp string) int {
	s := strings.TrimSpace(disp)
	if !strings.HasPrefix(s, ":") {
		return 0
	}
	s = s[1:]
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		s = s[:dot]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	if n <= 4 {
		return 80
	}
	if n < 10 {
		return 20
	}
	return -140
}

func findXAuthForUser(uid uint32, home string) string {
	var cands []string
	if uid > 0 {
		cands = append(cands, fmt.Sprintf("/run/user/%d/gdm/Xauthority", uid))
		if mutter, err := filepath.Glob(fmt.Sprintf("/run/user/%d/.mutter-Xwaylandauth.*", uid)); err == nil {
			cands = append(cands, mutter...)
		}
		if xauths, err := filepath.Glob(fmt.Sprintf("/run/user/%d/xauth_*", uid)); err == nil {
			cands = append(cands, xauths...)
		}
	}
	if home != "" {
		cands = append(cands, filepath.Join(home, ".Xauthority"))
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Size() > 0 {
			return c
		}
	}
	return ""
}

type xauthCandidate struct {
	path string
	uid  uint32
	gid  uint32
}

func discoverAllXAuthFiles() []xauthCandidate {
	patterns := []string{
		"/run/user/*/gdm/Xauthority",
		"/run/user/*/.mutter-Xwaylandauth.*",
		"/run/user/*/xauth_*",
		"/home/*/.Xauthority",
		"/var/run/lightdm/root/*",
		"/run/gdm3/*/database",
		"/run/sddm/*",
		"/root/.Xauthority",
	}
	var out []xauthCandidate
	seen := map[string]bool{}
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if seen[m] {
				continue
			}
			st, err := os.Stat(m)
			if err != nil || st.IsDir() || st.Size() == 0 {
				continue
			}
			seen[m] = true
			var uid, gid uint32
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid, gid = sys.Uid, sys.Gid
			}
			out = append(out, xauthCandidate{path: m, uid: uid, gid: gid})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		iUser := out[i].uid >= 1000
		jUser := out[j].uid >= 1000
		if iUser != jUser {
			return iUser
		}
		return out[i].path < out[j].path
	})
	return out
}

// detectLinuxDisplayEnv returns the best active DISPLAY and XAUTHORITY,
// working both for desktop user launches AND root systemd service (apn.service) before & after login.
func detectLinuxDisplayEnv() (display, xauth string) {
	s := getActiveLinuxSession()
	if s.Display == "" {
		return ":0", s.XAuthority
	}
	return s.Display, s.XAuthority
}

func linuxCmdEnv() []string {
	s := getActiveLinuxSession()
	overrides := map[string]string{}
	if s.Display != "" {
		overrides["DISPLAY"] = s.Display
	}
	if s.XAuthority != "" {
		overrides["XAUTHORITY"] = s.XAuthority
	}
	if s.WaylandDisplay != "" {
		overrides["WAYLAND_DISPLAY"] = s.WaylandDisplay
	}
	if s.SessionType != "" {
		overrides["XDG_SESSION_TYPE"] = s.SessionType
	}
	if s.RuntimeDir != "" {
		overrides["XDG_RUNTIME_DIR"] = s.RuntimeDir
	}
	if s.DBusAddr != "" {
		overrides["DBUS_SESSION_BUS_ADDRESS"] = s.DBusAddr
	}
	if s.Home != "" && os.Geteuid() == 0 && s.HasUserCred && s.UID >= 1000 {
		overrides["HOME"] = s.Home
	}

	base := os.Environ()
	env := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			if _, drop := overrides[kv[:eq]]; drop {
				continue
			}
		}
		env = append(env, kv)
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

// applyLinuxUserCred drops privileges to the active desktop user ONLY for user-session tools
// (Wayland / D-Bus screenshot & clipboard tools) when APN is running as root systemd service.
func applyLinuxUserCred(cmd *exec.Cmd) {
	if os.Geteuid() != 0 {
		return
	}
	s := getActiveLinuxSession()
	if s.HasUserCred && s.UID >= 1000 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: s.UID,
				Gid: s.GID,
			},
		}
	}
}

func isLinuxWayland() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("XDG_SESSION_TYPE")), "wayland") {
		return true
	}
	if strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return true
	}
	s := getActiveLinuxSession()
	return s.SessionType == "wayland" || s.WaylandDisplay != ""
}

// x11State holds a reusable pure-Go X11 connection.
// Capture and Input use TWO separate connections so mouse_move NEVER blocks waiting on GetImage!
type x11State struct {
	mu            sync.Mutex
	conn          *xgb.Conn
	root          xproto.Window
	w, h          int
	depth         byte
	hasTest       bool
	buf           *image.RGBA
	session       linuxSessionEnv
	lastUpgradeAt time.Time
}

var (
	linuxX11Cap x11State
	linuxX11Inp x11State
)

func (x *x11State) ensureLocked() error {
	// If currently attached to a login-screen greeter (uid < 1000), check every 3s whether
	// an interactive user has logged in and seamlessly switch to their active desktop!
	if x.conn != nil && x.session.UID < 1000 && time.Since(x.lastUpgradeAt) > 3*time.Second {
		x.lastUpgradeAt = time.Now()
		for _, c := range discoverLinuxSessions() {
			if c.UID >= 1000 && c.Display != "" && (c.Display != x.session.Display || c.XAuthority != x.session.XAuthority) {
				x.resetLocked()
				break
			}
		}
	}
	if x.conn != nil {
		return nil
	}

	cands := discoverLinuxSessions()
	if len(cands) == 0 {
		return errors.New("ไม่พบหน้าจอ X11 ที่เปิดใช้งานอยู่ (/tmp/.X11-unix)")
	}

	var lastErr error
	xauthEnvMu.Lock()
	defer xauthEnvMu.Unlock()

	for _, cand := range cands {
		if cand.Display == "" {
			continue
		}
		if cand.XAuthority != "" {
			_ = os.Setenv("XAUTHORITY", cand.XAuthority)
		} else {
			_ = os.Unsetenv("XAUTHORITY")
		}
		conn, err := xgb.NewConnDisplay(cand.Display)
		if err != nil {
			lastErr = fmt.Errorf("X11 %s: %w", cand.Display, err)
			continue
		}
		setup := xproto.Setup(conn)
		if setup == nil || len(setup.Roots) == 0 {
			conn.Close()
			lastErr = fmt.Errorf("X11 %s has no screens", cand.Display)
			continue
		}
		screen := setup.DefaultScreen(conn)
		x.conn = conn
		x.root = screen.Root
		x.w = int(screen.WidthInPixels)
		x.h = int(screen.HeightInPixels)
		x.depth = screen.RootDepth
		x.hasTest = xtest.Init(conn) == nil
		x.session = cand
		x.lastUpgradeAt = time.Now()
		setActiveLinuxSession(cand)
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("ไม่สามารถเชื่อมต่อ X11 Display ได้")
}

func (x *x11State) resetLocked() {
	if x.conn != nil {
		x.conn.Close()
		x.conn = nil
	}
	x.hasTest = false
}

func x11ScreenSize() (int, int, bool) {
	linuxX11Cap.mu.Lock()
	defer linuxX11Cap.mu.Unlock()
	if err := linuxX11Cap.ensureLocked(); err != nil {
		return 0, 0, false
	}
	geom, err := xproto.GetGeometry(linuxX11Cap.conn, xproto.Drawable(linuxX11Cap.root)).Reply()
	if err == nil && geom.Width > 0 && geom.Height > 0 {
		linuxX11Cap.w = int(geom.Width)
		linuxX11Cap.h = int(geom.Height)
	}
	if linuxX11Cap.w > 0 && linuxX11Cap.h > 0 {
		return linuxX11Cap.w, linuxX11Cap.h, true
	}
	return 0, 0, false
}

// captureX11Native captures the entire root desktop in 100% pure Go (zero CGO, zero external tools).
func captureX11Native() (*image.RGBA, error) {
	linuxX11Cap.mu.Lock()
	defer linuxX11Cap.mu.Unlock()

	if err := linuxX11Cap.ensureLocked(); err != nil {
		return nil, err
	}

	geom, err := xproto.GetGeometry(linuxX11Cap.conn, xproto.Drawable(linuxX11Cap.root)).Reply()
	if err != nil {
		linuxX11Cap.resetLocked()
		return nil, err
	}
	w, h := int(geom.Width), int(geom.Height)
	if w <= 0 || h <= 0 {
		return nil, errors.New("invalid X11 root screen geometry")
	}
	linuxX11Cap.w, linuxX11Cap.h = w, h

	reply, err := xproto.GetImage(
		linuxX11Cap.conn,
		xproto.ImageFormatZPixmap,
		xproto.Drawable(linuxX11Cap.root),
		0, 0,
		uint16(w), uint16(h),
		0xffffffff,
	).Reply()
	if err != nil {
		linuxX11Cap.resetLocked()
		return nil, err
	}

	data := reply.Data
	if len(data) < w*h*4 {
		return nil, fmt.Errorf("unexpected X11 ZPixmap size: got %d want %d", len(data), w*h*4)
	}

	if linuxX11Cap.buf == nil || linuxX11Cap.buf.Bounds().Dx() != w || linuxX11Cap.buf.Bounds().Dy() != h {
		linuxX11Cap.buf = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	pix := linuxX11Cap.buf.Pix
	total := w * h * 4
	// X11 ZPixmap 24/32-bit on little-endian Linux is BGRX -> convert in-place to RGBA.
	for i := 0; i < total; i += 4 {
		pix[i] = data[i+2]
		pix[i+1] = data[i+1]
		pix[i+2] = data[i]
		pix[i+3] = 255
	}

	sizeMu.Lock()
	lastW, lastH = w, h
	sizeMu.Unlock()
	return linuxX11Cap.buf, nil
}

// applyX11Input injects mouse/wheel/keyboard events directly into X11 via a DEDICATED X11 connection
// (~0.1ms, zero contention with screen capture, zero xdotool spawn overhead!).
func applyX11Input(ev InputEvent) (bool, error) {
	linuxX11Inp.mu.Lock()
	defer linuxX11Inp.mu.Unlock()

	if err := linuxX11Inp.ensureLocked(); err != nil {
		return false, nil
	}
	// Use live tracked screen size so mouse mapping stays accurate even after resolution changes.
	sizeMu.RLock()
	w, h := lastW, lastH
	sizeMu.RUnlock()
	if w <= 0 || h <= 0 {
		w, h = linuxX11Inp.w, linuxX11Inp.h
	}
	if w <= 0 || h <= 0 {
		w, h = 1920, 1080
	}
	px := int16(clamp(int(ev.X*float64(w)), 0, w-1))
	py := int16(clamp(int(ev.Y*float64(h)), 0, h-1))

	if !linuxX11Inp.hasTest {
		if ev.Type == "mouse_move" {
			xproto.WarpPointer(linuxX11Inp.conn, xproto.WindowNone, linuxX11Inp.root, 0, 0, 0, 0, px, py)
			return true, nil
		}
		return false, nil
	}

	switch ev.Type {
	case "mouse_move":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		return true, nil
	case "mouse_down":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonPress, x11MouseBtn(ev.Button), 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "mouse_up":
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonRelease, x11MouseBtn(ev.Button), 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "mouse_wheel":
		btn := byte(5) // scroll down
		if ev.DeltaY < 0 {
			btn = 4 // scroll up
		}
		xtest.FakeInput(linuxX11Inp.conn, xproto.MotionNotify, 0, 0, linuxX11Inp.root, px, py, 0)
		for n := wheelNotches(ev.DeltaY); n > 0; n-- {
			xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonPress, btn, 0, linuxX11Inp.root, 0, 0, 0)
			xtest.FakeInput(linuxX11Inp.conn, xproto.ButtonRelease, btn, 0, linuxX11Inp.root, 0, 0, 0)
		}
		return true, nil
	case "switch_lang":
		// Super_L (133) + Space (65) — standard GNOME / Ubuntu input source switch
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, 133, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, 65, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, 65, 0, linuxX11Inp.root, 0, 0, 0)
		xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, 133, 0, linuxX11Inp.root, 0, 0, 0)
		return true, nil
	case "key_down":
		if kc := codeToX11Keycode(ev.Code, ev.Key); kc != 0 {
			xtest.FakeInput(linuxX11Inp.conn, xproto.KeyPress, kc, 0, linuxX11Inp.root, 0, 0, 0)
			return true, nil
		}
		return false, nil
	case "key_up":
		if kc := codeToX11Keycode(ev.Code, ev.Key); kc != 0 {
			xtest.FakeInput(linuxX11Inp.conn, xproto.KeyRelease, kc, 0, linuxX11Inp.root, 0, 0, 0)
			return true, nil
		}
		return false, nil
	}
	return false, nil
}

func x11MouseBtn(b string) byte {
	switch b {
	case "right":
		return 3
	case "middle":
		return 2
	default:
		return 1
	}
}

// codeToX11Keycode maps W3C KeyboardEvent.code (physical key) to standard Linux Xorg evdev+8 keycodes.
// Physical keycodes work seamlessly for both English and Thai layouts as well as all shortcuts (Ctrl+C/V, Alt+Tab, Super+Space).
func codeToX11Keycode(code, key string) byte {
	if kc, ok := w3cCodeToEvdevX11[code]; ok {
		return kc
	}
	switch key {
	case "Enter":
		return 36
	case "Escape":
		return 9
	case "Backspace":
		return 22
	case "Tab":
		return 23
	case " ":
		return 65
	case "Meta", "Super", "OS":
		return 133
	case "ArrowUp":
		return 111
	case "ArrowDown":
		return 116
	case "ArrowLeft":
		return 113
	case "ArrowRight":
		return 114
	case "Delete":
		return 119
	case "Home":
		return 110
	case "End":
		return 115
	case "PageUp":
		return 112
	case "PageDown":
		return 117
	}
	return 0
}

// Standard Linux evdev keycode + 8 = X11 keycode.
var w3cCodeToEvdevX11 = map[string]byte{
	"Escape":         9,
	"Digit1":         10,
	"Digit2":         11,
	"Digit3":         12,
	"Digit4":         13,
	"Digit5":         14,
	"Digit6":         15,
	"Digit7":         16,
	"Digit8":         17,
	"Digit9":         18,
	"Digit0":         19,
	"Minus":          20,
	"Equal":          21,
	"Backspace":      22,
	"Tab":            23,
	"KeyQ":           24,
	"KeyW":           25,
	"KeyE":           26,
	"KeyR":           27,
	"KeyT":           28,
	"KeyY":           29,
	"KeyU":           30,
	"KeyI":           31,
	"KeyO":           32,
	"KeyP":           33,
	"BracketLeft":    34,
	"BracketRight":   35,
	"Enter":          36,
	"ControlLeft":    37,
	"KeyA":           38,
	"KeyS":           39,
	"KeyD":           40,
	"KeyF":           41,
	"KeyG":           42,
	"KeyH":           43,
	"KeyJ":           44,
	"KeyK":           45,
	"KeyL":           46,
	"Semicolon":      47,
	"Quote":          48,
	"Backquote":      49,
	"ShiftLeft":      50,
	"Backslash":      51,
	"KeyZ":           52,
	"KeyX":           53,
	"KeyC":           54,
	"KeyV":           55,
	"KeyB":           56,
	"KeyN":           57,
	"KeyM":           58,
	"Comma":          59,
	"Period":         60,
	"Slash":          61,
	"ShiftRight":     62,
	"NumpadMultiply": 63,
	"AltLeft":        64,
	"Space":          65,
	"CapsLock":       66,
	"F1":             67,
	"F2":             68,
	"F3":             69,
	"F4":             70,
	"F5":             71,
	"F6":             72,
	"F7":             73,
	"F8":             74,
	"F9":             75,
	"F10":            76,
	"NumLock":        77,
	"ScrollLock":     78,
	"Numpad7":        79,
	"Numpad8":        80,
	"Numpad9":        81,
	"NumpadSubtract": 82,
	"Numpad4":        83,
	"Numpad5":        84,
	"Numpad6":        85,
	"NumpadAdd":      86,
	"Numpad1":        87,
	"Numpad2":        88,
	"Numpad3":        89,
	"Numpad0":        90,
	"NumpadDecimal":  91,
	"F11":            95,
	"F12":            96,
	"NumpadEnter":    104,
	"ControlRight":   105,
	"NumpadDivide":   106,
	"PrintScreen":    107,
	"AltRight":       108,
	"Home":           110,
	"ArrowUp":        111,
	"PageUp":         112,
	"ArrowLeft":      113,
	"ArrowRight":     114,
	"End":            115,
	"ArrowDown":      116,
	"PageDown":       117,
	"Insert":         118,
	"Delete":         119,
	"Pause":          127,
	"MetaLeft":       133,
	"MetaRight":      134,
	"ContextMenu":    135,
}
