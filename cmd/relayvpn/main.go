package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"relayvpn/internal/agent"
	"relayvpn/internal/bootstrap"
	"relayvpn/internal/client"
	"relayvpn/internal/config"
	"relayvpn/internal/executil"
	"relayvpn/internal/installer"
	"relayvpn/internal/p2p"
	"relayvpn/internal/remote"
	"relayvpn/internal/rendezvous"
	"relayvpn/internal/security"
	"relayvpn/internal/server"
	"relayvpn/internal/service"
	"relayvpn/internal/tray"
	"relayvpn/internal/updater"
	"relayvpn/internal/version"
	"relayvpn/internal/webui"
)

var appVersion = version.Version

func main() {
	updater.CleanupOldBinary()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Double-clicking APN.exe with no arguments hides the console, sits in System Tray,
	// and opens a clean standalone APN App Window (or brings up the already-running instance)!
	if len(os.Args) < 2 {
		tray.HideConsoleWindow()
		if err := runPeer([]string{"-open", "-tray-icon"}, logger); err != nil {
			logger.Error("peer mode failed", "err", err)
			os.Exit(1)
		}
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = runInit(args)
	case "server":
		err = runServer(args, logger)
	case "agent":
		err = runAgent(args, logger)
	case "client":
		err = runClient(args, logger)
	case "peer":
		err = runPeer(args, logger)
	case "rdv-server":
		err = runRdvServer(args, logger)
	case "wayland-cast":
		// Internal: started by APN as the desktop user to drive GNOME's Wayland screen cast.
		err = remote.RunWaylandCastHelper()
	case "service":
		err = runService(args)
	case "set-password":
		err = runSetPassword(args)
	case "install":
		st, ierr := installer.Install()
		if ierr != nil {
			err = ierr
		} else {
			fmt.Printf("Installed APN v%s to %s (Auto-Start: %v)\n", appVersion, st.InstallPath, st.AutoStart)
		}
	case "uninstall":
		err = installer.Uninstall()
		if err == nil {
			fmt.Println("Uninstalled APN successfully.")
		}
	case "token":
		err = runToken()
	case "version", "-v", "--version":
		fmt.Printf("APN v%s (%s/%s)\n", appVersion, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		logger.Error("command failed", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "./config", "Output directory for generated configs and TLS certs")
	host := fs.String("host", "localhost", "Public domain or IP address of your Relay Server")
	port := fs.Int("port", 443, "TLS/WSS listen port (default 443; use 8443 for non-root local testing)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := config.InitBundle(*dir, *host, *port)
	if err != nil {
		return err
	}

	fmt.Println("Generated RelayVPN configuration bundle:")
	fmt.Printf("  Server config : %s\n", res.ServerFile)
	fmt.Printf("  Agent config  : %s\n", res.AgentFile)
	fmt.Printf("  Client config : %s\n", res.ClientFile)
	fmt.Printf("  Private CA    : %s\n", res.CACert)
	fmt.Printf("  Server TLS    : %s + %s\n", res.ServerCert, res.ServerKey)
	fmt.Println("\nQuick start:")
	fmt.Printf("  1. Server: relayvpn server -config %s\n", res.ServerFile)
	fmt.Printf("  2. Agent : relayvpn agent  -config %s\n", res.AgentFile)
	fmt.Printf("  3. Client: relayvpn client -config %s\n", res.ClientFile)
	return nil
}

func runServer(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "./config/server.json", "Path to server config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadJSON[config.ServerConfig](*cfgPath)
	if err != nil {
		return err
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		return err
	}

	if cfg.EnableWebPortal {
		srv.SetPortalHandler(webui.NewPortalHandler(srv, logger))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.AdminUIAddr != "" {
		go func() {
			if err := webui.Start(ctx, webui.Options{
				Addr:   cfg.AdminUIAddr,
				Mode:   "server",
				Server: srv,
				Logger: logger,
			}); err != nil {
				logger.Error("server web ui error", "err", err)
			}
		}()
	}

	return srv.Run(ctx)
}

func runAgent(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	cfgPath := fs.String("config", "./config/agent.json", "Path to agent config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadJSON[config.AgentConfig](*cfgPath)
	if err != nil {
		return err
	}

	ag, err := agent.New(cfg, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bootstrap.NewManager(logger).StartAutoInstall(ctx)

	if cfg.UIAddr != "" {
		go func() {
			if err := webui.Start(ctx, webui.Options{
				Addr:   cfg.UIAddr,
				Mode:   "agent",
				Agent:  ag,
				Logger: logger,
			}); err != nil {
				logger.Error("agent web ui error", "err", err)
			}
		}()
	}

	return ag.Run(ctx)
}

func runClient(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("config", "./config/client.json", "Path to client config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadJSON[config.ClientConfig](*cfgPath)
	if err != nil {
		return err
	}

	cl, err := client.New(cfg, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bootstrap.NewManager(logger).StartAutoInstall(ctx)

	if cfg.UIAddr != "" {
		go func() {
			if err := webui.Start(ctx, webui.Options{
				Addr:   cfg.UIAddr,
				Mode:   "client",
				Client: cl,
				Logger: logger,
			}); err != nil {
				logger.Error("client web ui error", "err", err)
			}
		}()
	}

	return cl.Run(ctx)
}

func runPeer(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("peer", flag.ExitOnError)
	cfgPath := fs.String("config", installer.DefaultConfigPath(), "Path to peer config JSON (auto-created on first run)")
	uiAddr := fs.String("ui", "", "Override local Web Dashboard address (e.g. 127.0.0.1:8080)")
	quicAddr := fs.String("quic", "", "Override QUIC UDP listen address (e.g. :4433)")
	wsAddr := fs.String("ws", "", "Override local WS peer listen address (e.g. :8444)")
	rdvURL := fs.String("rendezvous", "", "Optional Rendezvous Server URL for internet 9-digit ID lookup")
	openBrowser := fs.Bool("open", false, "Automatically open APN App Window")
	trayOnly := fs.Bool("tray", false, "Start silently in the System Tray (used for login auto-start)")
	trayIcon := fs.Bool("tray-icon", false, "Show APN System Tray icon (double-click to open, right-click to quit)")
	serviceWorker := fs.Bool("service-worker", false, "Run headless as elevated System Service console worker")
	waitOld := fs.Bool("wait-old", false, "Wait for previous APN instance to release UI port during self-update")
	waitPID := fs.Int("wait-pid", 0, "Previous APN PID to wait for (and terminate if stuck) during self-update")
	noAutoDeps := fs.Bool("no-auto-deps", false, "Disable automatic background install of FFmpeg/Wintun")
	connectTicket := fs.String("connect", "", "Optional RVPN1-... ticket or wss:// URL to connect on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *serviceWorker {
		_ = os.Setenv("APN_SERVICE_WORKER", "1")
		if binDir := service.SystemBinDir(); binDir != "" {
			_ = os.Setenv("APN_BIN_DIR", binDir)
		}
		*trayIcon = false
		*openBrowser = false
	}

	if *trayOnly || *serviceWorker {
		tray.HideConsoleWindow()
	}

	// A version that was just installed by self-update must prove it runs, or the previous one is
	// put back (see updater/rollback.go): supervised starts are counted, user mode runs a guard.
	if *serviceWorker || os.Getenv("APN_SYSTEMD_SERVICE") == "1" {
		if rolled, err := updater.CountSupervisedStart(appVersion); err != nil {
			logger.Warn("update start check failed", "err", err)
		} else if rolled {
			logger.Error("this update kept failing to start; restored the previous version", "version", appVersion)
			os.Exit(1) // the supervisor starts the restored binary
		}
	} else if handled, err := updater.RunUpdateGuard(appVersion, os.Args[1:]); handled {
		if err != nil {
			logger.Error("update guard", "err", err)
		}
		return nil
	}

	if *serviceWorker {
		// The System Service must own the device. A user-mode APN still holding the UI port
		// would otherwise make the service exit and restart in a loop, and every setting
		// changed there would be missing from the service config after the next reboot.
		takeOverUserModeInstance(logger)
		if merged := service.SyncNewerUserConfig(*cfgPath); len(merged) > 0 {
			logger.Info("merged newer user-mode settings into the service config", "from", merged, "config", *cfgPath)
		}
	}

	var cfg *config.PeerConfig
	if _, err := os.Stat(*cfgPath); errors.Is(err, os.ErrNotExist) {
		cfg, err = config.DefaultPeerConfig(filepath.Dir(*cfgPath))
		if err != nil {
			return err
		}
		if err := config.SaveJSON(*cfgPath, cfg, 0o600); err != nil {
			return err
		}
		logger.Info("created new APN P2P configuration", "path", *cfgPath, "device_id", p2p.FormatDeviceID(cfg.DeviceID))
	} else {
		cfg, err = config.LoadJSON[config.PeerConfig](*cfgPath)
		if err != nil {
			return err
		}
		// Keep cert/key anchored inside the persistent config folder after migration (and always in service mode)
		cfgDir := filepath.Dir(*cfgPath)
		if *serviceWorker || cfg.CertFile == "" {
			cfg.CertFile = filepath.Join(cfgDir, "peer.crt")
		} else if _, serr := os.Stat(cfg.CertFile); serr != nil {
			cfg.CertFile = filepath.Join(cfgDir, "peer.crt")
		}
		if *serviceWorker || cfg.KeyFile == "" {
			cfg.KeyFile = filepath.Join(cfgDir, "peer.key")
		} else if _, serr := os.Stat(cfg.KeyFile); serr != nil {
			cfg.KeyFile = filepath.Join(cfgDir, "peer.key")
		}
	}

	if *uiAddr != "" {
		cfg.UIAddr = *uiAddr
	}
	if *quicAddr != "" {
		cfg.QUICAddr = *quicAddr
	}
	if *wsAddr != "" {
		cfg.WSAddr = *wsAddr
	}
	if *rdvURL != "" {
		cfg.RendezvousURL = *rdvURL
	}

	// During self-update handoff (-wait-old / -wait-pid), ensure the exiting old process is
	// 100% gone and port 8080 is completely released BEFORE starting up (never two instances at once!).
	if *waitPID > 0 && *waitPID != os.Getpid() {
		waitForOldProcess(*waitPID, cfg.UIAddr)
	} else if *waitOld && cfg.UIAddr != "" {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) && isAlreadyRunning(cfg.UIAddr) {
			time.Sleep(120 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if *waitOld || *waitPID > 0 {
		updater.CleanupOldBinary()
	}

	// Single-instance check: verify whether an ACTUAL APN instance (not HiveMQ/Tomcat/other web app
	// sharing port 8080!) is already running on cfg.UIAddr or APN's fallback port range.
	if cfg.UIAddr != "" {
		// When starting as the authoritative OS System Service right after install/upgrade,
		// give a retiring user-mode instance up to 3.5s to hand off the local UI port cleanly.
		if *serviceWorker {
			handoffDeadline := time.Now().Add(3500 * time.Millisecond)
			for time.Now().Before(handoffDeadline) && findRunningAPNAddr(cfg.UIAddr) != "" {
				time.Sleep(150 * time.Millisecond)
			}
		}
		if existingAddr := findRunningAPNAddr(cfg.UIAddr); existingAddr != "" {
			if *openBrowser {
				tray.OpenAppWindow("http://" + existingAddr)
			}
			if !*serviceWorker {
				retireUserUnitIfServiceOwns()
			}
			return nil
		}
		// Ensure cfg.UIAddr is actually free to bind; if another app (e.g. HiveMQ on :8080) occupies it,
		// automatically pick a clean free port in APN's dedicated 18480-18499 range!
		resolvedAddr, err := resolveFreeUIAddr(cfg.UIAddr)
		if err != nil {
			return fmt.Errorf("failed to find free local UI port: %w", err)
		}
		if resolvedAddr != cfg.UIAddr {
			logger.Info("configured UI port is occupied by another app, switching APN UI port", "from", cfg.UIAddr, "to", resolvedAddr)
			cfg.UIAddr = resolvedAddr
		}
	}

	node, err := p2p.NewNode(cfg, logger)
	if err != nil {
		return err
	}
	node.SetConfigPath(*cfgPath)

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()
	node.SetOnQuit(cancel)

	if err := node.StartAsync(ctx); err != nil {
		return err
	}

	if !*noAutoDeps {
		node.StartAutoDeps(ctx)
	}

	snap := node.Snapshot()
	fmt.Println("====================================================")
	fmt.Printf("  APN Remote & VPN (v%s)\n", appVersion)
	fmt.Printf("  Your Device ID : %s\n", p2p.FormatDeviceID(snap.DeviceID))
	fmt.Printf("  Temporary PIN  : %s\n", snap.TempPIN)
	if cfg.UIAddr != "" {
		fmt.Printf("  Dashboard URL  : http://%s\n", cfg.UIAddr)
	}
	fmt.Println("====================================================")

	if *connectTicket != "" {
		go func() {
			info, err := node.ConnectByTicket(ctx, *connectTicket)
			if err != nil {
				logger.Warn("initial P2P connect failed", "err", err)
			} else {
				logger.Info("connected to P2P peer", "peer_id", info.ID, "transport", info.Transport)
			}
		}()
	}

	var stopTray func()
	if (*trayIcon || *trayOnly) && !*serviceWorker {
		uiURL := "http://" + cfg.UIAddr
		devID := snap.DeviceID
		devLabel := p2p.FormatDeviceID(devID)
		stopTray = tray.Start(tray.Callbacks{
			Tooltip:       "APN Remote & VPN — ID: " + devLabel,
			DeviceIDLabel: devLabel,
			OnOpen: func() {
				if cfg.UIAddr != "" {
					tray.OpenAppWindow(uiURL)
				}
			},
			OnCopyID: func() {
				copyToClipboard(devID)
			},
			IsPaused: func() bool {
				return node.Snapshot().Paused
			},
			OnTogglePause: func() {
				node.SetPaused(!node.Snapshot().Paused)
			},
			OnQuit: func() {
				cancel()
			},
		})
		defer stopTray()
	}

	if cfg.UIAddr != "" {
		popupURL := "http://" + cfg.UIAddr
		node.SetOnApprovalRequest(func(p2p.PendingApproval) {
			// Raise the open APN window (like AnyDesk); open one only if no page is showing.
			tray.PopupAppWindow(popupURL, !webui.ApprovalPageActive(4*time.Second))
		})
	}

	// Running this long means a just-installed update works: drop the kept previous version.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(updater.UpdateHealthyAfter):
			updater.ConfirmUpdate(appVersion)
		}
	}()

	var webDone chan struct{}
	if cfg.UIAddr != "" {
		webDone = make(chan struct{})
		go func() {
			defer close(webDone)
			if err := webui.Start(ctx, webui.Options{
				Addr:   cfg.UIAddr,
				Mode:   "peer",
				Peer:   node,
				Logger: logger,
			}); err != nil {
				logger.Error("peer web ui error", "err", err)
			}
		}()
		if *openBrowser {
			go func() {
				time.Sleep(400 * time.Millisecond)
				tray.OpenAppWindow("http://" + cfg.UIAddr)
			}()
		}
	}

	<-ctx.Done()
	if stopTray != nil {
		stopTray()
	}
	if webDone != nil {
		select {
		case <-webDone:
		case <-time.After(600 * time.Millisecond):
		}
	}
	return nil
}

func waitForOldProcess(pid int, uiAddr string) {
	// Wait up to 2.5s for graceful shutdown of the old process; if still alive, force-kill so
	// two APN instances NEVER run simultaneously after an update!
	gracefulDeadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(gracefulDeadline) {
		if uiAddr == "" || !isAlreadyRunning(uiAddr) {
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if p, err := os.FindProcess(pid); err == nil {
		// On Windows/Unix, if UI is still bound after graceful window, force-stop the old PID.
		if uiAddr != "" && isAlreadyRunning(uiAddr) {
			_ = p.Kill()
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && uiAddr != "" && isAlreadyRunning(uiAddr) {
		time.Sleep(120 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
}

func isAlreadyRunning(uiAddr string) bool {
	c := &http.Client{Timeout: 450 * time.Millisecond}
	resp, err := c.Get("http://" + uiAddr + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false
	}
	var payload struct {
		Mode    string `json:"mode"`
		Version string `json:"version"`
		Data    struct {
			DeviceID string `json:"device_id"`
			PeerID   string `json:"peer_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Mode == "peer" && payload.Version != "" && (payload.Data.DeviceID != "" || payload.Data.PeerID != "")
}

func apnCandidateUIAddrs(preferred string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		a = strings.TrimSpace(a)
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	add(preferred)
	for p := 18480; p <= 18499; p++ {
		add("127.0.0.1:" + strconv.Itoa(p))
	}
	return out
}

// retireUserUnitIfServiceOwns disables the per-user systemd unit (~/.config/systemd/user/apn.service)
// when the Linux System Service is running. Its Restart=always would otherwise relaunch this
// user-mode process every 3s forever, racing the service for the UI port.
func retireUserUnitIfServiceOwns() {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 || os.Getenv("APN_SYSTEMD_SERVICE") != "1" {
		return
	}
	if info := service.GetInfo(); !info.Installed || !info.Running {
		return
	}
	_ = exec.Command("systemctl", "--user", "disable", "--now", "apn.service").Start()
	time.Sleep(200 * time.Millisecond)
}

// takeOverUserModeInstance asks a running user-mode APN (if any) to quit so the System Service
// can bind the UI port and own the device ID, then waits up to 6s for it to exit.
func takeOverUserModeInstance(logger *slog.Logger) {
	addr := findRunningAPNAddr("127.0.0.1:18480")
	if addr == "" {
		return
	}
	logger.Info("asking user-mode APN to hand over to the System Service", "ui", addr)
	hc := &http.Client{Timeout: 3 * time.Second}
	if resp, err := hc.Post("http://"+addr+"/api/peer/quit", "application/json", strings.NewReader("{}")); err == nil {
		_ = resp.Body.Close()
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && isAlreadyRunning(addr) {
		time.Sleep(150 * time.Millisecond)
	}
	// Give the exiting process a moment to flush its peer.json before it is merged.
	time.Sleep(300 * time.Millisecond)
}

func findRunningAPNAddr(preferred string) string {
	for _, addr := range apnCandidateUIAddrs(preferred) {
		if isAlreadyRunning(addr) {
			return addr
		}
	}
	return ""
}

func resolveFreeUIAddr(preferred string) (string, error) {
	for _, addr := range apnCandidateUIAddrs(preferred) {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			actual := ln.Addr().String()
			_ = ln.Close()
			return actual, nil
		}
	}
	// Ultimate fallback: let OS assign an unused loopback port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	actual := ln.Addr().String()
	_ = ln.Close()
	return actual, nil
}

func copyToClipboard(text string) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "clip")
		executil.HideWindow(cmd)
		cmd.Stdin = strings.NewReader(text)
		_ = cmd.Run()
	}
}

func runToken() error {
	raw, err := security.GenerateToken(32)
	if err != nil {
		return err
	}
	fmt.Printf("Raw token (put in agent.json / client.json):\n  %s\n\n", raw)
	fmt.Printf("Hashed token (put in server.json token_hash):\n  %s\n", security.HashToken(raw))
	return nil
}

func runService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: APN service <install|uninstall|run|status>")
	}
	sub := strings.ToLower(args[0])
	rest := args[1:]
	switch sub {
	case "run":
		return service.RunSystemService()
	case "install":
		fs := flag.NewFlagSet("service install", flag.ExitOnError)
		migrateCfg := fs.String("migrate-cfg", installer.DefaultConfigPath(), "Existing peer.json to migrate into system config")
		migrateBin := fs.String("migrate-bin", bootstrap.BinDir(), "Existing helper bin dir to migrate")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		info, err := service.InstallSystemService(*migrateCfg, *migrateBin)
		if err != nil {
			return err
		}
		fmt.Printf("Installed APN System Service (%s) -> installed=%v running=%v\n", info.ServiceName, info.Installed, info.Running)
		return nil
	case "uninstall":
		if err := service.UninstallSystemService(); err != nil {
			return err
		}
		fmt.Println("Uninstalled APN System Service successfully.")
		return nil
	case "status":
		info := service.GetInfo()
		fmt.Printf("Service: %s | Supported: %v | Installed: %v | Running: %v | Binary: %s | Config: %s\n",
			info.ServiceName, info.Supported, info.Installed, info.Running, info.BinaryPath, info.ConfigPath)
		return nil
	default:
		return fmt.Errorf("unknown service command: %s (expected install, uninstall, run, status)", sub)
	}
}

func runSetPassword(args []string) error {
	defaultCfg := installer.DefaultConfigPath()
	if service.IsElevated() {
		if sysCfg := service.SystemConfigPath(); sysCfg != "" {
			if _, err := os.Stat(sysCfg); err == nil {
				defaultCfg = sysCfg
			}
		}
	}
	fs := flag.NewFlagSet("set-password", flag.ExitOnError)
	cfgPath := fs.String("config", defaultCfg, "Path to peer.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: apn set-password [-config /etc/apn/peer.json] <new-password>")
	}
	raw := strings.TrimSpace(fs.Arg(0))
	if len(raw) < 4 {
		return errors.New("รหัสผ่านถาวรต้องมีอย่างน้อย 4 ตัวอักษร")
	}

	var cfg *config.PeerConfig
	var err error
	if _, serr := os.Stat(*cfgPath); errors.Is(serr, os.ErrNotExist) {
		cfg, err = config.DefaultPeerConfig(filepath.Dir(*cfgPath))
		if err != nil {
			return err
		}
	} else {
		cfg, err = config.LoadJSON[config.PeerConfig](*cfgPath)
		if err != nil {
			return err
		}
	}
	hashed, err := security.HashPassword(raw)
	if err != nil {
		return err
	}
	cfg.PermanentPasswordHash = hashed
	if err := config.SaveJSON(*cfgPath, cfg, 0o600); err != nil {
		return err
	}
	fmt.Printf("Updated permanent password for Device ID %s (%s)\n", p2p.FormatDeviceID(cfg.DeviceID), *cfgPath)

	if runtime.GOOS == "linux" && service.IsElevated() && filepath.Clean(*cfgPath) == filepath.Clean(service.SystemConfigPath()) {
		if info := service.GetInfo(); info.Installed && info.Running {
			if err := exec.Command("systemctl", "restart", info.ServiceName).Run(); err == nil {
				fmt.Printf("Restarted %s to apply the new password.\n", info.ServiceName)
			}
		}
	}
	return nil
}

func runRdvServer(args []string, logger *slog.Logger) error {
	defaultSnap := "./rdv-snapshot.json"
	if runtime.GOOS == "linux" {
		defaultSnap = "/var/lib/apn/rdv-snapshot.json"
	}
	fs := flag.NewFlagSet("rdv-server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "HTTP listen address (use 0.0.0.0:8787 for Docker/LAN)")
	snapshot := fs.String("snapshot", defaultSnap, "Path to periodic disk snapshot JSON (empty disables)")
	ttl := fs.Duration("ttl", 5*time.Minute, "Peer online entry TTL before expiry")
	repo := fs.String("repo", "MYSitthichat/APN", "GitHub repo for /api/releases/latest")
	ratePerMin := fs.Int("rate-per-min", 600, "Requests per minute allowed per client IP (negative disables the limit)")
	rateBurst := fs.Int("rate-burst", 300, "Per-IP burst size")
	maxEntries := fs.Int("max-entries", 2_000_000, "Maximum online devices kept in RAM")
	accountsDir := fs.String("accounts-dir", "", "Directory for sign-in accounts and their encrypted address books (default: \"accounts\" next to the snapshot; \"off\" disables accounts)")
	accountSignup := fs.Bool("account-signup", true, "Let anyone create an account from the app")
	maxAccounts := fs.Int("max-accounts", 10_000, "Maximum number of accounts")
	// Mail settings for "forgot password". The password comes only from the environment
	// (APN_SMTP_PASSWORD) so it never shows up in the process list or a unit file.
	envInt := func(key string, def int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil {
			return n
		}
		return def
	}
	smtpHost := fs.String("smtp-host", os.Getenv("APN_SMTP_HOST"), "SMTP server for password-reset mail, e.g. smtp.gmail.com (env APN_SMTP_HOST)")
	smtpPort := fs.Int("smtp-port", envInt("APN_SMTP_PORT", 587), "SMTP port: 587 (STARTTLS) or 465 (TLS) (env APN_SMTP_PORT)")
	smtpUser := fs.String("smtp-user", os.Getenv("APN_SMTP_USER"), "SMTP sign-in name; the password is read from env APN_SMTP_PASSWORD (env APN_SMTP_USER)")
	smtpFrom := fs.String("smtp-from", os.Getenv("APN_SMTP_FROM"), "From address of reset mail; defaults to -smtp-user (env APN_SMTP_FROM)")
	smtpTest := fs.String("smtp-test", "", "Send a test mail to this address with the SMTP settings, then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	smtpCfg := rendezvous.SMTPConfig{
		Host:     strings.TrimSpace(*smtpHost),
		Port:     *smtpPort,
		Username: strings.TrimSpace(*smtpUser),
		Password: os.Getenv("APN_SMTP_PASSWORD"),
		From:     strings.TrimSpace(*smtpFrom),
	}
	if smtpCfg.From == "" {
		smtpCfg.From = smtpCfg.Username
	}
	if *smtpTest != "" {
		if err := rendezvous.SendTestMail(smtpCfg, *smtpTest); err != nil {
			return fmt.Errorf("test mail failed: %w", err)
		}
		fmt.Printf("Test mail sent to %s through %s:%d\n", *smtpTest, smtpCfg.Host, smtpCfg.Port)
		return nil
	}
	accDir := strings.TrimSpace(*accountsDir)
	switch {
	case strings.EqualFold(accDir, "off"):
		accDir = ""
	case accDir == "" && *snapshot != "":
		accDir = filepath.Join(filepath.Dir(*snapshot), "accounts")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := rendezvous.NewServer(rendezvous.Options{
		ListenAddr:   *listen,
		SnapshotPath: *snapshot,
		TTL:          *ttl,
		GitHubRepo:   *repo,
		Logger:       logger,
		RatePerMin:   *ratePerMin,
		RateBurst:    *rateBurst,
		MaxEntries:   *maxEntries,

		AccountsDir:   accDir,
		AccountSignup: *accountSignup,
		MaxAccounts:   *maxAccounts,
		SMTP:          smtpCfg,
	})
	return srv.Run(ctx)
}

func printUsage() {
	fmt.Println(`APN — Cross-Platform 60 FPS P2P Remote Desktop & Encrypted L3 VPN

Usage:
  APN peer         [-open] [-tray] [-tray-icon] [-ui 127.0.0.1:18480]
  APN rdv-server   [-listen 127.0.0.1:8787] [-snapshot /var/lib/apn/rdv-snapshot.json]
  APN service      <install|uninstall|run|status>  Install/manage OS System Service (runs before login)
  APN set-password <new-password>                  Set permanent password for this device (and restart service)
  APN install      Install APN with Desktop/Start Menu shortcuts & Login Auto-Start
  APN uninstall    Remove APN installation, shortcuts, and Auto-Start
  APN server       -config ./config/server.json
  APN agent        -config ./config/agent.json
  APN client       -config ./config/client.json
  APN version`)
}
