package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
	"relayvpn/internal/security"
	"relayvpn/internal/server"
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
	waitOld := fs.Bool("wait-old", false, "Wait for previous APN instance to release UI port during self-update")
	noAutoDeps := fs.Bool("no-auto-deps", false, "Disable automatic background install of FFmpeg/Wintun")
	connectTicket := fs.String("connect", "", "Optional RVPN1-... ticket or wss:// URL to connect on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *trayOnly {
		tray.HideConsoleWindow()
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
		// Keep cert/key anchored inside the persistent config folder after migration
		cfgDir := filepath.Dir(*cfgPath)
		if cfg.CertFile == "" {
			cfg.CertFile = filepath.Join(cfgDir, "peer.crt")
		} else if _, serr := os.Stat(cfg.CertFile); serr != nil {
			cfg.CertFile = filepath.Join(cfgDir, "peer.crt")
		}
		if cfg.KeyFile == "" {
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

	// During self-update handoff (-wait-old), wait up to 8s for the exiting old process to release UIAddr
	// so the new version ALWAYS binds cleanly on the first try and never exits prematurely!
	if *waitOld && cfg.UIAddr != "" {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) && isAlreadyRunning(cfg.UIAddr) {
			time.Sleep(150 * time.Millisecond)
		}
		time.Sleep(250 * time.Millisecond)
		updater.CleanupOldBinary()
	}

	// Single-instance check: if APN is already running in the System Tray on UIAddr,
	// simply bring up the APN App Window and exit cleanly instead of binding twice!
	if cfg.UIAddr != "" && isAlreadyRunning(cfg.UIAddr) {
		if *openBrowser {
			tray.OpenAppWindow("http://" + cfg.UIAddr)
		}
		return nil
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
	if *trayIcon || *trayOnly {
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
		go func() {
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
	return nil
}

func isAlreadyRunning(uiAddr string) bool {
	c := &http.Client{Timeout: 450 * time.Millisecond}
	resp, err := c.Get("http://" + uiAddr + "/api/status")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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

func printUsage() {
	fmt.Println(`APN — Cross-Platform 60 FPS P2P Remote Desktop & Encrypted L3 VPN

Usage:
  APN peer      [-open] [-tray] [-tray-icon] [-ui 127.0.0.1:8080]
  APN install   Install APN with Desktop/Start Menu shortcuts & Login Auto-Start
  APN uninstall Remove APN installation, shortcuts, and Auto-Start
  APN server    -config ./config/server.json
  APN agent     -config ./config/agent.json
  APN client    -config ./config/client.json
  APN version`)
}
