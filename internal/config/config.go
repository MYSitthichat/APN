package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"relayvpn/internal/security"
)

// ServerConfig configures the HTTPS/WSS 443 Relay Server.
type ServerConfig struct {
	ListenAddr      string       `json:"listen_addr"`       // e.g. ":443" or "0.0.0.0:8443"
	AdminUIAddr     string       `json:"admin_ui_addr"`     // e.g. "127.0.0.1:8082" (local dashboard, optional)
	EnableWebPortal bool         `json:"enable_web_portal"` // if true, serves authenticated Web Remote Portal on HTTPS 443
	CertFile        string       `json:"cert_file"`
	KeyFile         string       `json:"key_file"`
	Agents          []AgentAuth  `json:"agents"`
	Clients         []ClientAuth `json:"clients"`
}

// AgentAuth registers an authorized remote host agent.
type AgentAuth struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TokenHash   string `json:"token_hash"` // "sha256:<hex>"
}

// ClientAuth registers an authorized user/viewer client.
type ClientAuth struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	TokenHash     string   `json:"token_hash"`     // "sha256:<hex>"
	AllowedAgents []string `json:"allowed_agents"` // ["*"] or explicit agent IDs
}

// AgentConfig configures the remote host agent (runs on the machine you want to access).
type AgentConfig struct {
	AgentID        string          `json:"agent_id"`
	Name           string          `json:"name"`
	ServerURL      string          `json:"server_url"` // e.g. "wss://vpn.example.com:443/ws/tunnel"
	Token          string          `json:"token"`
	CAFile         string          `json:"ca_file,omitempty"`
	ServerName     string          `json:"server_name,omitempty"`
	UIAddr         string          `json:"ui_addr"`         // e.g. "127.0.0.1:8081"
	AllowScreen    bool            `json:"allow_screen"`    // permit live remote screen viewing
	AllowInput     bool            `json:"allow_input"`     // permit remote mouse & keyboard control
	AllowShell     bool            `json:"allow_shell"`     // permit interactive remote terminal
	AllowedTargets []AllowedTarget `json:"allowed_targets"` // strict local TCP allowlist
}

// AllowedTarget defines a service explicitly permitted for remote access on the Agent.
type AllowedTarget struct {
	Name    string `json:"name"`    // e.g. "RDP", "SSH", "VNC"
	Address string `json:"address"` // e.g. "127.0.0.1:3389"
}

// ClientConfig configures the controller/viewer client.
type ClientConfig struct {
	ClientID   string        `json:"client_id"`
	ServerURL  string        `json:"server_url"` // e.g. "wss://vpn.example.com:443/ws/tunnel"
	Token      string        `json:"token"`
	CAFile     string        `json:"ca_file,omitempty"`
	ServerName string        `json:"server_name,omitempty"`
	UIAddr     string        `json:"ui_addr"` // e.g. "127.0.0.1:8080"
	Tunnels    []TunnelRule  `json:"tunnels"`
}

// TunnelRule binds a local TCP port on the client to an allowed target on a remote Agent.
type TunnelRule struct {
	Name       string `json:"name"`        // e.g. "Home PC RDP"
	LocalAddr  string `json:"local_addr"`  // e.g. "127.0.0.1:13389"
	AgentID    string `json:"agent_id"`    // e.g. "home-pc"
	TargetAddr string `json:"target_addr"` // e.g. "127.0.0.1:3389"
	Enabled    bool   `json:"enabled"`
}

// PeerConfig configures a serverless P2P node that acts simultaneously as BOTH Host and Client.
type PeerConfig struct {
	DeviceID              string          `json:"device_id"`                          // 9-digit AnyDesk/RustDesk-style ID (e.g. "482917305")
	PeerID                string          `json:"peer_id"`                            // internal hostname/slug
	Name                  string          `json:"name"`
	PairSecret            string          `json:"pair_secret"`                        // legacy ticket secret
	PermanentPasswordHash string          `json:"permanent_password_hash,omitempty"`  // salted SHA-256 hash of user-set permanent password
	RequireApproval       bool            `json:"require_approval"`                   // prompt owner on dashboard before accepting peer
	RendezvousURL         string          `json:"rendezvous_url,omitempty"`           // optional Rendezvous directory URL for internet 9-digit ID lookup
	QUICAddr              string          `json:"quic_addr"`                          // UDP listen addr for QUIC P2P + STUN (e.g. ":4433")
	WSAddr                string          `json:"ws_addr"`                            // HTTP/WS peer listener (e.g. ":8444", can expose via cloudflared)
	PublicWSURL           string          `json:"public_ws_url,omitempty"`            // optional external wss:// URL (e.g. trycloudflare.com/ws/peer)
	UIAddr                string          `json:"ui_addr"`                            // local Web Dashboard (e.g. "127.0.0.1:8080")
	CertFile              string          `json:"cert_file"`
	KeyFile               string          `json:"key_file"`
	STUNServers           []string        `json:"stun_servers,omitempty"`
	EnableLANDisc         bool            `json:"enable_lan_discovery"`
	AllowScreen           bool            `json:"allow_screen"`
	AllowInput            bool            `json:"allow_input"`
	AllowShell            bool            `json:"allow_shell"`
	// AllowReverseAccess lets a device that THIS machine connected to open screen, shell, files,
	// clipboard or TCP tunnels back on this machine. Off by default: otherwise connecting to a
	// stranger's ID (e.g. a fake "support" request) handed them full control of this computer
	// without knowing its password.
	AllowReverseAccess bool `json:"allow_reverse_access,omitempty"`
	EnableVPN             bool            `json:"enable_vpn"`
	EnableBridge          bool            `json:"enable_bridge"`      // auto-start zero-VPS Port 443 Internet Bridge (cloudflared)
	VPNIP                 string          `json:"vpn_ip,omitempty"`   // auto-derived 10.99.x.y if empty
	AllowedTargets        []AllowedTarget `json:"allowed_targets"`
	KnownPeers            []KnownPeer     `json:"known_peers,omitempty"` // remembered peers for fast 9-digit reconnect
}

// KnownPeer remembers a previously connected peer for Saved History, live online status, and 1-click reconnect.
type KnownPeer struct {
	DeviceID      string `json:"device_id"`
	Name          string `json:"name,omitempty"`
	OS            string `json:"os,omitempty"`
	VPNIP         string `json:"vpn_ip,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	QUICAddr      string `json:"quic_addr,omitempty"`
	WSURL         string `json:"ws_url,omitempty"`
	SavedPassword string `json:"saved_password,omitempty"` // stored only in local 0600 peer.json; never exposed in API snapshots
	LastConnected string `json:"last_connected,omitempty"` // RFC3339 timestamp
	// CustomName is true when the user renamed this peer; reconnects then keep Name instead of
	// replacing it with the remote machine's hostname.
	CustomName bool `json:"custom_name,omitempty"`
}

// DefaultRendezvousURL can be embedded at build time via:
//   -ldflags "-X relayvpn/internal/config.DefaultRendezvousURL=https://relayvpn-rdv.you.workers.dev"
// so every machine connects across the Internet using ONLY the 9-digit ID + PIN (zero setup!).
var DefaultRendezvousURL = ""

// DefaultPeerConfig creates a ready-to-run serverless P2P configuration saved in dir.
func DefaultPeerConfig(dir string) (*PeerConfig, error) {
	devID, err := security.GenerateDigits(9, true)
	if err != nil {
		return nil, err
	}
	secret, err := security.GenerateToken(18)
	if err != nil {
		return nil, err
	}
	hostName, _ := os.Hostname()
	if hostName == "" {
		hostName = "peer-node"
	}
	peerID := sanitizeID(hostName)
	targets := []AllowedTarget{
		{Name: "SSH", Address: "127.0.0.1:22"},
		{Name: "VNC", Address: "127.0.0.1:5900"},
	}
	if runtime.GOOS == "windows" {
		targets = append([]AllowedTarget{{Name: "Windows RDP", Address: "127.0.0.1:3389"}}, targets...)
	}
	return &PeerConfig{
		DeviceID:       devID,
		PeerID:         peerID,
		Name:           hostName,
		PairSecret:     secret,
		RendezvousURL:  DefaultRendezvousURL,
		QUICAddr:       ":4433",
		WSAddr:         ":8444",
		UIAddr:         "127.0.0.1:18480",
		CertFile:       filepath.Join(dir, "peer.crt"),
		KeyFile:        filepath.Join(dir, "peer.key"),
		EnableLANDisc:  true,
		EnableBridge:   true,
		AllowScreen:    true,
		AllowInput:     true,
		AllowShell:     true,
		AllowedTargets: targets,
	}, nil
}

// LoadJSON reads a JSON config file into dst.
func LoadJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &out, nil
}

// SaveJSON writes a JSON config file with indented formatting.
func SaveJSON(path string, v any, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, perm)
}

// InitBundleResult summarizes generated starter configuration files.
type InitBundleResult struct {
	Dir        string
	ServerFile string
	AgentFile  string
	ClientFile string
	CACert     string
	ServerCert string
	ServerKey  string
	AgentToken string
	ClientToken string
}

// InitBundle creates a ready-to-run starter configuration with TLS 1.3 certs and hashed tokens.
func InitBundle(outDir, serverHost string, listenPort int) (*InitBundleResult, error) {
	if serverHost == "" {
		serverHost = "localhost"
	}
	if listenPort <= 0 {
		listenPort = 443
	}

	certDir := filepath.Join(outDir, "certs")
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if serverHost != "localhost" && serverHost != "127.0.0.1" {
		hosts = append(hosts, serverHost)
	}

	caCert, srvCert, srvKey, err := security.GenerateDevPKI(certDir, hosts)
	if err != nil {
		return nil, err
	}

	agentToken, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	clientToken, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}

	hostName, _ := os.Hostname()
	if hostName == "" {
		hostName = "my-device"
	}
	agentID := sanitizeID(hostName)

	listenAddr := fmt.Sprintf(":%d", listenPort)
	serverURL := fmt.Sprintf("wss://%s:%d/ws/tunnel", serverHost, listenPort)

	defaultTargets := []AllowedTarget{
		{Name: "SSH", Address: "127.0.0.1:22"},
		{Name: "VNC", Address: "127.0.0.1:5900"},
	}
	if runtime.GOOS == "windows" {
		defaultTargets = append([]AllowedTarget{{Name: "Windows RDP", Address: "127.0.0.1:3389"}}, defaultTargets...)
	}

	srvCfg := &ServerConfig{
		ListenAddr:      listenAddr,
		AdminUIAddr:     "127.0.0.1:8082",
		EnableWebPortal: true,
		CertFile:        srvCert,
		KeyFile:         srvKey,
		Agents: []AgentAuth{
			{
				ID:        agentID,
				Name:      hostName,
				TokenHash: security.HashToken(agentToken),
			},
		},
		Clients: []ClientAuth{
			{
				ID:            "admin-client",
				Name:          "Primary Device",
				TokenHash:     security.HashToken(clientToken),
				AllowedAgents: []string{"*"},
			},
		},
	}

	agentCfg := &AgentConfig{
		AgentID:        agentID,
		Name:           hostName,
		ServerURL:      serverURL,
		Token:          agentToken,
		CAFile:         caCert,
		ServerName:     serverHost,
		UIAddr:         "127.0.0.1:8081",
		AllowScreen:    true,
		AllowInput:     true,
		AllowShell:     true,
		AllowedTargets: defaultTargets,
	}

	clientCfg := &ClientConfig{
		ClientID:   "admin-client",
		ServerURL:  serverURL,
		Token:      clientToken,
		CAFile:     caCert,
		ServerName: serverHost,
		UIAddr:     "127.0.0.1:8080",
		Tunnels: []TunnelRule{
			{
				Name:       "Remote Desktop (RDP)",
				LocalAddr:  "127.0.0.1:13389",
				AgentID:    agentID,
				TargetAddr: "127.0.0.1:3389",
				Enabled:    false,
			},
			{
				Name:       "SSH Tunnel",
				LocalAddr:  "127.0.0.1:2222",
				AgentID:    agentID,
				TargetAddr: "127.0.0.1:22",
				Enabled:    false,
			},
		},
	}

	serverFile := filepath.Join(outDir, "server.json")
	agentFile := filepath.Join(outDir, "agent.json")
	clientFile := filepath.Join(outDir, "client.json")

	if err := SaveJSON(serverFile, srvCfg, 0o600); err != nil {
		return nil, err
	}
	if err := SaveJSON(agentFile, agentCfg, 0o600); err != nil {
		return nil, err
	}
	if err := SaveJSON(clientFile, clientCfg, 0o600); err != nil {
		return nil, err
	}

	return &InitBundleResult{
		Dir:         outDir,
		ServerFile:  serverFile,
		AgentFile:   agentFile,
		ClientFile:  clientFile,
		CACert:      caCert,
		ServerCert:  srvCert,
		ServerKey:   srvKey,
		AgentToken:  agentToken,
		ClientToken: clientToken,
	}, nil
}

func sanitizeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' || r == '.' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "agent-1"
	}
	return out
}
