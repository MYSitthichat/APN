package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const (
	// HeaderRole identifies the peer role during WebSocket upgrade.
	HeaderRole = "X-RelayVPN-Role"
	// HeaderPeerID identifies the agent or client ID during WebSocket upgrade.
	HeaderPeerID = "X-RelayVPN-ID"
	// HeaderPeerName provides a human-friendly display name.
	HeaderPeerName = "X-RelayVPN-Name"
	// HeaderPeerOS provides runtime OS/Arch metadata.
	HeaderPeerOS = "X-RelayVPN-OS"

	RoleAgent  = "agent"
	RoleClient = "client"

	// Stream modes
	ModeTCP     = "tcp"
	ModeControl = "control"
	ModeScreen  = "screen"
	ModeShell   = "shell"
	ModeTUN       = "tun"
	ModeFiles     = "files"
	ModeClipboard = "clipboard"

	// Typed binary frame tags used inside ModeScreen streams.
	FrameTypeJPEG      byte = 0x01 // Agent -> Client: [w:u16][h:u16][jpeg bytes] (legacy full frame)
	FrameTypeInput     byte = 0x02 // Client -> Agent: JSON InputEvent / ACK / Config
	FrameTypeError     byte = 0x03 // Agent -> Client: UTF-8 error text
	FrameTypeTileBatch byte = 0x04 // Agent -> Client: [seq:u32][w:u16][h:u16][count:u16] + tiles
	FrameTypeH264      byte = 0x05 // Agent -> Client: [seq:u32][w:u16][h:u16][flags:u8][annex-b h264]
	FrameTypeInfo      byte = 0x06 // Agent -> Client: UTF-8 JSON info/notice
	FrameTypeClipboard byte = 0x07 // Client -> Agent: [kind:u8 (0=text,1=png,2=text+paste,3=png+paste)][data]
	FrameTypeHEVC      byte = 0x08 // Agent -> Client: [seq:u32][w:u16][h:u16][flags:u8][annex-b hevc/h265]
	// FrameTypeClipboardChanged (Agent -> Client, empty payload) tells the viewer that the host's
	// clipboard changed (e.g. copied with right-click -> Copy), so it can pull it. Older viewers
	// and bridges ignore unknown frame types.
	FrameTypeClipboardChanged byte = 0x09

	maxControlFrameBytes = 64 * 1024
	maxBinaryFrameBytes  = 16 * 1024 * 1024 // 16 MiB max for lossless 4K initial frame
)

// StreamOpenRequest is sent as the first length-prefixed JSON frame on every new Yamux stream.
type StreamOpenRequest struct {
	Mode         string             `json:"mode"`                   // "tcp", "control", "screen", "shell", "tun"
	Action       string             `json:"action,omitempty"`       // for ModeControl: "list_agents", "register_targets"
	AgentID      string             `json:"agent_id,omitempty"`     // target agent ID (client -> server)
	TargetAddr   string             `json:"target_addr,omitempty"`  // target host:port on agent (e.g. "127.0.0.1:3389")
	ClientID     string             `json:"client_id,omitempty"`    // originating client ID (server -> agent)
	Targets      []TargetInfo       `json:"targets,omitempty"`      // agent -> server target advertisement
	Capabilities *AgentCapabilities `json:"capabilities,omitempty"` // agent -> server remote capability advertisement
	FPS          int                `json:"fps,omitempty"`          // initial target FPS (default 24)
	Quality      int                `json:"quality,omitempty"`      // initial JPEG quality (default 82)
	Codec        string             `json:"codec,omitempty"`        // "tiles" (default), "png", "h264"
	MaxWidth     int                `json:"max_width,omitempty"`    // 0 = Native 100%, or 1920/1280
}

// AgentCapabilities declares which built-in remote features the Agent owner has enabled.
type AgentCapabilities struct {
	AllowScreen bool `json:"allow_screen"`
	AllowInput  bool `json:"allow_input"`
	AllowShell  bool `json:"allow_shell"`
	AllowFiles  bool `json:"allow_files,omitempty"`
	HasFFmpeg   bool `json:"has_ffmpeg,omitempty"`
}

// StreamOpenResponse is returned immediately before switching the stream to payload traffic.
type StreamOpenResponse struct {
	OK           bool        `json:"ok"`
	Error        string      `json:"error,omitempty"`
	Agents       []AgentInfo `json:"agents,omitempty"`
	ScreenWidth  int         `json:"screen_width,omitempty"`
	ScreenHeight int         `json:"screen_height,omitempty"`
	AllowInput   bool        `json:"allow_input,omitempty"`
}

// TargetInfo describes an explicitly allowed TCP target service on an Agent.
type TargetInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// AgentInfo describes an online Agent visible to authorized Clients.
type AgentInfo struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	OS           string            `json:"os"`
	RemoteAddr   string            `json:"remote_addr,omitempty"`
	ConnectedAt  time.Time         `json:"connected_at"`
	Targets      []TargetInfo      `json:"targets"`
	Capabilities AgentCapabilities `json:"capabilities"`
	ActiveConns  int               `json:"active_conns"`
}

// WriteMessage writes a length-prefixed JSON frame to w without over-writing.
func WriteMessage(w io.Writer, msg any) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(payload) > maxControlFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", len(payload))
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

// ReadMessage reads an exact length-prefixed JSON frame from r without reading past the frame boundary.
func ReadMessage(r io.Reader, dst any) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > maxControlFrameBytes {
		return fmt.Errorf("invalid frame size: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("unmarshal frame: %w", err)
	}
	return nil
}

// WriteTypedFrame writes a 1-byte type tag + 4-byte length + payload in a SINGLE write call
// (eliminates extra Yamux/WebSocket/TCP frames and Delayed-ACK stalls at 60 FPS).
func WriteTypedFrame(w io.Writer, frameType byte, payload []byte) error {
	if len(payload) > maxBinaryFrameBytes {
		return fmt.Errorf("binary frame too large: %d", len(payload))
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	if len(payload) > 0 {
		copy(frame[5:], payload)
	}
	_, err := w.Write(frame)
	return err
}

// ReadTypedFrame reads a 1-byte type tag + 4-byte length + payload frame.
func ReadTypedFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(hdr[1:])
	if size > maxBinaryFrameBytes {
		return 0, nil, fmt.Errorf("binary frame too large: %d", size)
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}
