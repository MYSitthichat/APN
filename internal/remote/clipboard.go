package remote

import (
	"io"

	"relayvpn/internal/protocol"
)

// ClipboardRequest is sent over a ModeClipboard stream ("get" or "set").
type ClipboardRequest struct {
	Action    string `json:"action"`               // "get" or "set"
	Kind      byte   `json:"kind,omitempty"`       // 0=text, 1=png
	AutoPaste bool   `json:"auto_paste,omitempty"` // for "set": trigger Ctrl+V after setting clipboard
	Size      int64  `json:"size,omitempty"`       // payload byte length for "set"
}

// ClipboardResponse is returned on a ModeClipboard stream (followed by Size raw bytes on "get").
type ClipboardResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Kind  byte   `json:"kind,omitempty"` // 0=text, 1=png
	Size  int64  `json:"size,omitempty"`
}

const maxClipboardBytes = 16 * 1024 * 1024 // 16 MiB max screenshot

// ServeClipboardStream serves one bidirectional native OS clipboard operation ("get" or "set").
func ServeClipboardStream(stream io.ReadWriteCloser) error {
	defer stream.Close()

	var req ClipboardRequest
	if err := protocol.ReadMessage(stream, &req); err != nil {
		return err
	}

	switch req.Action {
	case "get":
		kind, data, err := ReadClipboard()
		if err != nil {
			return protocol.WriteMessage(stream, ClipboardResponse{OK: false, Error: err.Error()})
		}
		if len(data) > maxClipboardBytes {
			return protocol.WriteMessage(stream, ClipboardResponse{OK: false, Error: "ขนาดรูปในคลิปบอร์ดใหญ่เกิน 16 MB"})
		}
		if err := protocol.WriteMessage(stream, ClipboardResponse{
			OK:   true,
			Kind: kind,
			Size: int64(len(data)),
		}); err != nil {
			return err
		}
		if len(data) > 0 {
			_, err = stream.Write(data)
			return err
		}
		return nil

	case "set":
		if req.Size <= 0 || req.Size > maxClipboardBytes {
			return protocol.WriteMessage(stream, ClipboardResponse{OK: false, Error: "ขนาดข้อมูลคลิปบอร์ดไม่ถูกต้อง"})
		}
		if err := protocol.WriteMessage(stream, ClipboardResponse{OK: true}); err != nil {
			return err
		}
		data := make([]byte, req.Size)
		if _, err := io.ReadFull(stream, data); err != nil {
			return err
		}
		kind := req.Kind
		if req.AutoPaste {
			if kind == 1 {
				kind = 3
			} else {
				kind = 2
			}
		}
		if err := ApplyClipboardPayload(kind, data); err != nil {
			return protocol.WriteMessage(stream, ClipboardResponse{OK: false, Error: err.Error()})
		}
		return protocol.WriteMessage(stream, ClipboardResponse{OK: true, Kind: req.Kind, Size: req.Size})

	default:
		return protocol.WriteMessage(stream, ClipboardResponse{OK: false, Error: "unsupported clipboard action"})
	}
}
