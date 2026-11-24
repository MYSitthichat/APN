package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// pinnedDownload is one exact upstream file: an immutable URL and the SHA-256 it must have.
type pinnedDownload struct {
	URL    string
	SHA256 string
}

// verifyFileSHA256 checks a downloaded file against the pinned hash before it is extracted or
// installed. An empty want is refused: every bootstrap download must be pinned.
func verifyFileSHA256(path, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if len(want) != 64 {
		return fmt.Errorf("ไม่มีค่า SHA-256 ที่กำหนดไว้สำหรับ %s — ไม่ติดตั้ง", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("ไฟล์ที่ดาวน์โหลดไม่ตรงกับ SHA-256 ที่กำหนด (ได้ %s…) — ไม่ติดตั้ง", got[:16])
	}
	return nil
}
