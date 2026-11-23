package vpn

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// DefaultMTU is 1200 so every L3 IPv4 packet fits cleanly inside a single RFC 9221 QUIC Datagram
	// even over nested tunnels, PPPoE, or 4G/5G without fragmentation or DatagramTooLargeError.
	DefaultMTU       = 1200
	maxIPPacketBytes = 65535
)

// DeriveVPNIP deterministically assigns a private Virtual LAN IP in 10.99.x.y/16 from a DeviceID.
// Avoids .0 and .255 host octets so every peer gets a valid routable unicast address.
func DeriveVPNIP(deviceID string) string {
	sum := sha256.Sum256([]byte("relayvpn-ip:" + deviceID))
	o3 := int(sum[0])%250 + 1 // 1..250
	o4 := int(sum[1])%250 + 2 // 2..251
	return fmt.Sprintf("10.99.%d.%d", o3, o4)
}

// ExtractIPv4Dst returns the destination IPv4 address string from a raw IP packet, if IPv4.
func ExtractIPv4Dst(pkt []byte) (string, bool) {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return "", false
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).String(), true
}

// WriteIPPacket writes a 2-byte big-endian length-prefixed raw IP packet to a ModeTUN stream.
func WriteIPPacket(w io.Writer, pkt []byte) error {
	if len(pkt) == 0 || len(pkt) > maxIPPacketBytes {
		return fmt.Errorf("invalid IP packet length: %d", len(pkt))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(pkt)
	return err
}

// ReadIPPacket reads one length-prefixed raw IP packet from a ModeTUN stream into dstBuf (reused).
func ReadIPPacket(r io.Reader, dstBuf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:]))
	if size == 0 || size > maxIPPacketBytes {
		return nil, fmt.Errorf("invalid IP packet frame size: %d", size)
	}
	if cap(dstBuf) < size {
		dstBuf = make([]byte, size)
	}
	pkt := dstBuf[:size]
	if _, err := io.ReadFull(r, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}
