//go:build windows

package webui

import (
	"encoding/binary"
	"testing"
)

func TestFindOwnerPID(t *testing.T) {
	row := func(lport, rport uint16, pid uint32) []byte {
		b := make([]byte, 24)
		binary.LittleEndian.PutUint32(b[0:], 5)
		binary.LittleEndian.PutUint32(b[4:], 0x0100007F)
		binary.LittleEndian.PutUint32(b[8:], uint32(lport>>8|lport<<8)) // network byte order
		binary.LittleEndian.PutUint32(b[12:], 0x0100007F)
		binary.LittleEndian.PutUint32(b[16:], uint32(rport>>8|rport<<8))
		binary.LittleEndian.PutUint32(b[20:], pid)
		return b
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 2)
	buf = append(buf, row(18480, 50000, 111)...) // server side
	buf = append(buf, row(50000, 18480, 222)...) // client side
	if pid, ok := findOwnerPID(buf, 50000, 18480); !ok || pid != 222 {
		t.Fatalf("got pid=%d ok=%v, want 222", pid, ok)
	}
	if _, ok := findOwnerPID(buf, 50001, 18480); ok {
		t.Fatal("found a non-existent connection")
	}
}
