package remote

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildFLVTag(tagType byte, payload []byte) []byte {
	var buf bytes.Buffer
	size := len(payload)
	buf.WriteByte(tagType)
	buf.WriteByte(byte(size >> 16))
	buf.WriteByte(byte(size >> 8))
	buf.WriteByte(byte(size))
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0}) // timestamp + streamID
	buf.Write(payload)
	var prev [4]byte
	binary.BigEndian.PutUint32(prev[:], uint32(11+size))
	buf.Write(prev[:])
	return buf.Bytes()
}

func TestFLVH264ReaderZeroDelay(t *testing.T) {
	var flv bytes.Buffer
	flv.Write([]byte{'F', 'L', 'V', 0x01, 0x01, 0, 0, 0, 9, 0, 0, 0, 0})

	// 1. AVC Sequence Header (SPS + PPS)
	sps := []byte{0x67, 0x42, 0xE0, 0x28}
	pps := []byte{0x68, 0xCE, 0x38, 0x80}
	var avcCfg bytes.Buffer
	avcCfg.Write([]byte{0x17, 0x00, 0x00, 0x00, 0x00}) // keyframe+AVC, packetType=0, CTS=0
	avcCfg.Write([]byte{1, 0x42, 0xE0, 0x28, 0xFF, 0xE1})
	binary.Write(&avcCfg, binary.BigEndian, uint16(len(sps)))
	avcCfg.Write(sps)
	avcCfg.WriteByte(1)
	binary.Write(&avcCfg, binary.BigEndian, uint16(len(pps)))
	avcCfg.Write(pps)
	flv.Write(buildFLVTag(9, avcCfg.Bytes()))

	// 2. IDR Keyframe (AVCC length-prefixed)
	idr := []byte{0x65, 0x88, 0x84, 0x21}
	var kf bytes.Buffer
	kf.Write([]byte{0x17, 0x01, 0x00, 0x00, 0x00})
	binary.Write(&kf, binary.BigEndian, uint32(len(idr)))
	kf.Write(idr)
	flv.Write(buildFLVTag(9, kf.Bytes()))

	// 3. Delta P-frame
	delta := []byte{0x41, 0x9A, 0x11, 0x22}
	var pf bytes.Buffer
	pf.Write([]byte{0x27, 0x01, 0x00, 0x00, 0x00})
	binary.Write(&pf, binary.BigEndian, uint32(len(delta)))
	pf.Write(delta)
	flv.Write(buildFLVTag(9, pf.Bytes()))

	r := newFLVH264Reader(&flv)

	au1, isKey1, err := r.NextAccessUnit()
	if err != nil {
		t.Fatalf("read keyframe: %v", err)
	}
	if !isKey1 {
		t.Fatalf("expected keyframe=true")
	}
	want1 := []byte{
		0, 0, 0, 1, 0x67, 0x42, 0xE0, 0x28,
		0, 0, 0, 1, 0x68, 0xCE, 0x38, 0x80,
		0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21,
	}
	if !bytes.Equal(au1, want1) {
		t.Fatalf("keyframe mismatch: got %x want %x", au1, want1)
	}

	au2, isKey2, err := r.NextAccessUnit()
	if err != nil {
		t.Fatalf("read delta frame: %v", err)
	}
	if isKey2 {
		t.Fatalf("expected keyframe=false")
	}
	want2 := []byte{0, 0, 0, 1, 0x41, 0x9A, 0x11, 0x22}
	if !bytes.Equal(au2, want2) {
		t.Fatalf("delta mismatch: got %x want %x", au2, want2)
	}
}

func TestH264CandidatesSanity(t *testing.T) {
	cands := h264EncoderCandidates(60, 1920, 1080, 1920, 1080, 82)
	if len(cands) == 0 {
		t.Fatalf("expected non-empty encoder candidates")
	}
	for _, c := range cands {
		joined := ""
		for _, a := range c.args {
			joined += a + " "
		}
		if bytes.Contains([]byte(joined), []byte("scale_d3d11")) {
			t.Errorf("candidate %q should not use broken scale_d3d11 filter", c.name)
		}
		if bytes.Contains([]byte(joined), []byte("gdigrab")) && bytes.Contains([]byte(joined), []byte("-probesize 32")) {
			t.Errorf("gdigrab candidate %q must not pass -probesize 32 (BMP header is 54 bytes)", c.name)
		}
		if bytes.Contains([]byte(joined), []byte("annexb=1")) {
			t.Errorf("FLV candidate %q must not force annexb=1 in x264-params", c.name)
		}
	}
	if !isDDACaptureFailure("[Parsed_ddagrab_0] Desktop duplication access denied") {
		t.Errorf("expected Desktop duplication error to trigger DDA skip")
	}
	if !isDDACaptureFailure("[Parsed_ddagrab_0] Failed to duplicate output") {
		t.Errorf("expected Failed to duplicate output to trigger DDA skip")
	}
}
