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
		if bytes.Contains([]byte(joined), []byte("gfxcapture")) && bytes.Contains([]byte(joined), []byte("-fps_mode cfr")) {
			t.Errorf("WGC candidate %q must use -fps_mode passthrough (cfr causes burst duplicate stutter)", c.name)
		}
	}
	if !isDDACaptureFailure("[Parsed_ddagrab_0] Desktop duplication access denied") {
		t.Errorf("expected Desktop duplication error to trigger DDA skip")
	}
	if !isDDACaptureFailure("[Parsed_ddagrab_0] Failed to duplicate output") {
		t.Errorf("expected Failed to duplicate output to trigger DDA skip")
	}
	if !isDDACaptureFailure("[Parsed_ddagrab_0] Failed to enumerate DXGI output 0") {
		t.Errorf("expected Failed to enumerate DXGI output 0 to trigger DDA skip")
	}
	if !isCaptureTierFailure("WGC", "No such filter: 'gfxcapture'") {
		t.Errorf("expected missing gfxcapture filter to trigger WGC skip")
	}
	// Ensure an encoder error (like NVENC API version mismatch) does NOT wrongly skip the WGC capture tier!
	if isCaptureTierFailure("WGC", "[hevc_nvenc] Driver does not support the required nvenc API version") {
		t.Errorf("encoder failure must not skip WGC capture tier")
	}
	hevcCands := videoEncoderCandidates("hevc", 60, 1920, 1080, 1920, 1080, 82)
	if len(hevcCands) == 0 {
		t.Fatalf("expected non-empty HEVC GPU encoder candidates")
	}
}

func TestEnhancedFLVHEVCReader(t *testing.T) {
	var flv bytes.Buffer
	flv.Write([]byte{'F', 'L', 'V', 0x01, 0x01, 0, 0, 0, 9, 0, 0, 0, 0})

	// Enhanced FLV SequenceStart (ExHeader=1, FrameType=1, PacketType=0, FourCC="hvc1")
	vps := []byte{0x40, 0x01, 0x0C, 0x01}
	sps := []byte{0x42, 0x01, 0x01, 0x01}
	pps := []byte{0x44, 0x01, 0xC0, 0xF7}
	var cfg bytes.Buffer
	cfg.WriteByte(0x90) // 1001_0000 (ExHeader=1, Keyframe=1, SeqStart=0)
	cfg.WriteString("hvc1")
	cfg.Write(make([]byte, 21)) // HEVCDecoderConfigurationRecord header bytes 0..20
	cfg.WriteByte(0xFF)         // lengthSizeMinusOne = 3 (4-byte NAL length)
	cfg.WriteByte(3)            // numOfArrays = 3 (VPS, SPS, PPS)
	for _, entry := range []struct {
		t byte
		b []byte
	}{{32, vps}, {33, sps}, {34, pps}} {
		cfg.WriteByte(entry.t)
		binary.Write(&cfg, binary.BigEndian, uint16(1))
		binary.Write(&cfg, binary.BigEndian, uint16(len(entry.b)))
		cfg.Write(entry.b)
	}
	flv.Write(buildFLVTag(9, cfg.Bytes()))

	// Enhanced FLV CodedFramesX keyframe (ExHeader=1, FrameType=1, PacketType=3, FourCC="hvc1")
	idr := []byte{0x26, 0x01, 0xAF, 0x09} // NAL type 19 (IDR_W_RADL)
	var kf bytes.Buffer
	kf.WriteByte(0x93)
	kf.WriteString("hvc1")
	binary.Write(&kf, binary.BigEndian, uint32(len(idr)))
	kf.Write(idr)
	flv.Write(buildFLVTag(9, kf.Bytes()))

	// Enhanced FLV CodedFramesX inter-frame (ExHeader=1, FrameType=2, PacketType=3, FourCC="hvc1")
	trail := []byte{0x02, 0x01, 0x11, 0x22} // NAL type 1 (TRAIL_R)
	var pf bytes.Buffer
	pf.WriteByte(0xA3)
	pf.WriteString("hvc1")
	binary.Write(&pf, binary.BigEndian, uint32(len(trail)))
	pf.Write(trail)
	flv.Write(buildFLVTag(9, pf.Bytes()))

	r := newFLVH264Reader(&flv)
	au1, isKey1, err := r.NextAccessUnit()
	if err != nil || !isKey1 {
		t.Fatalf("read HEVC keyframe: key=%v err=%v", isKey1, err)
	}
	want1 := []byte{
		0, 0, 0, 1, 0x40, 0x01, 0x0C, 0x01,
		0, 0, 0, 1, 0x42, 0x01, 0x01, 0x01,
		0, 0, 0, 1, 0x44, 0x01, 0xC0, 0xF7,
		0, 0, 0, 1, 0x26, 0x01, 0xAF, 0x09,
	}
	if !bytes.Equal(au1, want1) {
		t.Fatalf("HEVC keyframe mismatch: got %x want %x", au1, want1)
	}
	au2, isKey2, err := r.NextAccessUnit()
	if err != nil || isKey2 {
		t.Fatalf("read HEVC delta: key=%v err=%v", isKey2, err)
	}
	want2 := []byte{0, 0, 0, 1, 0x02, 0x01, 0x11, 0x22}
	if !bytes.Equal(au2, want2) {
		t.Fatalf("HEVC delta mismatch: got %x want %x", au2, want2)
	}
}
