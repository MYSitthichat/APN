//go:build windows

package remote

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestWindowsDIBRoundTrip(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 8, 6))
	src.SetRGBA(0, 0, color.RGBA{R: 255, G: 10, B: 20, A: 255})
	src.SetRGBA(7, 5, color.RGBA{R: 30, G: 200, B: 250, A: 255})

	dib, err := imageToDIB(src)
	if err != nil {
		t.Fatalf("imageToDIB: %v", err)
	}
	pngBytes, err := dibToPNG(dib)
	if err != nil {
		t.Fatalf("dibToPNG: %v", err)
	}
	decoded, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
	if decoded.Bounds().Dx() != 8 || decoded.Bounds().Dy() != 6 {
		t.Fatalf("unexpected bounds: %v", decoded.Bounds())
	}
	r0, g0, b0, _ := decoded.At(0, 0).RGBA()
	if uint8(r0>>8) != 255 || uint8(g0>>8) != 10 || uint8(b0>>8) != 20 {
		t.Fatalf("top-left pixel mismatch: got (%d,%d,%d)", r0>>8, g0>>8, b0>>8)
	}
	r1, g1, b1, _ := decoded.At(7, 5).RGBA()
	if uint8(r1>>8) != 30 || uint8(g1>>8) != 200 || uint8(b1>>8) != 250 {
		t.Fatalf("bottom-right pixel mismatch: got (%d,%d,%d)", r1>>8, g1>>8, b1>>8)
	}
}
