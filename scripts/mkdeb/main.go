package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	binPath := flag.String("bin", "", "Path to compiled Linux APN binary")
	iconPath := flag.String("icon", "", "Path to 256x256 PNG icon")
	ver := flag.String("version", "1.2.0", "Package version")
	arch := flag.String("arch", "amd64", "Debian architecture: amd64, arm64, armhf")
	outPath := flag.String("out", "", "Output .deb file path")
	flag.Parse()

	if *binPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: mkdeb -bin <path> -icon <png> -version <ver> -arch <amd64|arm64|armhf> -out <file.deb>")
		os.Exit(1)
	}

	binData, err := os.ReadFile(*binPath)
	if err != nil {
		panic(err)
	}
	var iconData []byte
	if *iconPath != "" {
		iconData, err = os.ReadFile(*iconPath)
		if err != nil {
			panic(err)
		}
	}

	now := time.Now().UTC()

	desktopEntry := `[Desktop Entry]
Version=1.0
Type=Application
Name=APN
GenericName=Remote Desktop & VPN
Comment=High-Speed 60 FPS P2P Remote Desktop & Encrypted L3 VPN
Exec=/usr/bin/apn
Icon=apn
Terminal=false
Categories=Network;RemoteAccess;
StartupNotify=true
`

	autostartEntry := `[Desktop Entry]
Type=Application
Name=APN Background Service
Comment=Keep APN online for incoming remote access
Exec=/usr/bin/apn peer -tray
Icon=apn
Terminal=false
X-GNOME-Autostart-enabled=true
`

	launcherScript := `#!/bin/sh
# Prefer user-updated binary (~/.local/bin/apn) when newer than system .deb binary
USER_BIN="$HOME/.local/bin/apn"
if [ -x "$USER_BIN" ] && [ "$USER_BIN" -nt /usr/lib/apn/apn ]; then
  exec "$USER_BIN" "$@"
fi
exec /usr/lib/apn/apn "$@"
`

	dataEntries := []tarEntry{
		{name: "./usr/", isDir: true, mode: 0o755},
		{name: "./usr/bin/", isDir: true, mode: 0o755},
		{name: "./usr/bin/apn", data: []byte(launcherScript), mode: 0o755},
		{name: "./usr/lib/", isDir: true, mode: 0o755},
		{name: "./usr/lib/apn/", isDir: true, mode: 0o755},
		{name: "./usr/lib/apn/apn", data: binData, mode: 0o755},
		{name: "./usr/share/", isDir: true, mode: 0o755},
		{name: "./usr/share/applications/", isDir: true, mode: 0o755},
		{name: "./usr/share/applications/apn.desktop", data: []byte(desktopEntry), mode: 0o644},
		{name: "./etc/", isDir: true, mode: 0o755},
		{name: "./etc/xdg/", isDir: true, mode: 0o755},
		{name: "./etc/xdg/autostart/", isDir: true, mode: 0o755},
		{name: "./etc/xdg/autostart/apn.desktop", data: []byte(autostartEntry), mode: 0o644},
	}
	if len(iconData) > 0 {
		dataEntries = append(dataEntries,
			tarEntry{name: "./usr/share/icons/", isDir: true, mode: 0o755},
			tarEntry{name: "./usr/share/icons/hicolor/", isDir: true, mode: 0o755},
			tarEntry{name: "./usr/share/icons/hicolor/256x256/", isDir: true, mode: 0o755},
			tarEntry{name: "./usr/share/icons/hicolor/256x256/apps/", isDir: true, mode: 0o755},
			tarEntry{name: "./usr/share/icons/hicolor/256x256/apps/apn.png", data: iconData, mode: 0o644},
		)
	}

	dataTarGz := buildTarGz(dataEntries, now)

	installedKB := (len(binData) + len(iconData) + 4096) / 1024
	controlFile := fmt.Sprintf(`Package: apn
Version: %s
Section: net
Priority: optional
Architecture: %s
Maintainer: APN <apn@psms-center.com>
Installed-Size: %d
Recommends: ffmpeg, xdotool
Description: APN Remote Desktop & Built-in L3 VPN
 High-speed 60 FPS P2P Remote Desktop and encrypted L3 VPN in a single app.
`, *ver, *arch, installedKB)

	postinst := `#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
`

	controlTarGz := buildTarGz([]tarEntry{
		{name: "./control", data: []byte(controlFile), mode: 0o644},
		{name: "./postinst", data: []byte(postinst), mode: 0o755},
	}, now)

	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	writeArMember(&deb, "debian-binary", []byte("2.0\n"), now)
	writeArMember(&deb, "control.tar.gz", controlTarGz, now)
	writeArMember(&deb, "data.tar.gz", dataTarGz, now)

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*outPath, deb.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("Built Debian/Ubuntu package: %s (%d bytes)\n", *outPath, deb.Len())
}

type tarEntry struct {
	name  string
	data  []byte
	mode  int64
	isDir bool
}

func buildTarGz(entries []tarEntry, modTime time.Time) []byte {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			ModTime:  modTime,
			Format:   tar.FormatUSTAR,
			Typeflag: tar.TypeReg,
			Size:     int64(len(e.data)),
		}
		if e.isDir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if !e.isDir && len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				panic(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func writeArMember(w *bytes.Buffer, name string, data []byte, modTime time.Time) {
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n",
		name,
		modTime.Unix(),
		0,
		0,
		0o100644,
		len(data),
	)
	w.WriteString(hdr)
	w.Write(data)
	if len(data)%2 == 1 {
		w.WriteByte('\n')
	}
}
