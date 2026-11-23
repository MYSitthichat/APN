# APN — Changelog

ประวัติการพัฒนาและการแก้ไขในแต่ละเวอร์ชันของ **APN (Remote Desktop 60 FPS & Built-in L3 VPN)**

---

## v1.1.2 (2026-11-23)
- **ไร้หน้าต่างคอมมานด์ 100% (Pure Windows GUI):** บิลด์ Windows (`amd64` / `arm64`) ด้วย `-H=windowsgui` และซ่อนโปรเซสเบื้องหลังทั้งหมด (`cloudflared`, `ffmpeg`, `netsh`, `powershell`, `clip`) ไม่มีหน้าต่าง CMD หรือ Windows Terminal เด้งขึ้นมาอีกต่อไป
- **Auto-Update ครบวงจรผ่าน GitHub Releases:** เชื่อม `https://rdv.psms-center.com/api/releases/latest` กับ `MYSitthichat/APN` พร้อมตรวจ **SHA-256** และรีสตาร์ทกลับเข้าหน้าต่างแอป + System Tray อัตโนมัติหลังอัปเดต
- **GitHub Actions Auto-Release:** บิลด์ไบนารีครบทั้ง 7 แพลตฟอร์ม + `SHA256SUMS.txt` อัตโนมัติทุกครั้งที่ปล่อย Tag เวอร์ชันใหม่

## v1.1.1 (2026-11-23)
- **จัดวางหน้าจอใหม่เต็มจอหน้าเดียว (Desktop App Layout):** ดีไซน์สไตล์ AnyDesk / RustDesk / TeamViewer เต็มความกว้าง 100% ไม่มีขอบว่างซ้าย-ขวาและไม่ต้องเลื่อนหน้าต่าง
- **แยกแถบซ้าย (Your Desk) + แถบเชื่อมต่อแนวนอน + แท็บประวัติเครื่องพร้อมช่องค้นหา** และย้ายการตั้งค่าขั้นสูง/TCP Port Forward เข้าลิ้นชักด้านข้าง (`⚙️ ตั้งค่า`)

## v1.1.0 (2026-11-23)
- **เปลี่ยนชื่อแบรนด์เป็น APN** พร้อมโลโก้ใหม่ฝังลงทั้งตัว `.exe`, System Tray, หน้าเว็บ, Favicon และ PWA มือถือ
- **Windows System Tray + หน้าต่างแอปเดี่ยว:** ปิดหน้าต่างแล้วซ่อนที่ Tray อัตโนมัติ, ดับเบิลคลิกเปิดกลับขึ้นมา, คลิกขวาเพื่อคัดลอก ID / พักรับรีโมต / ออกจากโปรแกรม
- **คีย์บอร์ดสมบูรณ์ 100% + เปลี่ยนภาษาได้จริง:** ส่ง Physical Hardware Scan Code (`ev.Code` → `SendInput`) รองรับตัวหนอน (`~`), `Alt+Shift`, `Win+Space`, `Ctrl+C/V` แม้เปิดภาษาไทย, ปุ่ม Numpad/สัญลักษณ์ครบ พร้อมปุ่มลัด `🌐 เปลี่ยนภาษา`
- **แก้จอดำครั้งแรก & ลดความหน่วง:** แคช GPU Encoder, แคช Keyframe (`SPS+PPS+IDR`) พร้อมระบบขอ Keyframe อัตโนมัติภายใน 1.1 วิ, ลดคิวส่งวิดีโอเหลือ 3 เฟรม และเพิ่มความถี่เมาส์เป็น 166 Hz
- **ตัวติดตั้งในเครื่อง 1 คลิก (Windows / Linux / macOS):** สร้าง Desktop + Start Menu Shortcut, เปิดอัตโนมัติพร้อม Windows แบบซ่อนใน Tray และย้ายการตั้งค่าเดิมมาเก็บใน `%APPDATA%\APN` อัตโนมัติ

## v1.0.2 (2026-11-23)
- ออกแบบและฝังโลโก้ใหม่ (Rounded Squircle โล่กระจก Indigo–Cyan) ลงในไบนารี Windows `.exe` (`rsrc_windows_*.syso`) และ Web UI / PWA

## v1.0.1 (2026-11-23)
- เพิ่ม **Windows Media Foundation GPU (`h264_mf -scenario display_remoting`)** รันได้ 150+ FPS บนการ์ดจอ NVIDIA/Intel/AMD
- แก้บั๊ก Intel QSV ปล่อยบิตเรต CQP 18 Mbps จนท่อตัน เป็น VBR คุมบิตเรต 3.5–5 Mbps
- แก้บั๊ก WebCodecs `decodeQueueSize > 5` ที่ทำให้เฟรมเรตตกเหลือ 25 FPS
- เพิ่ม **Instant WSS-to-QUIC UDP Hole-Punch Upgrade** อัปเกรดการเชื่อมต่อข้ามเน็ตเป็น P2P ตรงอัตโนมัติเมื่อ NAT รองรับ

## v1.0.0 (2026-11-23)
- เพิ่มหน้า **ประวัติเครื่องที่เคยรีโมต (Saved Devices)** พร้อมเช็กสถานะ **ออนไลน์ / ออฟไลน์สด** ผ่าน Cloudflare Worker (`/api/rendezvous/presence`, `/unregister`) และกด **รีโมตเลย (คลิกเดียว)** ด้วยรหัสผ่านที่จำไว้
- ปรับจูน WebCodecs VSync Render (`requestAnimationFrame`), โหมดเมาส์เดี่ยว, `-flush_packets 1` และขยาย Yamux Window เป็น 4 MiB
