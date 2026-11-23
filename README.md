<p align="center">
  <img src="assets/logo-512.png" alt="APN Logo" width="112" />
</p>

<h1 align="center">APN — Remote Desktop &amp; Built-in L3 VPN</h1>

<p align="center">
  โปรแกรมรีโมตเดสก์ท็อป 60 FPS และ Virtual LAN (L3 VPN) ข้ามเครือข่ายอัตโนมัติในไฟล์เดียว<br />
  รองรับ Windows · Linux · macOS · มือถือ (PWA)
</p>

---

## จุดเด่นหลัก
- **เชื่อมต่อด้วยเลข 9 หลัก + รหัสผ่าน:** ใช้งานง่ายสไตล์ AnyDesk / RustDesk ทั้งในวง LAN และข้ามอินเทอร์เน็ต
- **ภาพลื่น 60 FPS (GPU H.264):** ใช้ Hardware Acceleration (Windows Media Foundation / NVENC / Intel QSV / AMD AMF / VideoToolbox) พร้อมโหมด Smart Tiles สำรองอัตโนมัติ
- **คีย์บอร์ดสมบูรณ์ (ไทย/อังกฤษ):** ส่ง Hardware Scan Code เต็มรูปแบบ รองรับปุ่มเปลี่ยนภาษาและคีย์ลัดครบ
- **Built-in L3 VPN:** สร้างการ์ดแลนจำลองในตัวสำหรับใช้งาน RDP, SSH, SMB หรือ Moonlight/Sunshine
- **ทำงานเป็นแอปเดสก์ท็อปเต็มรูปแบบ:** หน้าต่างแอปเดี่ยว ไร้หน้าต่างคอมมานด์ ซ่อนที่ System Tray เมื่อปิดหน้าต่าง และเปิดอัตโนมัติพร้อมเครื่องได้
- **ประวัติเครื่อง & อัปเดตตัวเองอัตโนมัติ:** แสดงสถานะออนไลน์สด คลิกเดียวเชื่อมต่อใหม่ และอัปเดตเวอร์ชันใหม่ได้จากในแอปพร้อมตรวจ SHA-256
- **ความปลอดภัย:** เข้ารหัส TLS 1.3 แบบ End-to-End, ยืนยันตัวตนด้วย PIN / รหัสผ่านถาวร (Salted SHA-256) และโหมดขออนุมัติก่อนเข้าควบคุม (Accept/Reject)

---

## ดาวน์โหลดและเริ่มต้นใช้งาน
1. ดาวน์โหลดไฟล์ตามระบบปฏิบัติการจากหน้า [Releases ล่าสุด](https://github.com/MYSitthichat/APN/releases/latest)
2. ดับเบิลคลิกเปิดโปรแกรม (คอมโพเนนต์ที่จำเป็นจะถูกเตรียมให้อัตโนมัติ)
3. กดปุ่ม **ติดตั้ง APN ลงเครื่อง** เพื่อสร้างไอคอนหน้าจอ + เปิดอัตโนมัติพร้อมระบบ + ซ่อนที่ System Tray
4. กรอก **รหัสเครื่อง 9 หลัก** และ **รหัสผ่าน** ของเครื่องปลายทางเพื่อเริ่มรีโมต

### แพลตฟอร์มที่รองรับ
| แพลตฟอร์ม | ไฟล์ |
| :--- | :--- |
| Windows (Intel/AMD, ARM64) | `APN-v*-windows-amd64.exe`, `APN-v*-windows-arm64.exe` |
| Linux (x64, ARM64, ARMv7) | `APN-v*-linux-amd64`, `APN-v*-linux-arm64`, `APN-v*-linux-armv7` |
| macOS (Apple Silicon, Intel) | `APN-v*-macos-arm64`, `APN-v*-macos-amd64` |
| iOS / Android | ติดตั้งผ่านเบราว์เซอร์ (Add to Home Screen / PWA) |

---

## การบิลด์จากซอร์สโค้ด (สำหรับนักพัฒนา)
ต้องติดตั้ง Go 1.24+ แล้วรัน:
```powershell
go test ./...
.\scripts\build-all.ps1
```

ดูประวัติการเปลี่ยนแปลงทั้งหมดได้ที่ [CHANGELOG.md](CHANGELOG.md)
