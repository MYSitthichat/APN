# RelayVPN 443

โปรแกรม Remote Access & Tunnel ข้ามแพลตฟอร์มที่พัฒนาด้วย **Go (Pure Go / Zero CGO)** เชื่อมต่อแบบ **Outbound ผ่านพอร์ต 443 (TLS 1.3 + WebSocket + Yamux Multiplexing)** พร้อมหน้า **Web Dashboard** ฝังในตัวไฟล์เดียว รองรับ Windows, macOS และ Linux (amd64 & arm64)

## จุดเด่นด้านความปลอดภัยและเสถียรภาพ
- **TLS 1.3 Only (`MinVersion: TLS 1.3`)** พร้อมรองรับ Certificate Pinning (Private CA) หรือใบรับรองมาตรฐาน (Let's Encrypt)
- **Token Hashing (SHA-256 + Constant-Time Compare)** เซิร์ฟเวอร์เก็บเฉพาะค่าแฮชของ Token ไม่เก็บ Token เปล่า
- **Built-in Remote Desktop + Mouse/Keyboard + Remote Terminal** รีโมตดูหน้าจอสดและควบคุมเครื่องผ่านท่อ TLS 1.3 / WSS 443 ได้ทันทีจากเบราว์เซอร์ (รองรับพิมพ์ไทย-อังกฤษ)
- **Web Remote Portal บน HTTPS 443 (`enable_web_portal: true`)** เปิดเบราว์เซอร์จากมือถือ (iOS/Android) หรือคอมเครื่องไหนก็ได้แล้วล็อกอินด้วย Client ID + Token เพื่อรีโมตได้ทันทีโดยไม่ต้องลงแอปเพิ่ม
- **Strict Allowlist & Permissions ฝั่งเครื่องเป้าหมาย** ควบคุมสิทธิ์แยกอิสระ (`allow_screen`, `allow_input`, `allow_shell`, `allowed_targets`)
- **Owner Controls บน Agent Web UI** เจ้าของเครื่องเห็นเซสชันรีโมตแบบเรียลไทม์ กดพักการรีโมตชั่วคราว หรือตัดการเชื่อมต่อทั้งหมดได้ทันที
- **Auto-Reconnect + Keepalive (Yamux)** เชื่อมต่อใหม่อัตโนมัติแบบ Exponential Backoff เมื่อสลับ Wi-Fi / 4G / 5G
- **พร้อมต่อยอดสู่ Phase 2 (L3 VPN / TUN)** โปรโตคอลเฟรมรองรับโหมด `tun` ไว้แล้ว สามารถเพิ่ม Wintun / `/dev/net/tun` บนท่อ TLS 443 เดิมได้ทันที

---

## โหมดใหม่: Serverless P2P (`relayvpn peer`) — ไม่ต้องมี VPS ทุกเครื่องเป็นทั้ง Host และ Client!

รันคำสั่งเดียวบนแต่ละเครื่อง (สร้างไฟล์ตั้งค่าและใบรับรอง ECDSA P-256 อัตโนมัติครั้งแรก):
```powershell
.\dist\relayvpn-windows-amd64.exe peer
```
แล้วเปิดเบราว์เซอร์ที่ `http://127.0.0.1:8080`

### วิธีเชื่อม 2 เครื่องเข้าหากันแบบไม่มี VPS
1. **ในวง Wi-Fi / LAN เดียวกัน:** ทั้ง 2 เครื่องจะมองเห็นกันอัตโนมัติในหัวข้อ *เครื่องที่พบอัตโนมัติในวง LAN* หรือคัดลอก **Peer Ticket (`RVPN1-...`)** จากเครื่องหนึ่งไปวางอีกเครื่อง
2. **ข้ามอินเทอร์เน็ต (Home Router / 4G / 5G):** โปรแกรมใช้ **STUN** หา Public UDP IP:Port ให้อัตโนมัติแล้วใส่ลงใน **Peer Ticket (`RVPN1-...`)** เมื่ออีกเครื่องวาง Ticket จะทำ **UDP Hole Punching + QUIC TLS 1.3** เชื่อมตรงกันพร้อมตรวจสอบ Certificate Fingerprint
3. **กรณีเจอ Symmetric NAT หรือไฟร์วอลล์บล็อก UDP (ใช้ Cloudflare Tunnel ฟรี ไม่ต้องมี VPS/โดเมน):**
   * บนเครื่องใดเครื่องหนึ่ง รัน:
     ```powershell
     cloudflared tunnel --url http://127.0.0.1:8444
     ```
   * นำลิงก์ `https://xxxx.trycloudflare.com` ที่ได้มาวางลงในช่อง **Public WSS URL** บนหน้า Dashboard ของเครื่องนั้น → ระบบจะใส่เข้า **Peer Ticket** ให้อัตโนมัติ (วิ่งผ่านพอร์ต 443 แท้!)
   * **จุดเด่น:** ไม่ว่าเครื่องไหนจะเชื่อมออกไปหาอีกเครื่อง ทั้งสองเครื่องจะเห็นกันและ **สามารถรีโมตดูหน้าจอ / เปิด Terminal / ส่งพอร์ต TCP หากันได้ทั้งสองฝั่ง** บนการเชื่อมต่อเดียว!

---

## สถาปัตยกรรม (โหมด Relay Server 443)

```text
[Client / โน้ตบุ๊ก] ──(Outbound WSS/TLS 1.3 :443)──> [Relay Server (VPS :443)] <──(Outbound WSS/TLS 1.3 :443)── [Agent / เครื่องปลายทาง]
  └─ Localhost :13389 (RDP)                                                                                        └─ Allowlist: 127.0.0.1:3389
  └─ Web UI: http://127.0.0.1:8080                     └─ Admin UI: http://127.0.0.1:8082                          └─ Web UI: http://127.0.0.1:8081
```

---

## วิธีทดสอบบนเครื่องตัวเอง (Quick Start)

### 1. คอมไพล์โปรแกรม
```powershell
go build -o relayvpn.exe ./cmd/relayvpn
```

### 2. สร้างไฟล์ตั้งค่า + ใบรับรอง TLS + Token อัตโนมัติ
*(ใช้ `-port 8443` สำหรับทดสอบบนเครื่องตัวเอง หรือ `-port 443 -host vpn.yourdomain.com` สำหรับ VPS จริง)*
```powershell
.\relayvpn.exe init -dir ./config -host localhost -port 8443
```

### 3. เปิดรันทั้ง 3 ส่วน (แยก Terminal)
```powershell
# Terminal 1: Relay Server
.\relayvpn.exe server -config ./config/server.json

# Terminal 2: Agent (เครื่องเป้าหมายที่อยากรีโมตเข้า)
.\relayvpn.exe agent -config ./config/agent.json

# Terminal 3: Client (เครื่องที่ใช้รีโมต)
.\relayvpn.exe client -config ./config/client.json
```

### 4. เปิดหน้า Web Dashboard
- **Client Dashboard:** http://127.0.0.1:8080 (ดูเครื่องที่ออนไลน์และกดสร้าง Tunnel 1 คลิก)
- **Agent Dashboard:** http://127.0.0.1:8081 (ดูผู้ที่รีโมตเข้ามา / กดพักหรือตัดการเชื่อมต่อ)
- **Server Dashboard:** http://127.0.0.1:8082 (ดูภาพรวมระบบ)

เมื่อเปิด Tunnel เช่น `127.0.0.1:13389 -> home-pc:3389` แล้ว สามารถเปิด **Remote Desktop Connection (`mstsc`)** และเชื่อมต่อไปที่ `127.0.0.1:13389` ได้ทันที

---

## การคอมไพล์สำหรับทุก OS (Windows / macOS / Linux)

```powershell
.\scripts\build-all.ps1
```
ไฟล์ไบนารีทั้งหมดจะถูกสร้างไว้ที่โฟลเดอร์ `dist/` ได้แก่:
- `relayvpn-windows-amd64.exe`, `relayvpn-windows-arm64.exe`
- `relayvpn-linux-amd64`, `relayvpn-linux-arm64`
- `relayvpn-darwin-amd64`, `relayvpn-darwin-arm64`

---

## การติดตั้งบน VPS จริง (พอร์ต 443)

1. อัปโหลด `relayvpn-linux-amd64` และ `server.json` ไปยัง VPS ของคุณ
2. ใช้ใบรับรอง TLS จริง (เช่น Let's Encrypt `/etc/letsencrypt/live/vpn.yourdomain.com/fullchain.pem` และ `privkey.pem`) หรือใช้ Private CA ที่สร้างจาก `relayvpn init` (หากใช้ Private CA ต้องคัดลอกไฟล์ `ca.crt` ไปไว้ที่เครื่อง Agent และ Client ด้วย)
3. ตั้งค่า `"listen_addr": ":443"` ใน `server.json` และให้สิทธิ์พอร์ต 443 โดยไม่ต้องรันด้วย root:
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/relayvpn
   ```
4. สร้าง Token เพิ่มสำหรับเครื่องใหม่ได้ตลอดด้วยคำสั่ง:
   ```bash
   relayvpn token
   ```

---

## แผนต่อยอด Phase 2 (L3 VPN เต็มรูปแบบ)
- เพิ่มอินเทอร์เฟซ TUN (`Wintun` บน Windows, `/dev/net/tun` บน Linux, `utun` บน macOS) เชื่อมเข้าโหมด `ModeTUN` ที่จองไว้แล้วใน `internal/protocol`
- เพิ่ม IPAM (แจก Virtual IP เช่น `10.99.0.x`) บน Relay Server
- เพิ่ม Transport ทางเลือก **QUIC / HTTP/3 (UDP 443)** พร้อม Fallback เป็น WSS (TCP 443) อัตโนมัติ
