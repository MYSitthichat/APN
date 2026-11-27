# APN Self-Hosted Rendezvous Server (`apn rdv-server`)

สมุดหน้าเหลือง ID 9 หลักแบบรันเองบน Linux Server (ไม่ติดโควต้า Cloudflare KV 1,000 writes/วัน)
- เก็บข้อมูลใน RAM แบบ **64-Shard Lock** รองรับ **หลายหมื่น request/วินาที** (100,000 เครื่องใช้ RAM แค่ ~300 MB และเน็ต ~25 Mbps)
- บันทึก **Snapshot ลงดิสก์อัตโนมัติทุก 30 วินาทีและตอนปิดเครื่อง** รีสตาร์ทแล้วข้อมูลไม่หาย
- รองรับ API ครบ 100% แทน `cloudflare-worker/rendezvous-worker.js` โดยไม่ต้องแก้ไคลเอนต์ APN

---

## วิธีที่ 1: รันตรงๆ บน Ubuntu ด้วย `systemd` (แนะนำ — เร็วสุด กิน RAM น้อยสุด)

1. ติดตั้งแพ็กเกจ `APN-v1.3.8-linux-amd64.deb`:
   ```bash
   sudo dpkg -i APN-v1.3.8-linux-amd64.deb
   ```
2. สร้างไฟล์ Service `/etc/systemd/system/apn-rdv.service` (หรือคัดลอกจาก `deploy/rdv-server/apn-rdv.service`):
   ```bash
   sudo tee /etc/systemd/system/apn-rdv.service >/dev/null <<'EOF'
   [Unit]
   Description=APN Self-Hosted Rendezvous Directory Server
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   ExecStart=/usr/lib/apn/apn rdv-server -listen 127.0.0.1:8787 -snapshot /var/lib/apn/rdv-snapshot.json -ttl 5m
   Restart=always
   RestartSec=2
   LimitNOFILE=1048576

   [Install]
   WantedBy=multi-user.target
   EOF
   ```
3. เปิดใช้งานและตรวจสอบ:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now apn-rdv.service
   curl -s http://127.0.0.1:8787/healthz
   ```

---

## วิธีที่ 2: รันผ่าน Docker Compose บน Ubuntu

```bash
cd deploy/rdv-server
docker compose up -d --build
curl -s http://127.0.0.1:8787/healthz
```

*(หากต้องการให้ `cloudflared` รันคู่กันใน Docker ให้เอา `#` ออกใน `docker-compose.yml` และใส่ `CLOUDFLARE_TUNNEL_TOKEN=...` ในไฟล์ `.env`)*

---

## เชื่อมโดเมน `rdv.psms-center.com` ผ่าน Cloudflare Named Tunnel (ฟรี ถาวร ไม่ต้องเปิดพอร์ตเราเตอร์)

1. เข้า **Cloudflare Zero Trust Dashboard** → **Networks** → **Tunnels** → **Create a tunnel** (Cloudflared)
2. ตั้งชื่อ Tunnel (เช่น `apn-rdv`) แล้วรันคำสั่งติดตั้ง Connector ที่หน้าเว็บให้มาบน Ubuntu Server
3. ในแท็บ **Public Hostname** เพิ่ม:
   - **Hostname:** `rdv.psms-center.com`
   - **Service:** `http://127.0.0.1:8787` *(หรือ `http://apn-rdv:8787` ถ้ารันใน Docker Compose เดียวกัน)*
4. ลบ Worker Route เดิมของ `rdv.psms-center.com` ออก (ใน Workers & Pages → `relayvpn-rdv` → Settings → Domains & Routes) เพื่อให้ทราฟฟิกวิ่งเข้า Linux Server ของคุณทันที
5. ทดสอบ:
   ```bash
   curl -s https://rdv.psms-center.com/healthz
   ```
   จะเห็น `"backend":"self-hosted-go","online_peers":...` ใช้งานแทน Cloudflare KV ได้ทันทีโดยไม่ต้องแก้โปรแกรมลูกค้าเลย!

## ระบบบัญชีสำหรับซิงก์รายชื่อเครื่อง (ตั้งแต่ v1.3.34)
ผู้ใช้สมัครและเข้าสู่ระบบจากในแอป (ปุ่ม `👤 เข้าสู่ระบบ` ในแถบประวัติเครื่อง) แล้วรายชื่อเครื่องที่เคย remote กลุ่ม และรหัสผ่านที่จำไว้จะตามไปทุกเครื่องที่เข้าสู่ระบบด้วยบัญชีเดียวกัน

- **เปิดใช้เองหลังอัปเดต Server:** ไม่ต้องตั้งค่าเพิ่ม ข้อมูลบัญชีเก็บในโฟลเดอร์ `accounts` ข้างไฟล์ snapshot คือ `/var/lib/apn/accounts` (systemd) หรือ `/data/accounts` (Docker อยู่ใน volume `apn_rdv_data` อยู่แล้ว)
- **ต้องสำรองโฟลเดอร์นี้:** ต่างจาก snapshot ที่สร้างใหม่เองได้ ถ้าโฟลเดอร์ `accounts` หาย บัญชีและรายชื่อของทุกคนจะหายไปด้วย (รายชื่อบนเครื่องของผู้ใช้แต่ละคนยังอยู่ และจะอัปโหลดกลับเมื่อสมัครใหม่)
- **Server อ่านรายชื่อไม่ได้:** รายชื่อถูกเข้ารหัสบนเครื่องผู้ใช้ด้วย key ที่ได้จากรหัสผ่านบัญชี (Argon2id แล้ว AES-256-GCM) ก่อนส่ง Server เก็บเฉพาะข้อมูลที่เข้ารหัสแล้ว, ค่า hash ของ key สำหรับเข้าสู่ระบบ และ hash ของ session token จึงไม่มีรหัสผ่านบัญชีหรือรหัสผ่านของเครื่องปลายทางอยู่บน Server
- **ลืมรหัสผ่านบัญชี:** ผู้ใช้กด `ลืมรหัสผ่าน?` ในแอป แล้ว Server ส่งรหัส 8 หลักไปที่อีเมลของบัญชี (ต้องตั้งค่าส่งอีเมลตามหัวข้อถัดไป) เมื่อตั้งรหัสผ่านใหม่ รายชื่อที่เข้ารหัสไว้บน Server จะถูกล้าง เพราะไม่มีใครถอดรหัสแทนได้ ส่วนรายชื่อบนเครื่องของผู้ใช้ยังอยู่ และจะอัปโหลดกลับเมื่อเครื่องนั้นเข้าสู่ระบบด้วยรหัสผ่านใหม่
- **ถ้าไม่ได้ตั้งค่าส่งอีเมล:** รีเซ็ตทางอีเมลไม่ได้ ทางแก้คือลบไฟล์ `u-<ชื่อผู้ใช้>.json` และ `u-<ชื่อผู้ใช้>.vault` ในโฟลเดอร์ `accounts` แล้ว restart Server จากนั้นให้ผู้ใช้สมัครใหม่จากเครื่องที่ยังมีรายชื่ออยู่
- **ตัวเลือกของ `apn rdv-server`:**
  - `-account-signup=false` ปิดรับสมัครบัญชีใหม่ (บัญชีเดิมยังใช้ได้)
  - `-accounts-dir <path>` ย้ายที่เก็บ หรือ `-accounts-dir off` ปิดระบบบัญชี
  - `-max-accounts 10000` จำนวนบัญชีสูงสุด
- **การจำกัด:** สมัครได้ 5 บัญชีต่อ IP ต่อชั่วโมง, ใส่รหัสผ่านผิดได้ 8 ครั้งต่อ IP ต่อบัญชีใน 10 นาที (และ 60 ครั้งต่อบัญชีต่อชั่วโมงจากทุก IP), รายชื่อที่เข้ารหัสแล้วใหญ่ได้ไม่เกิน 256 KB ต่อบัญชี, session หมดอายุเมื่อไม่ได้ใช้ 90 วัน

### ตั้งค่าส่งอีเมลสำหรับ "ลืมรหัสผ่าน"
Server ส่งรหัสรีเซ็ตผ่าน SMTP ของผู้ให้บริการอีเมลที่คุณมีอยู่ ตั้งค่าด้วยตัวแปรสภาพแวดล้อม (รหัสผ่าน SMTP รับจากตัวแปรเท่านั้น ไม่รับจากบรรทัดคำสั่ง):

| ตัวแปร | ความหมาย | ตัวอย่าง (Gmail) |
|---|---|---|
| `APN_SMTP_HOST` | เซิร์ฟเวอร์ SMTP | `smtp.gmail.com` |
| `APN_SMTP_PORT` | `587` (STARTTLS, ค่าเริ่มต้น) หรือ `465` (TLS) | `587` |
| `APN_SMTP_USER` | ชื่อเข้าสู่ระบบ SMTP | `you@gmail.com` |
| `APN_SMTP_PASSWORD` | รหัสผ่าน SMTP | App Password 16 ตัวของ Google |
| `APN_SMTP_FROM` | ผู้ส่งที่แสดงในอีเมล (ไม่ใส่จะใช้ค่าเดียวกับ `APN_SMTP_USER`) | `APN <you@gmail.com>` |

- **Gmail:** ใช้รหัสผ่านบัญชี Google ตรงๆ ไม่ได้ ต้องเปิดการยืนยันสองขั้นตอน แล้วสร้าง "App Password" ที่ `myaccount.google.com/apppasswords`
- **systemd:** สร้างไฟล์ `/etc/apn/rdv.env` (สิทธิ์ `600`) ใส่ตัวแปรบรรทัดละตัว แล้วเพิ่ม `EnvironmentFile=/etc/apn/rdv.env` ใต้ `[Service]` ใน `apn-rdv.service` จากนั้น `sudo systemctl daemon-reload && sudo systemctl restart apn-rdv`
- **Docker Compose:** ใส่ตัวแปรในไฟล์ `.env` ข้าง `docker-compose.yml` (ดูส่วน `environment:` ที่เตรียมไว้ในไฟล์) แล้ว `docker compose up -d`
- **ทดสอบก่อนใช้จริง:** รันด้วยตัวแปรชุดเดียวกัน แล้วดูว่าอีเมลถึงหรือไม่
  ```bash
  apn rdv-server -smtp-test you@example.com
  ```
  ใน Docker: `docker compose run --rm apn-rdv -smtp-test you@example.com`
- เมื่อเปิดสำเร็จ log ตอนเริ่ม Server จะมี `reset_by_email=true` และเมื่อตั้งค่าแล้ว การสมัครบัญชีใหม่จะบังคับกรอกอีเมล
- ขอรหัสรีเซ็ตได้ 3 ครั้งต่อบัญชีต่อชั่วโมง รหัสใช้ได้ 15 นาที และใส่ผิดได้ 5 ครั้งต่อรหัส

## ความปลอดภัยและการจำกัดการใช้งาน (ตั้งแต่ v1.3.10)
- **ลงลายเซ็นการลงทะเบียน:** เครื่อง APN ลงลายเซ็นคำขอ `register`/`unregister` ด้วย key ECDSA P-256 ของใบรับรอง TLS ของเครื่อง และ Server จะผูกรหัสเครื่อง 9 หลักกับ key ตัวแรกที่ลงลายเซ็นนาน 30 วัน (บันทึกใน snapshot) — คนอื่นจึงสวมรหัสเครื่องเพื่อดักรหัสผ่านไม่ได้ ส่วนเครื่องเวอร์ชันเก่าที่ยังไม่ลงลายเซ็นยังใช้งานได้ แต่จะถูกแทนที่ไม่ได้ขณะออนไลน์อยู่
- **จำกัดอัตราต่อ IP:** ค่าเริ่มต้น 600 คำขอ/นาที (burst 300) ปรับด้วย `-rate-per-min` และ `-rate-burst` (ค่าติดลบ = ปิด) — หลัง Cloudflare Tunnel หรือ reverse proxy บนเครื่องเดียวกัน/เครือข่ายภายใน Server จะใช้ IP จาก `CF-Connecting-IP` / `X-Forwarded-For`
- **จำกัดจำนวนเครื่องในหน่วยความจำ:** `-max-entries` (ค่าเริ่มต้น 2,000,000) และจำกัดความยาวชื่อ/`ws_url`/ที่อยู่ UDP ต่อคำขอ
