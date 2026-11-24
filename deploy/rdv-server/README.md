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

## ความปลอดภัยและการจำกัดการใช้งาน (ตั้งแต่ v1.3.10)
- **ลงลายเซ็นการลงทะเบียน:** เครื่อง APN ลงลายเซ็นคำขอ `register`/`unregister` ด้วย key ECDSA P-256 ของใบรับรอง TLS ของเครื่อง และ Server จะผูกรหัสเครื่อง 9 หลักกับ key ตัวแรกที่ลงลายเซ็นนาน 30 วัน (บันทึกใน snapshot) — คนอื่นจึงสวมรหัสเครื่องเพื่อดักรหัสผ่านไม่ได้ ส่วนเครื่องเวอร์ชันเก่าที่ยังไม่ลงลายเซ็นยังใช้งานได้ แต่จะถูกแทนที่ไม่ได้ขณะออนไลน์อยู่
- **จำกัดอัตราต่อ IP:** ค่าเริ่มต้น 600 คำขอ/นาที (burst 300) ปรับด้วย `-rate-per-min` และ `-rate-burst` (ค่าติดลบ = ปิด) — หลัง Cloudflare Tunnel หรือ reverse proxy บนเครื่องเดียวกัน/เครือข่ายภายใน Server จะใช้ IP จาก `CF-Connecting-IP` / `X-Forwarded-For`
- **จำกัดจำนวนเครื่องในหน่วยความจำ:** `-max-entries` (ค่าเริ่มต้น 2,000,000) และจำกัดความยาวชื่อ/`ws_url`/ที่อยู่ UDP ต่อคำขอ
