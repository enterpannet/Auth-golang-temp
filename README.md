# Auth Service

ระบบจัดการการยืนยันตัวตน (Authentication Service) ที่มีความปลอดภัยสูงและมีฟีเจอร์ครบถ้วน

## คุณสมบัติหลัก

- **การจัดการผู้ใช้**: ลงทะเบียน, เข้าสู่ระบบ, รีเซ็ตรหัสผ่าน
- **การพิสูจน์ตัวตนหลายปัจจัย (MFA)**: รองรับ TOTP (Time-based One-Time Password)
- **OAuth 2.0**: รองรับการเข้าสู่ระบบผ่าน Google, Facebook, GitHub
- **JWT Authentication**: จัดการ Access Token และ Refresh Token
- **ระบบจัดการสิทธิ์**: บทบาท (Roles) และสิทธิ์การเข้าถึง (Permissions)
- **การบันทึกประวัติความปลอดภัย**: บันทึกกิจกรรมที่สำคัญทั้งหมดสำหรับการตรวจสอบ
- **ระบบจัดการผู้ใช้สำหรับผู้ดูแลระบบ**: จัดการผู้ใช้และสิทธิ์อย่างสมบูรณ์

## ความต้องการของระบบ

- Go 1.20 หรือสูงกว่า
- PostgreSQL 12 หรือสูงกว่า
- Docker (เสริม สำหรับการใช้งานกับ Docker)

## การติดตั้ง

1. โคลนโปรเจค

```bash
git clone https://github.com/your-org/auth-service.git
cd auth-service
```

2. ติดตั้ง dependencies

```bash
go mod download
```

3. ตั้งค่าฐานข้อมูล PostgreSQL

ตรวจสอบให้แน่ใจว่าคุณมี PostgreSQL เวอร์ชัน 12 หรือสูงกว่าที่ติดตั้งและทำงานอยู่ ระบบจะตรวจสอบและสร้างฐานข้อมูลโดยอัตโนมัติหากยังไม่มี

คุณสามารถกำหนดค่าการเชื่อมต่อกับฐานข้อมูลได้ที่ไฟล์ `config/config.go`

4. สร้าง config.yaml (เสริม)

```bash
cp config/config.example.yaml config/config.yaml
```

แก้ไขไฟล์ config.yaml ตามความเหมาะสม

5. รันแอปพลิเคชัน

```bash
# สำหรับการพัฒนา
go run cmd/server/main.go

# หรือใช้ Air สำหรับ hot reload
air
```

## การตั้งค่า Hot Reload (สำหรับการพัฒนา)

ติดตั้ง Air เพื่อใช้ Hot Reload:

```bash
go install github.com/air-verse/air@latest
```

รัน Air ในโฟลเดอร์โปรเจค:

```bash
air
```

## API Endpoints

### การยืนยันตัวตน

| Endpoint | Method | คำอธิบาย |
|----------|--------|----------|
| `/auth/register` | POST | ลงทะเบียนผู้ใช้ใหม่ |
| `/auth/login` | POST | เข้าสู่ระบบ |
| `/auth/refresh` | POST | รีเฟรช access token |
| `/auth/logout` | POST | ออกจากระบบ (ยกเลิก token) |

### การยืนยันตัวตนแบบหลายปัจจัย (MFA)

| Endpoint | Method | คำอธิบาย |
|----------|--------|----------|
| `/auth/mfa/setup` | POST | ตั้งค่า MFA |
| `/auth/mfa/verify` | POST | ยืนยัน MFA |
| `/auth/mfa/disable` | POST | ปิดการใช้งาน MFA |
| `/auth/mfa/backup-codes` | POST | สร้างรหัสสำรอง |

### การจัดการผู้ใช้ (ผู้ดูแลระบบ)

| Endpoint | Method | คำอธิบาย |
|----------|--------|----------|
| `/api/v1/admin/users` | GET | รายการผู้ใช้ทั้งหมด |
| `/api/v1/admin/users` | POST | สร้างผู้ใช้ใหม่ |
| `/api/v1/admin/users/:id` | GET | ข้อมูลผู้ใช้ |
| `/api/v1/admin/users/:id` | PUT | อัปเดตผู้ใช้ |
| `/api/v1/admin/users/:id` | DELETE | ลบผู้ใช้ |
| `/api/v1/admin/users/:id/reset-password` | POST | รีเซ็ตรหัสผ่านผู้ใช้ |
| `/api/v1/admin/roles` | GET | รายการบทบาททั้งหมด |

## ตัวอย่างการใช้งาน API

### ลงทะเบียนผู้ใช้ใหม่

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### เข้าสู่ระบบ

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### ตั้งค่า MFA

```bash
curl -X POST http://localhost:8080/auth/mfa/setup \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## การจัดการผู้ใช้สำหรับผู้ดูแลระบบ

ระบบมีฟีเจอร์การจัดการผู้ใช้สำหรับผู้ดูแลระบบที่สมบูรณ์ ทำให้ผู้ดูแลระบบสามารถ:

1. **ดูรายการผู้ใช้ทั้งหมด**: สามารถค้นหา, กรอง และแบ่งหน้าข้อมูลผู้ใช้
   ```
   GET /api/v1/admin/users?page=1&limit=20&search=คำค้นหา&role=admin
   ```

2. **ดูข้อมูลผู้ใช้เฉพาะราย**:
   ```
   GET /api/v1/admin/users/{user_id}
   ```

3. **สร้างผู้ใช้ใหม่**:
   ```
   POST /api/v1/admin/users
   ```
   ตัวอย่าง payload:
   ```json
   {
     "email": "user@example.com",
     "username": "newuser",
     "password": "securepassword",
     "confirm_password": "securepassword",
     "first_name": "John",
     "last_name": "Doe",
     "roles": ["admin", "user"],
     "is_verified": true
   }
   ```

4. **แก้ไขข้อมูลผู้ใช้**:
   ```
   PUT /api/v1/admin/users/{user_id}
   ```
   ตัวอย่าง payload:
   ```json
   {
     "email": "updated@example.com",
     "username": "updateduser",
     "first_name": "Updated",
     "last_name": "User",
     "roles": ["user"],
     "is_verified": true,
     "is_locked": false
   }
   ```

5. **ลบผู้ใช้**:
   ```
   DELETE /api/v1/admin/users/{user_id}
   ```

6. **รีเซ็ตรหัสผ่านผู้ใช้**:
   ```
   POST /api/v1/admin/users/{user_id}/reset-password
   ```
   ตัวอย่าง payload:
   ```json
   {
     "password": "newpassword123",
     "confirm_password": "newpassword123"
   }
   ```

7. **ดูรายการบทบาททั้งหมด**:
   ```
   GET /api/v1/admin/roles
   ```

## การตั้งค่า Multi-Factor Authentication (MFA)

ระบบรองรับการยืนยันตัวตนแบบหลายปัจจัยโดยใช้ TOTP (Time-based One-Time Password) โดยสามารถกำหนดได้ว่า MFA เป็นตัวเลือกหรือบังคับใช้

### การตั้งค่าบังคับใช้ MFA

ผู้ดูแลระบบสามารถกำหนดให้ผู้ใช้ทุกคนต้องใช้ MFA โดยการตั้งค่าในไฟล์ `config/config.go`:

```go
Auth: AuthConfig{
  // ... ค่าอื่นๆ
  MFARequired: true, // ตั้งเป็น true เพื่อบังคับใช้ MFA กับผู้ใช้ทุกคน
}
```

### การเปิดใช้งาน MFA

1. หลังจากลงทะเบียนและเข้าสู่ระบบแล้ว ต้องเรียกใช้ API เพื่อเปิดใช้งาน MFA:

```
POST /auth/mfa/setup
```

2. ติดตั้งแอปพลิเคชัน Authenticator (เช่น Google Authenticator, Microsoft Authenticator, Authy) บนสมาร์ทโฟน

3. สแกน QR code หรือเพิ่ม secret key ที่ได้รับจากการเรียก API ลงในแอปพลิเคชัน Authenticator

4. ยืนยัน MFA โดยส่ง TOTP code ที่ได้จากแอปพลิเคชัน Authenticator:

```
POST /auth/mfa/verify
```

5. หลังจากยืนยันแล้ว ระบบจะสร้างรหัสสำรอง (Backup Codes) ให้ใช้ในกรณีฉุกเฉินที่ไม่สามารถเข้าถึงแอปพลิเคชัน Authenticator ได้

## ความปลอดภัย

- **การเข้ารหัสข้อมูล**: ข้อมูลที่สำคัญทั้งหมดถูกเข้ารหัสก่อนเก็บในฐานข้อมูล
- **การเข้ารหัสรหัสผ่าน**: ใช้อัลกอริทึม Argon2id ที่ทันสมัยและปลอดภัย
- **JWT Token**: Access Tokens และ Refresh Tokens ปลอดภัย พร้อมระบบหมดอายุอัตโนมัติ
- **MFA**: รองรับการยืนยันตัวตนด้วย TOTP
- **Audit Logging**: บันทึกกิจกรรมที่สำคัญทั้งหมดสำหรับการตรวจสอบภายหลัง
- **Rate Limiting**: ป้องกันการโจมตีแบบ brute force และ DDoS
- **Role-Based Access Control**: ควบคุมการเข้าถึงตามบทบาทและสิทธิ์

## โครงสร้างโปรเจค

```
auth-service/
├── cmd/
│   └── server/           # โค้ดหลักของเซิร์ฟเวอร์
├── config/               # การตั้งค่าต่างๆ
├── internal/
│   ├── api/              # API routes และ handlers
│   ├── auth/             # การยืนยันตัวตนและควบคุมการเข้าถึง
│   ├── controllers/      # ตัวควบคุม HTTP
│   ├── crypto/           # การเข้ารหัสและความปลอดภัย
│   ├── database/         # การเชื่อมต่อฐานข้อมูล
│   ├── logging/          # การบันทึกประวัติ
│   ├── middleware/       # Middleware ต่างๆ
│   └── models/           # โครงสร้างข้อมูล
├── migrations/           # ไฟล์สำหรับการทำ migrations
└── test/                 # ไฟล์ทดสอบ
```

## การนำไปใช้งานในโปรดักชัน

สำหรับการใช้งานจริง ควรพิจารณาต่อไปนี้:

1. **ตั้งค่า Environment Variables**: ใช้ environment variables แทนค่าคงที่ในไฟล์ config
2. **ตั้งค่า HTTPS**: ใช้ HTTPS เสมอในโปรดักชัน (ด้วย reverse proxy หรือโดยตรง)
3. **การกำหนดค่า Trusted Proxies**: กำหนดค่า trusted proxies ที่เหมาะสมหากใช้งานหลัง reverse proxy
4. **การติดตั้ง Monitoring**: เพิ่มระบบ monitoring และ alerting
5. **การตั้งค่า Rate Limits**: ปรับแต่งค่า rate limits ให้เหมาะสมกับปริมาณการใช้งาน

## จัดทำโดย

ทีมพัฒนา Auth Service
