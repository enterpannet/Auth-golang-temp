# คู่มือระบบ Authentication Service

## ขั้นตอนการเริ่มต้นใช้งาน
1. ติดตั้ง dependencies: `go get -u ./...`
2. ตั้งค่าฐานข้อมูล PostgreSQL:
   - ต้องติดตั้ง PostgreSQL เวอร์ชัน 12 ขึ้นไป
   - ระบบจะตรวจสอบและสร้างฐานข้อมูลให้โดยอัตโนมัติ หากยังไม่มี
   - กำหนดค่า PostgreSQL ในไฟล์ `config/config.go` ตามความต้องการ
3. เริ่มต้นเซิร์ฟเวอร์: `go run cmd/server/main.go`
4. เซิร์ฟเวอร์จะทำงานที่ `localhost:8080`

## เทคโนโลยีและเฟรมเวิร์กที่ใช้

### Gin Framework
ระบบใช้ [Gin Framework](https://github.com/gin-gonic/gin) ซึ่งเป็น HTTP web framework ที่มีประสิทธิภาพสูงสำหรับ Go
ด้วยคุณสมบัติดังนี้:
- Performance ที่เร็วกว่า net/http มาตรฐาน
- Middleware ที่หลากหลายและใช้งานง่าย
- การผูกข้อมูล (binding) จาก request ที่มีประสิทธิภาพ
- การจัดการ route ที่มีความยืดหยุ่น

### GORM
ระบบใช้ [GORM](https://gorm.io/) เป็น ORM (Object Relational Mapping) ที่ช่วยในการจัดการฐานข้อมูล
โดยมีคุณสมบัติดังนี้:
- Auto Migration สำหรับสร้างและอัปเดตโครงสร้างฐานข้อมูล
- การทำงานกับ Relation และ Association
- Hooks และ Callbacks สำหรับการจัดการชีวิตของข้อมูล
- Transaction และการจัดการข้อผิดพลาด

## API Endpoints

### การลงทะเบียน (Register)
```
POST /auth/register
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "email": "user@example.com",
  "username": "user123",
  "password": "SecurePassword123!",
  "confirm_password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```
**ข้อมูลที่ได้รับ (Response):**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_at": "2023-05-01T15:00:00Z"
}
```

### การเข้าสู่ระบบ (Login)
```
POST /auth/login
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "totp_code": "123456",
  "remember_me": true
}
```
**ข้อมูลที่ได้รับ (Response):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_at": "2023-05-01T15:00:00Z"
}
```

### การรีเฟรชโทเค็น (Refresh Token)
```
POST /auth/refresh
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "refresh_token": "eyJhbGc..."
}
```
**หรือส่งคุกกี้ `refresh_token` ในการร้องขอ**

**ข้อมูลที่ได้รับ (Response):**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_at": "2023-05-01T15:00:00Z"
}
```

### การออกจากระบบ (Logout)
```
POST /auth/logout
```
**Header ที่ต้องส่ง:** 
```
Authorization: Bearer <access_token>
```

**ข้อมูลที่ได้รับ (Response):**
```json
{
  "success": true
}
```

## การตั้งค่าระบบ
แก้ไขการตั้งค่าได้ที่ไฟล์ `config/config.go` โดยมีการตั้งค่าดังนี้:

### การตั้งค่าพื้นฐาน
- Environment
- Debug mode
- Server configuration
- Database configuration

### การตั้งค่าความปลอดภัย
- JWT Secret Key
- Token Expiry
- CSRF Protection
- Rate Limiting
- Content Security Policy

## ความปลอดภัย
ระบบมีการป้องกันความปลอดภัยดังนี้:

### ป้องกัน CSRF (Cross-Site Request Forgery)
- ใช้ CSRF Token ในฟอร์มและ API

### การป้องกัน Rate Limiting
- จำกัดจำนวนคำขอต่อ IP address
- จำกัดจำนวนการพยายามเข้าสู่ระบบ
- จำกัดจำนวนการลงทะเบียน

### การเข้ารหัส
- เข้ารหัสรหัสผ่านด้วย Argon2id
- การเข้ารหัสข้อมูลสำคัญด้วย AES-GCM

### การยืนยันตัวตนหลายขั้นตอน (MFA)
- รองรับ TOTP (Time-based One-Time Password)
- สร้างรหัสสำรองสำหรับการกู้คืน
- สร้าง QR Code สำหรับแอพ Authenticator

## การเชื่อมต่อกับ OAuth Providers
ระบบรองรับการเข้าสู่ระบบผ่าน:
- Google
- Facebook
- GitHub

### การตั้งค่า OAuth
ตั้งค่า Client ID และ Secret ในไฟล์ `config/config.go`:

```go
OAuthProviders: map[string]OAuthProviderConfig{
    "google": {
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURL:  "http://localhost:8080/auth/callback/google",
        Scopes:       []string{"openid", "profile", "email"},
    },
    // อื่นๆ...
}
```

## การพัฒนาเพิ่มเติม
1. ทำการตั้งค่าฐานข้อมูล PostgreSQL
2. ตั้งค่า JWT Secret ที่ปลอดภัย
3. กำหนดค่า CORS policy และ CSP headers ให้เหมาะสม

## การใช้งาน JWT Token
ส่ง token ในหัว HTTP Header ทุกครั้งที่เรียกใช้ API ที่ต้องการยืนยันตัวตน:
```
Authorization: Bearer <access_token>
```

## การดูแลระบบ
- ระบบมีการบันทึกเหตุการณ์ผ่าน Audit Log
- สามารถตรวจสอบการเข้าถึงระบบได้
- มีการบันทึกเหตุการณ์สำคัญเช่น การเข้าสู่ระบบล้มเหลวหลายครั้ง

## การพัฒนาและขยายระบบ
หากต้องการเพิ่มฟีเจอร์ใหม่ใน API:

1. สร้าง model ใน `internal/models/`
2. เพิ่ม service ใน `internal/auth/service.go`
3. เพิ่ม handler ใน `internal/auth/handlers.go`
4. เพิ่ม route ใน `internal/api/router.go`

ระบบออกแบบให้เพิ่มฟีเจอร์ได้ง่ายโดยการใช้ Gin และ GORM ร่วมกัน

## การตั้งค่า MFA (Multi-Factor Authentication)

ระบบรองรับการยืนยันตัวตนแบบหลายปัจจัยโดยใช้ TOTP (Time-based One-Time Password)

### การเปิดใช้งาน MFA

1. หลังจากลงทะเบียนและเข้าสู่ระบบแล้ว ต้องเรียกใช้ API เพื่อเปิดใช้งาน MFA:

```
POST /auth/mfa/setup
```
**Header ที่ต้องส่ง:** 
```
Authorization: Bearer <access_token>
```

**ข้อมูลที่ได้รับ (Response):**
```json
{
  "secret": "BASE32ENCODEDSECRET",
  "qr_code_url": "otpauth://totp/ExampleService:user@example.com?secret=BASE32ENCODEDSECRET&issuer=ExampleService&algorithm=SHA1&digits=6&period=30"
}
```

2. นำค่า `qr_code_url` ไปสร้าง QR Code หรือใช้ค่า `secret` เพื่อตั้งค่าในแอพฯ Authenticator โดยตรง เช่น:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - หรือแอพฯ ที่รองรับ TOTP อื่นๆ

3. เมื่อตั้งค่าในแอพฯ Authenticator แล้ว จะต้องยืนยันโดยส่งรหัส TOTP ที่ได้จากแอพฯ:

```
POST /auth/mfa/verify
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "totp_code": "123456"
}
```

**ข้อมูลที่ได้รับ (Response):**
```json
{
  "enabled": true,
  "backup_codes": ["ABCD-EFGH-IJKL", "MNOP-QRST-UVWX", ...]
}
```

เก็บรหัสสำรอง (backup_codes) ไว้ในที่ปลอดภัย เพื่อใช้ในกรณีที่ไม่สามารถเข้าถึงอุปกรณ์ที่มีแอพฯ Authenticator

### การใช้งาน MFA เมื่อเข้าสู่ระบบ

1. เมื่อลงชื่อเข้าใช้ด้วยอีเมลและรหัสผ่าน ระบบจะตรวจสอบว่าบัญชีมีการเปิดใช้งาน MFA หรือไม่
2. ถ้าเปิดใช้งาน MFA แล้ว ระบบจะส่งคำตอบกลับมาพร้อมสถานะ `requires_mfa: true`
3. ผู้ใช้จะต้องส่งรหัส TOTP จากแอพฯ Authenticator เพื่อยืนยันตัวตนอีกครั้ง:

```
POST /auth/login
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "totp_code": "123456" 
}
```

รหัส TOTP จะเปลี่ยนทุก 30 วินาที และตัวเลขที่แสดงในแอพฯ Authenticator จะต้องถูกใช้ภายในช่วงเวลาที่กำหนด

### การใช้รหัสสำรอง (Backup Codes)

ในกรณีที่ไม่สามารถเข้าถึงอุปกรณ์ที่มีแอพฯ Authenticator ผู้ใช้สามารถใช้รหัสสำรองที่ได้รับเมื่อตั้งค่า MFA:

```
POST /auth/login
```
**ข้อมูลที่ส่ง (Request Body):**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "recovery_code": "ABCD-EFGH-IJKL"
}
```

แต่ละรหัสสำรองสามารถใช้ได้เพียงครั้งเดียว และควรสร้างรหัสสำรองใหม่หลังจากใช้งาน
