## การตั้งค่า MFA (Multi-Factor Authentication)

ระบบรองรับการยืนยันตัวตนแบบหลายปัจจัยโดยใช้ TOTP (Time-based One-Time Password) โดยสามารถกำหนดได้ว่า MFA เป็นตัวเลือกหรือบังคับใช้

### การตั้งค่าบังคับใช้ MFA

ผู้ดูแลระบบสามารถกำหนดให้ผู้ใช้ทุกคนต้องใช้ MFA โดยการตั้งค่าในไฟล์ `config/config.go`:

```go
Auth: AuthConfig{
  // ... ค่าอื่นๆ
  MFARequired: true, // ตั้งเป็น true เพื่อบังคับใช้ MFA กับผู้ใช้ทุกคน
}
```

เมื่อตั้งค่า `MFARequired` เป็น `true` ผู้ใช้ทุกคนจะต้องตั้งค่า MFA เมื่อเข้าสู่ระบบครั้งแรก และจะต้องใช้ TOTP code ในการเข้าสู่ระบบครั้งต่อไปเสมอ

หากตั้งค่า `MFARequired` เป็น `false` (ค่าเริ่มต้น) ผู้ใช้สามารถเลือกได้ว่าจะเปิดใช้งาน MFA หรือไม่

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

# การตั้งค่าการยืนยันอีเมล (Email Verification)

ระบบการยืนยันอีเมลถูกใช้เพื่อตรวจสอบว่าผู้ใช้เป็นเจ้าของอีเมลที่ได้ลงทะเบียนไว้ โดยการส่งอีเมลที่มีลิงก์พิเศษไปยังที่อยู่อีเมลที่ผู้ใช้ให้ไว้

## การตั้งค่า

1. ตรวจสอบให้แน่ใจว่าการตั้งค่าเมลเซิร์ฟเวอร์ในไฟล์ `config/config.go` มีการตั้งค่าที่ถูกต้อง:

```go
Mail: MailConfig{
    Enabled:       true,
    Host:          "smtp.example.com",   // ใส่โฮสต์ SMTP ของคุณ
    Port:          587,                  // พอร์ตของเซิร์ฟเวอร์ SMTP
    Username:      "your-username",      // ชื่อผู้ใช้สำหรับการรับรองความถูกต้อง SMTP
    Password:      "your-password",      // รหัสผ่านสำหรับการรับรองความถูกต้อง SMTP
    FromEmail:     "noreply@example.com", // ที่อยู่อีเมลที่จะแสดงในฟิลด์ "From"
    FromName:      "Auth Service",       // ชื่อที่จะแสดงในฟิลด์ "From"
    UseSSL:        false,
    UseTLS:        true,
    TemplatesPath: "templates/email",    // เส้นทางไปยังเทมเพลตอีเมล
},
```

2. ตรวจสอบการตั้งค่าการยืนยันอีเมลในส่วน `Auth` ของการกำหนดค่า:

```go
Auth: AuthConfig{
    // ...
    VerificationRequired:    true,          // ตั้งเป็น 'false' ถ้าไม่ต้องการให้บังคับยืนยันอีเมล
    VerificationTokenExpiry: 24 * time.Hour, // ระยะเวลาหมดอายุของโทเค็นการยืนยัน
    VerificationRedirectURL: "http://localhost:3000/verification-success", // URL สำหรับเปลี่ยนเส้นทางหลังจากยืนยันสำเร็จ
    // ...
},
```

## เทมเพลตอีเมล

วางเทมเพลตอีเมลของคุณในไดเรกทอรี `templates/email/` ระบบรองรับเทมเพลต HTML ที่ใช้ Go template syntax:

- `verification.html` - เทมเพลตสำหรับอีเมลยืนยัน

## เวิร์กโฟลว์การยืนยันอีเมล

1. เมื่อผู้ใช้ลงทะเบียน ระบบจะสร้างโทเค็นการยืนยันและส่งอีเมลไปยังที่อยู่อีเมลที่ผู้ใช้ให้ไว้
2. อีเมลประกอบด้วยลิงก์ที่มีโทเค็นการยืนยัน: `https://your-domain.com/api/v1/auth/verify-email?token=TOKEN`
3. เมื่อผู้ใช้คลิกลิงก์ ระบบจะตรวจสอบโทเค็นและอัปเดตสถานะการยืนยันอีเมลของผู้ใช้
4. จากนั้นผู้ใช้จะถูกเปลี่ยนเส้นทางไปยัง URL ที่ระบุใน `VerificationRedirectURL`

## การส่งอีเมลยืนยันใหม่

หากผู้ใช้ไม่ได้รับอีเมลยืนยันหรือโทเค็นหมดอายุ พวกเขาสามารถขอให้ส่งใหม่ได้:

```
GET /api/v1/auth/resend-verification
Authorization: Bearer YOUR_ACCESS_TOKEN
```

## การตรวจสอบสถานะการยืนยันอีเมล

ข้อมูลสถานะการยืนยันอีเมลจะถูกรวมอยู่ในโทเค็น JWT ที่ส่งไปยังไคลเอนต์ในคำตอบการเข้าสู่ระบบ ตรวจสอบคำอ้างสิทธิ์ `email_verified` ในโทเค็น JWT เพื่อตรวจสอบสถานะการยืนยัน

หากการตั้งค่า `VerificationRequired` เป็น `true` บางจุดสิ้นสุด API อาจต้องการให้ยืนยันอีเมลก่อนที่จะอนุญาตให้เข้าถึง ซึ่งจะส่งคืนข้อผิดพลาด `ErrEmailNotVerified` 

# คู่มือการตั้งค่า Email Service

การตั้งค่าเมลเซิร์ฟเวอร์และการสร้างไดเรกทอรีเทมเพลต:

1. ตรวจสอบให้แน่ใจว่าคุณได้สร้างไดเรกทอรีเทมเพลตสำหรับอีเมล:

```bash
mkdir -p templates/email
```

2. วางเทมเพลต HTML ในไดเรกทอรีนี้:
   - `verification.html` - สำหรับอีเมลยืนยัน
   - `password-reset.html` - สำหรับอีเมลรีเซ็ตรหัสผ่าน

3. ตรวจสอบการตั้งค่าในไฟล์ `config/config.go` ในส่วน `Mail`:

```go
Mail: MailConfig{
    Enabled:       true,                    // ตั้งค่าเป็น false ถ้าคุณไม่ต้องการเปิดใช้งานการส่งอีเมล
    Host:          "smtp.example.com",      // เปลี่ยนเป็นเซิร์ฟเวอร์ SMTP ของคุณ
    Port:          587,                     // พอร์ต SMTP
    Username:      "your-username",         // ชื่อผู้ใช้ SMTP
    Password:      "your-password",         // รหัสผ่าน SMTP
    FromEmail:     "noreply@example.com",   // อีเมลสำหรับส่ง
    FromName:      "Auth Service",          // ชื่อที่แสดงในอีเมล
    UseSSL:        false,                   // ใช้ SSL หรือไม่
    UseTLS:        true,                    // ใช้ TLS หรือไม่
    TemplatesPath: "templates/email",       // เส้นทางไปยังไดเรกทอรีเทมเพลต
},
```

## การทดสอบ

ทำการลงทะเบียนผู้ใช้ใหม่ใน API และตรวจสอบบันทึกเซิร์ฟเวอร์ว่ามีการส่งอีเมล:

1. สมัครสมาชิกใหม่:

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
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

2. ตรวจสอบบันทึกเซิร์ฟเวอร์เพื่อดูว่าอีเมลถูกส่งหรือไม่

3. หากคุณต้องการทดสอบการยืนยันอีเมล คุณสามารถใช้โทเค็นการยืนยันที่ได้จากบันทึก:

```bash
curl -X GET "http://localhost:8080/api/v1/auth/verify-email?token=YOUR_TOKEN"
```

4. ทดสอบการส่งอีเมลยืนยันใหม่ (เฉพาะผู้ใช้ที่ยังไม่ได้ยืนยันอีเมล):

```bash
curl -X GET http://localhost:8080/api/v1/auth/resend-verification \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## การแก้ไขปัญหา

1. **ไม่สามารถส่งอีเมล**:
   - ตรวจสอบการตั้งค่า SMTP ให้ถูกต้อง
   - ตรวจสอบว่าพอร์ต SMTP ไม่ได้ถูกบล็อกโดยไฟร์วอลล์
   - ตรวจสอบบันทึกเซิร์ฟเวอร์เพื่อดูข้อความข้อผิดพลาด

2. **ไม่พบเทมเพลตอีเมล**:
   - ตรวจสอบว่าไดเรกทอรี `templates/email` ถูกสร้างขึ้นและมีเทมเพลตอยู่
   - ตรวจสอบว่า `TemplatesPath` ใน `config.go` ชี้ไปที่ไดเรกทอรีที่ถูกต้อง 