# คู่มือการใช้งาน Webhook สำหรับ Social Media

## ภาพรวม

ระบบ Webhook คือ ฟีเจอร์ที่ช่วยให้แอปพลิเคชันของคุณสามารถรับและประมวลผลข้อมูลแบบเรียลไทม์จากแพลตฟอร์มโซเชียลมีเดียต่างๆ เช่น Line, Facebook, Twitter และอื่นๆ เมื่อมีเหตุการณ์เกิดขึ้นบนแพลตฟอร์มเหล่านั้น (เช่น มีข้อความใหม่, มีผู้ติดตามใหม่) ระบบจะส่งข้อมูลเหตุการณ์มายัง Endpoint ที่คุณกำหนดไว้

## การตั้งค่า

### 1. การกำหนดค่าในไฟล์ config.go

เริ่มต้นโดยการกำหนดค่าต่างๆ ในไฟล์ config.go:

```yaml
webhook:
  line:
    enabled: true
    channel_id: "YOUR_LINE_CHANNEL_ID"
    channel_secret: "YOUR_LINE_CHANNEL_SECRET"
    callback_url: "https://your-domain.com/webhooks/line"
  
  facebook:
    enabled: true
    app_id: "YOUR_FB_APP_ID"
    app_secret: "YOUR_FB_APP_SECRET"
    verify_token: "YOUR_CUSTOM_VERIFY_TOKEN"
    callback_url: "https://your-domain.com/webhooks/facebook"
  
  twitter:
    enabled: false
    consumer_key: "YOUR_TWITTER_CONSUMER_KEY"
    consumer_secret: "YOUR_TWITTER_CONSUMER_SECRET"
    access_token: "YOUR_TWITTER_ACCESS_TOKEN"
    access_token_secret: "YOUR_TWITTER_ACCESS_TOKEN_SECRET"
    callback_url: "https://your-domain.com/webhooks/twitter"
```

### 2. สร้าง Handler สำหรับแพลตฟอร์มต่างๆ

สร้าง Handler ที่ implement interface `webhook.Handler` สำหรับแต่ละแพลตฟอร์มที่คุณต้องการใช้งาน:

```go
type MyLineHandler struct {
    // ใส่ dependencies ที่จำเป็น เช่น database, service ต่างๆ
}

func (h *MyLineHandler) HandleEvent(payload []byte, platform webhook.Platform, event webhook.Event) error {
    // ทำการประมวลผลข้อมูลจาก Line
    // ตัวอย่างเช่น ตอบกลับข้อความอัตโนมัติ, บันทึกข้อมูลผู้ใช้, ฯลฯ
    return nil
}
```

### 3. ลงทะเบียน Handler กับ WebhookService

เพิ่มการลงทะเบียน Handler ในไฟล์ main.go หรือที่ๆ คุณตั้งค่าเริ่มต้นระบบ:

```go
// สร้าง webhook service
webhookService := webhook.NewWebhookService(cfg, auditLogger)

// ลงทะเบียน handler สำหรับแต่ละแพลตฟอร์มและแต่ละประเภทเหตุการณ์
lineHandler := &MyLineHandler{}
webhookService.RegisterHandler(webhook.PlatformLine, webhook.EventMessage, lineHandler)
webhookService.RegisterHandler(webhook.PlatformLine, webhook.EventFollow, lineHandler)

// สำหรับ Facebook
fbHandler := &MyFacebookHandler{}
webhookService.RegisterHandler(webhook.PlatformFacebook, webhook.EventMessage, fbHandler)
```

### 4. สร้าง Endpoint สำหรับรับ Webhook

สร้าง API Endpoint สำหรับรับ Webhook ในไฟล์ router.go:

```go
// ในโค้ดของ Router.Setup()
// สร้าง endpoint สำหรับ webhook
webhooks := router.Group("/webhooks")
{
    webhooks.POST("/line", func(c *gin.Context) {
        webhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformLine)
    })
    
    // Facebook ต้องรองรับทั้ง GET (สำหรับการยืนยัน) และ POST (สำหรับรับเหตุการณ์)
    webhooks.Any("/facebook", func(c *gin.Context) {
        webhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformFacebook)
    })
    
    webhooks.POST("/twitter", func(c *gin.Context) {
        webhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformTwitter)
    })
}
```

## การตั้งค่าบนแพลตฟอร์มโซเชียลมีเดีย

### LINE

1. เข้าไปที่ [LINE Developers Console](https://developers.line.biz/console/)
2. สร้าง Provider และ Channel (Messaging API)
3. ในส่วน "Messaging API" ให้กำหนด Webhook URL เป็น `https://your-domain.com/webhooks/line`
4. เปิดใช้งาน "Use webhook" และปิด "Auto-reply messages" ถ้าคุณต้องการควบคุมการตอบกลับเอง
5. บันทึก Channel ID และ Channel Secret ไว้ในไฟล์ config ของคุณ

### Facebook

1. เข้าไปที่ [Facebook for Developers](https://developers.facebook.com/)
2. สร้าง App ใหม่ และเลือกประเภท "Business"
3. ไปที่ "Settings" > "Basic" และบันทึก App ID และ App Secret
4. ไปที่ "Products" และเพิ่ม "Messenger"
5. ในส่วน "Webhooks" ให้คลิก "Setup Webhooks"
6. กรอก:
   - Callback URL: `https://your-domain.com/webhooks/facebook`
   - Verify Token: ข้อความที่คุณกำหนดเองในไฟล์ config (verify_token)
   - เลือก Subscription Fields ที่ต้องการ เช่น messages, messaging_postbacks
7. คลิก "Verify and Save"

### Twitter

1. เข้าไปที่ [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard)
2. สร้าง Project และ App
3. สร้าง Consumer Key และ Access Token
4. ไปที่ "Account Activity API" / "Premium"
5. ลงทะเบียน Webhook URL: `https://your-domain.com/webhooks/twitter`
6. เปิดใช้งาน Subscriptions สำหรับบัญชีที่ต้องการ

## ตัวอย่างการใช้งาน

### การตอบกลับข้อความอัตโนมัติใน LINE

```go
func (h *MyLineHandler) HandleEvent(payload []byte, platform webhook.Platform, event webhook.Event) error {
    // แปลงข้อมูล Payload เป็นโครงสร้างที่เข้าใจได้
    var lineEvent struct {
        Events []struct {
            Type       string `json:"type"`
            ReplyToken string `json:"replyToken"`
            Source     struct {
                UserID string `json:"userId"`
            } `json:"source"`
            Message struct {
                Type string `json:"type"`
                Text string `json:"text"`
            } `json:"message"`
        } `json:"events"`
    }
    
    if err := json.Unmarshal(payload, &lineEvent); err != nil {
        return err
    }
    
    // ประมวลผลแต่ละเหตุการณ์
    for _, e := range lineEvent.Events {
        if e.Type == "message" && e.Message.Type == "text" {
            // ทำการตอบกลับข้อความ
            replyText := "ขอบคุณสำหรับข้อความ: " + e.Message.Text
            
            // ส่งคำตอบกลับไปยัง LINE Platform
            err := h.lineService.SendReply(e.ReplyToken, replyText)
            if err != nil {
                return err
            }
        }
    }
    
    return nil
}
```

### การบันทึกผู้ใช้ใหม่จาก Facebook

```go
func (h *MyFacebookHandler) HandleEvent(payload []byte, platform webhook.Platform, event webhook.Event) error {
    var fbEvent struct {
        Object string `json:"object"`
        Entry  []struct {
            Messaging []struct {
                Sender struct {
                    ID string `json:"id"`
                } `json:"sender"`
                Message struct {
                    Text string `json:"text"`
                } `json:"message"`
            } `json:"messaging"`
        } `json:"entry"`
    }
    
    if err := json.Unmarshal(payload, &fbEvent); err != nil {
        return err
    }
    
    // ประมวลผลข้อมูล
    for _, entry := range fbEvent.Entry {
        for _, messaging := range entry.Messaging {
            // บันทึกหรืออัปเดตข้อมูลผู้ใช้
            userID := messaging.Sender.ID
            err := h.userService.CreateOrUpdateSocialUser("facebook", userID)
            if err != nil {
                return err
            }
            
            // ตอบกลับข้อความ
            if messaging.Message.Text != "" {
                err = h.fbService.SendMessage(userID, "ขอบคุณสำหรับข้อความของคุณ!")
                if err != nil {
                    return err
                }
            }
        }
    }
    
    return nil
}
```

## ข้อควรระวังและการแก้ไขปัญหา

1. **ความปลอดภัย**: ตรวจสอบ Signature ทุกครั้งเพื่อยืนยันว่าข้อมูลมาจากแพลตฟอร์มจริง (มีการตรวจสอบโดยอัตโนมัติในโค้ด)

2. **HTTPS**: Webhook URL ต้องใช้ HTTPS เท่านั้น (ยกเว้นเมื่อทดสอบในเครื่องท้องถิ่น)

3. **การตอบกลับทันที**: Webhook ควรตอบกลับด้วย HTTP 200 โดยเร็ว (ภายใน 3-5 วินาที) เพื่อไม่ให้แพลตฟอร์มคิดว่ามีข้อผิดพลาด

4. **Idempotency**: ออกแบบ Handler ให้ Idempotent (ทำงานซ้ำได้โดยไม่มีผลกระทบ) เพราะแพลตฟอร์มอาจส่ง Webhook ซ้ำในบางกรณี

5. **การทดสอบ**:
   - ใช้ [ngrok](https://ngrok.com/) เพื่อทดสอบ Webhook บนเครื่องท้องถิ่น
   - ใช้เครื่องมือจำลอง Webhook ของแต่ละแพลตฟอร์มเพื่อทดสอบ

6. **การแก้ไขปัญหา**:
   - ตรวจสอบ Log เพื่อดูข้อผิดพลาด
   - ตรวจสอบว่า Signature Header ถูกส่งมาและตรงกัน
   - ตรวจสอบรูปแบบ Payload ว่าตรงกับที่คาดหวัง

## ตัวอย่างโครงสร้างข้อมูล Webhook

### LINE

```json
{
  "destination": "xxxxxxxxxx",
  "events": [
    {
      "replyToken": "nHuyWiB7yP5Zw52FIkcQobQuGDXCTA",
      "type": "message",
      "mode": "active",
      "timestamp": 1462629479859,
      "source": {
        "type": "user",
        "userId": "U4af4980629..."
      },
      "message": {
        "id": "325708",
        "type": "text",
        "text": "Hello, world!"
      }
    }
  ]
}
```

### Facebook

```json
{
  "object": "page",
  "entry": [
    {
      "id": "PAGE_ID",
      "time": 1458692752478,
      "messaging": [
        {
          "sender": {
            "id": "USER_ID"
          },
          "recipient": {
            "id": "PAGE_ID"
          },
          "timestamp": 1458692752478,
          "message": {
            "mid": "mid.1457764197618:41d102a3e1ae206a38",
            "text": "hello, world!",
            "quick_reply": {
              "payload": "DEVELOPER_DEFINED_PAYLOAD"
            }
          }
        }
      ]
    }
  ]
}
```

## สรุป

การใช้งาน Webhook ช่วยให้แอปพลิเคชันของคุณสามารถเชื่อมต่อกับแพลตฟอร์มโซเชียลมีเดียต่างๆ ได้แบบเรียลไทม์ เพื่อสร้างประสบการณ์ที่ดีให้กับผู้ใช้งาน อย่าลืมว่าแต่ละแพลตฟอร์มมีรูปแบบและข้อกำหนดเฉพาะ ดังนั้นควรศึกษาเอกสารอ้างอิงของแต่ละแพลตฟอร์มเพิ่มเติม

## เอกสารอ้างอิง

- [LINE Messaging API](https://developers.line.biz/en/docs/messaging-api/)
- [Facebook Messenger Platform](https://developers.facebook.com/docs/messenger-platform)
- [Twitter API Documentation](https://developer.twitter.com/en/docs) 