package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/logging"
)

// Common webhook errors
var (
	ErrInvalidSignature      = errors.New("invalid webhook signature")
	ErrUnsupportedPlatform   = errors.New("unsupported social platform")
	ErrMissingConfiguration  = errors.New("missing webhook configuration")
	ErrInvalidPayload        = errors.New("invalid webhook payload")
	ErrWebhookProcessingFail = errors.New("webhook processing failed")
)

// Platform represents supported social media platforms
type Platform string

const (
	PlatformLine     Platform = "line"
	PlatformFacebook Platform = "facebook"
	PlatformTwitter  Platform = "twitter"
	PlatformGoogle   Platform = "google"
	PlatformGithub   Platform = "github"
	PlatformCustom   Platform = "custom"
)

// Event represents webhook event types
type Event string

const (
	EventMessage     Event = "message"
	EventFollow      Event = "follow"
	EventUnfollow    Event = "unfollow"
	EventJoin        Event = "join"
	EventLeave       Event = "leave"
	EventPostback    Event = "postback"
	EventVerify      Event = "verify"
	EventSubscribe   Event = "subscribe"
	EventUnsubscribe Event = "unsubscribe"
	EventCustom      Event = "custom"
)

// Handler defines the webhook handler interface
type Handler interface {
	HandleEvent(payload []byte, platform Platform, event Event) error
}

// WebhookService handles webhook operations
type WebhookService struct {
	Config      *config.Config
	AuditLogger *logging.AuditLogger
	Handlers    map[Platform]map[Event][]Handler
}

// WebhookConfig contains configuration for a specific platform
type WebhookConfig struct {
	Secret          string
	VerifyToken     string
	SignatureHeader string
	EventTypeKey    string
	Enabled         bool
}

// NewWebhookService creates a new webhook service
func NewWebhookService(cfg *config.Config, auditLogger *logging.AuditLogger) *WebhookService {
	return &WebhookService{
		Config:      cfg,
		AuditLogger: auditLogger,
		Handlers:    make(map[Platform]map[Event][]Handler),
	}
}

// RegisterHandler registers a handler for a specific platform and event
func (s *WebhookService) RegisterHandler(platform Platform, event Event, handler Handler) {
	if _, exists := s.Handlers[platform]; !exists {
		s.Handlers[platform] = make(map[Event][]Handler)
	}

	s.Handlers[platform][event] = append(s.Handlers[platform][event], handler)
}

// GetPlatformConfig returns the configuration for a specific platform
func (s *WebhookService) GetPlatformConfig(platform Platform) (*WebhookConfig, error) {
	switch platform {
	case PlatformLine:
		return &WebhookConfig{
			Secret:          s.Config.Webhook.Line.ChannelSecret,
			SignatureHeader: "X-Line-Signature",
			EventTypeKey:    "type",
			Enabled:         s.Config.Webhook.Line.Enabled,
		}, nil
	case PlatformFacebook:
		return &WebhookConfig{
			Secret:          s.Config.Webhook.Facebook.AppSecret,
			VerifyToken:     s.Config.Webhook.Facebook.VerifyToken,
			SignatureHeader: "X-Hub-Signature-256",
			EventTypeKey:    "object",
			Enabled:         s.Config.Webhook.Facebook.Enabled,
		}, nil
	case PlatformTwitter:
		return &WebhookConfig{
			Secret:          s.Config.Webhook.Twitter.ConsumerSecret,
			SignatureHeader: "X-Twitter-Webhooks-Signature",
			EventTypeKey:    "for_user_id",
			Enabled:         s.Config.Webhook.Twitter.Enabled,
		}, nil
	default:
		return nil, ErrUnsupportedPlatform
	}
}

// ValidateWebhook validates the webhook request signature
func (s *WebhookService) ValidateWebhook(r *http.Request, platform Platform) (bool, error) {
	cfg, err := s.GetPlatformConfig(platform)
	if err != nil {
		return false, err
	}

	if !cfg.Enabled {
		return false, ErrMissingConfiguration
	}

	// For Facebook verification challenge
	if platform == PlatformFacebook && r.Method == "GET" {
		mode := r.URL.Query().Get("hub.mode")
		token := r.URL.Query().Get("hub.verify_token")

		if mode == "subscribe" && token == cfg.VerifyToken {
			return true, nil
		}
		return false, ErrInvalidSignature
	}

	// For other platforms, validate signature
	signature := r.Header.Get(cfg.SignatureHeader)
	if signature == "" {
		return false, ErrInvalidSignature
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}

	// Restore body for subsequent reads
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	// Validate signature based on platform
	switch platform {
	case PlatformLine:
		// LINE uses base64 encoded HMAC-SHA256
		decodedSignature, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return false, err
		}

		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(body)
		expectedMAC := mac.Sum(nil)

		return hmac.Equal(decodedSignature, expectedMAC), nil

	case PlatformFacebook:
		// Facebook uses sha256=HMAC-SHA256 format
		if !strings.HasPrefix(signature, "sha256=") {
			return false, ErrInvalidSignature
		}

		signatureParts := strings.Split(signature, "=")
		if len(signatureParts) != 2 {
			return false, ErrInvalidSignature
		}

		providedSignature, err := hex.DecodeString(signatureParts[1])
		if err != nil {
			return false, err
		}

		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		mac.Write(body)
		expectedMAC := mac.Sum(nil)

		return hmac.Equal(providedSignature, expectedMAC), nil

	default:
		return false, ErrUnsupportedPlatform
	}
}

// HandleWebhook processes a webhook request
func (s *WebhookService) HandleWebhook(w http.ResponseWriter, r *http.Request, platform Platform) {
	// For Facebook verification challenge
	if platform == PlatformFacebook && r.Method == "GET" {
		cfg, err := s.GetPlatformConfig(platform)
		if err != nil {
			http.Error(w, "Unsupported platform", http.StatusBadRequest)
			return
		}

		mode := r.URL.Query().Get("hub.mode")
		token := r.URL.Query().Get("hub.verify_token")
		challenge := r.URL.Query().Get("hub.challenge")

		if mode == "subscribe" && token == cfg.VerifyToken {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(challenge))
			return
		}

		http.Error(w, "Invalid verification token", http.StatusUnauthorized)
		return
	}

	// Validate signature
	valid, err := s.ValidateWebhook(r, platform)
	if err != nil || !valid {
		s.logWebhookAttempt(r, platform, "", false, "Invalid signature")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Read and process payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logWebhookAttempt(r, platform, "", false, "Failed to read request body")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Extract event type
	event, err := s.extractEventType(body, platform)
	if err != nil {
		s.logWebhookAttempt(r, platform, string(event), false, "Failed to extract event type")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Process the webhook with registered handlers
	err = s.processWebhook(body, platform, Event(event))
	if err != nil {
		s.logWebhookAttempt(r, platform, string(event), false, fmt.Sprintf("Processing failed: %v", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Log successful webhook
	s.logWebhookAttempt(r, platform, string(event), true, "Success")

	// Return success
	w.WriteHeader(http.StatusOK)
}

// extractEventType extracts the event type from the payload based on platform
func (s *WebhookService) extractEventType(payload []byte, platform Platform) (string, error) {
	cfg, err := s.GetPlatformConfig(platform)
	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return "", ErrInvalidPayload
	}

	switch platform {
	case PlatformLine:
		// LINE typically has an events array
		events, ok := data["events"].([]interface{})
		if !ok || len(events) == 0 {
			return "", ErrInvalidPayload
		}

		firstEvent, ok := events[0].(map[string]interface{})
		if !ok {
			return "", ErrInvalidPayload
		}

		eventType, ok := firstEvent[cfg.EventTypeKey].(string)
		if !ok {
			return "", ErrInvalidPayload
		}

		return eventType, nil

	case PlatformFacebook:
		// Extract the object type (usually "page")
		object, ok := data[cfg.EventTypeKey].(string)
		if !ok {
			return "", ErrInvalidPayload
		}

		// Check for entries
		entries, ok := data["entry"].([]interface{})
		if !ok || len(entries) == 0 {
			return "", ErrInvalidPayload
		}

		return object, nil

	default:
		return "custom", nil
	}
}

// processWebhook processes the webhook with registered handlers
func (s *WebhookService) processWebhook(payload []byte, platform Platform, event Event) error {
	// Get handlers for this platform and event
	platformHandlers, ok := s.Handlers[platform]
	if !ok {
		// No handlers for this platform
		return nil
	}

	// Get specific event handlers
	eventHandlers, ok := platformHandlers[event]
	if !ok {
		// Try fallback to custom event handlers
		eventHandlers, ok = platformHandlers[EventCustom]
		if !ok {
			// No handlers for this event
			return nil
		}
	}

	// Execute all handlers
	for _, handler := range eventHandlers {
		if err := handler.HandleEvent(payload, platform, event); err != nil {
			return err
		}
	}

	return nil
}

// logWebhookAttempt logs webhook attempt to audit log
func (s *WebhookService) logWebhookAttempt(r *http.Request, platform Platform, event string, success bool, description string) {
	// Skip if audit logging is disabled
	if s.AuditLogger == nil {
		return
	}

	// Create audit event
	s.AuditLogger.Log(r.Context(), logging.AuditEvent{
		Action:      "webhook_received",
		Resource:    string(platform),
		ResourceID:  event,
		ClientIP:    getClientIP(r),
		UserAgent:   r.UserAgent(),
		Success:     success,
		Description: description,
	})
}

// Helper function to get client IP from request
func getClientIP(r *http.Request) string {
	// Try to get IP from X-Forwarded-For header
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	// Try to get IP from X-Real-IP header
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

// LineMessageHandler is a sample implementation of a LINE webhook handler
type LineMessageHandler struct {
	// Add dependencies here
}

// HandleEvent processes LINE webhook events
func (h *LineMessageHandler) HandleEvent(payload []byte, platform Platform, event Event) error {
	// Process LINE webhook
	// This is just an example implementation
	var lineEvent struct {
		Events []struct {
			Type       string `json:"type"`
			ReplyToken string `json:"replyToken,omitempty"`
			Source     struct {
				UserID string `json:"userId,omitempty"`
			} `json:"source"`
			Message struct {
				Type string `json:"type"`
				Text string `json:"text,omitempty"`
			} `json:"message,omitempty"`
		} `json:"events"`
	}

	if err := json.Unmarshal(payload, &lineEvent); err != nil {
		return err
	}

	// Process each event
	for _, e := range lineEvent.Events {
		// Handle based on event type
		switch e.Type {
		case "message":
			// Handle message
			if e.Message.Type == "text" {
				// Process text message
				// You would implement your business logic here
			}
		case "follow":
			// Handle follow event (user added the bot)
		case "unfollow":
			// Handle unfollow event (user blocked the bot)
		}
	}

	return nil
}

// FacebookMessageHandler is a sample implementation of a Facebook webhook handler
type FacebookMessageHandler struct {
	// Add dependencies here
}

// HandleEvent processes Facebook webhook events
func (h *FacebookMessageHandler) HandleEvent(payload []byte, platform Platform, event Event) error {
	// Process Facebook webhook
	// This is just an example implementation
	var fbEvent struct {
		Object string `json:"object"`
		Entry  []struct {
			ID        string `json:"id"`
			Time      int64  `json:"time"`
			Messaging []struct {
				Sender struct {
					ID string `json:"id"`
				} `json:"sender"`
				Recipient struct {
					ID string `json:"id"`
				} `json:"recipient"`
				Timestamp int64 `json:"timestamp"`
				Message   struct {
					Mid  string `json:"mid"`
					Text string `json:"text,omitempty"`
				} `json:"message,omitempty"`
				Postback struct {
					Title   string `json:"title,omitempty"`
					Payload string `json:"payload,omitempty"`
				} `json:"postback,omitempty"`
			} `json:"messaging,omitempty"`
		} `json:"entry"`
	}

	if err := json.Unmarshal(payload, &fbEvent); err != nil {
		return err
	}

	// Process each entry
	for _, entry := range fbEvent.Entry {
		// Process each messaging event
		for _, messaging := range entry.Messaging {
			// Check if it's a message
			if messaging.Message.Text != "" {
				// Process text message
				// You would implement your business logic here
			}

			// Check if it's a postback
			if messaging.Postback.Payload != "" {
				// Process postback
				// You would implement your business logic here
			}
		}
	}

	return nil
}
