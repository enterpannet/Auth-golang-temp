package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/models"
	"gorm.io/gorm"
)

// AuditLogger handles audit logging operations
type AuditLogger struct {
	DB     *gorm.DB
	Config *config.Config
	File   *os.File
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(db *gorm.DB, cfg *config.Config) (*AuditLogger, error) {
	var file *os.File
	var err error

	// If audit logging to file is enabled, open the file
	if cfg.Audit.Enabled && cfg.Audit.File != "" && cfg.Audit.Output == "file" {
		// Ensure directory exists
		dir := cfg.Audit.File
		if err = os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create audit log directory: %w", err)
		}

		// Open file in append mode
		file, err = os.OpenFile(
			fmt.Sprintf("%s/audit_%s.log", dir, time.Now().Format("2006-01-02")),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
	}

	return &AuditLogger{
		DB:     db,
		Config: cfg,
		File:   file,
	}, nil
}

// Close closes the audit logger
func (a *AuditLogger) Close() error {
	if a.File != nil {
		return a.File.Close()
	}
	return nil
}

// AuditEvent represents a security event to be logged
type AuditEvent struct {
	UserID      string      `json:"user_id,omitempty"`
	Action      string      `json:"action"`
	Resource    string      `json:"resource"`
	ResourceID  string      `json:"resource_id,omitempty"`
	OldValue    interface{} `json:"old_value,omitempty"`
	NewValue    interface{} `json:"new_value,omitempty"`
	ClientIP    string      `json:"client_ip,omitempty"`
	UserAgent   string      `json:"user_agent,omitempty"`
	Success     bool        `json:"success"`
	Description string      `json:"description,omitempty"`
}

// Log logs an audit event to both the database and file if configured
func (a *AuditLogger) Log(ctx context.Context, event AuditEvent) error {
	// Check if audit logging is enabled
	if !a.Config.Audit.Enabled {
		return nil
	}

	// Convert complex old/new values to JSON
	var oldValueStr, newValueStr string
	if event.OldValue != nil {
		oldBytes, err := json.Marshal(event.OldValue)
		if err == nil {
			oldValueStr = string(oldBytes)
		}
	}
	if event.NewValue != nil {
		newBytes, err := json.Marshal(event.NewValue)
		if err == nil {
			newValueStr = string(newBytes)
		}
	}

	// Create the audit log entry
	auditLog := models.AuditLog{
		UserID:      event.UserID,
		Action:      event.Action,
		Resource:    event.Resource,
		ResourceID:  event.ResourceID,
		OldValue:    oldValueStr,
		NewValue:    newValueStr,
		ClientIP:    event.ClientIP,
		UserAgent:   event.UserAgent,
		Timestamp:   time.Now(),
		Success:     event.Success,
		Description: event.Description,
	}

	// Log to database
	if err := a.DB.Create(&auditLog).Error; err != nil {
		return fmt.Errorf("failed to create audit log in database: %w", err)
	}

	// Log to file if configured
	if a.File != nil {
		// Format the log entry as JSON
		logEntry, err := json.Marshal(map[string]interface{}{
			"id":          auditLog.ID,
			"timestamp":   auditLog.Timestamp,
			"user_id":     auditLog.UserID,
			"action":      auditLog.Action,
			"resource":    auditLog.Resource,
			"resource_id": auditLog.ResourceID,
			"old_value":   auditLog.OldValue,
			"new_value":   auditLog.NewValue,
			"client_ip":   auditLog.ClientIP,
			"user_agent":  auditLog.UserAgent,
			"success":     auditLog.Success,
			"description": auditLog.Description,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal audit log for file: %w", err)
		}

		// Write to file
		if _, err := a.File.Write(append(logEntry, '\n')); err != nil {
			return fmt.Errorf("failed to write audit log to file: %w", err)
		}
	}

	return nil
}

// LogFromRequest logs an audit event from HTTP request context
func (a *AuditLogger) LogFromRequest(r *http.Request, action, resource, resourceID string, success bool, description string, oldValue, newValue interface{}) error {
	// Extract user ID from context (assumed to be set by auth middleware)
	userID := getUserIDFromContext(r.Context())

	// Create audit event
	event := AuditEvent{
		UserID:      userID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		OldValue:    oldValue,
		NewValue:    newValue,
		ClientIP:    getClientIP(r),
		UserAgent:   r.UserAgent(),
		Success:     success,
		Description: description,
	}

	return a.Log(r.Context(), event)
}

// LogLogin logs a login attempt
func (a *AuditLogger) LogLogin(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "login",
		Resource:    "auth",
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// LogLogout logs a logout
func (a *AuditLogger) LogLogout(ctx context.Context, userID, clientIP, userAgent string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "logout",
		Resource:    "auth",
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     true,
		Description: "User logged out",
	})
}

// LogTokenRefresh logs a token refresh
func (a *AuditLogger) LogTokenRefresh(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "token_refresh",
		Resource:    "auth",
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// LogPasswordReset logs a password reset
func (a *AuditLogger) LogPasswordReset(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "password_reset",
		Resource:    "user",
		ResourceID:  userID,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// LogPasswordChange logs a password change
func (a *AuditLogger) LogPasswordChange(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "password_change",
		Resource:    "user",
		ResourceID:  userID,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// LogMFAEnable logs MFA enablement
func (a *AuditLogger) LogMFAEnable(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "mfa_enable",
		Resource:    "user",
		ResourceID:  userID,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// LogMFADisable logs MFA disablement
func (a *AuditLogger) LogMFADisable(ctx context.Context, userID, clientIP, userAgent string, success bool, description string) error {
	return a.Log(ctx, AuditEvent{
		UserID:      userID,
		Action:      "mfa_disable",
		Resource:    "user",
		ResourceID:  userID,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		Success:     success,
		Description: description,
	})
}

// Helper function to get user ID from context
func getUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return ""
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
