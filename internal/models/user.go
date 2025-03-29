package models

import (
	"database/sql"
	"time"
)

// User represents a registered user in the system
type User struct {
	ID                  string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email               string         `json:"email" gorm:"uniqueIndex;not null"`
	Username            string         `json:"username" gorm:"uniqueIndex;not null"`
	PasswordHash        string         `json:"-" gorm:"not null"` // Never expose password hash in JSON
	FirstName           string         `json:"first_name,omitempty"`
	LastName            string         `json:"last_name,omitempty"`
	IsEmailVerified     bool           `json:"is_email_verified" gorm:"default:false"`
	VerificationToken   string         `json:"-"`
	VerifiedAt          sql.NullTime   `json:"verified_at"`
	TOTPSecret          string         `json:"-"` // TOTP secret for 2FA
	TOTPEnabled         bool           `json:"totp_enabled" gorm:"default:false"`
	RecoveryCode        string         `json:"-"` // Used for password reset
	RecoveryCodeExpiry  time.Time      `json:"-"`
	LastLogin           sql.NullTime   `json:"last_login"`
	LastFailedLogin     sql.NullTime   `json:"-"`
	FailedLoginAttempts int            `json:"-" gorm:"default:0"`
	Locked              bool           `json:"locked" gorm:"default:false"`
	LockedUntil         sql.NullTime   `json:"-"`
	OAuthProvider       sql.NullString `json:"oauth_provider,omitempty"`
	OAuthID             sql.NullString `json:"-"`
	RefreshTokens       []RefreshToken `json:"-" gorm:"foreignKey:UserID"`
	Roles               []Role         `json:"roles,omitempty" gorm:"many2many:user_roles;"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	DeletedAt           sql.NullTime   `json:"deleted_at,omitempty" gorm:"index"`
}

// RefreshToken represents a JWT refresh token
type RefreshToken struct {
	ID         string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID     string         `json:"-" gorm:"type:uuid;not null"`
	Token      string         `json:"-" gorm:"uniqueIndex;not null"` // Hashed token value
	UserAgent  string         `json:"-"`
	ClientIP   string         `json:"-"`
	IssuedAt   time.Time      `json:"issued_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	RevokedAt  sql.NullTime   `json:"revoked_at,omitempty"`
	ReplacedBy sql.NullString `json:"-"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Role represents a role for role-based access control
type Role struct {
	ID          string       `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string       `json:"name" gorm:"uniqueIndex;not null"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions,omitempty" gorm:"many2many:role_permissions;"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Permission represents a permission for fine-grained access control
type Permission struct {
	ID          string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string    `json:"name" gorm:"uniqueIndex;not null"`
	Description string    `json:"description"`
	Resource    string    `json:"resource" gorm:"not null"` // The resource this permission applies to
	Action      string    `json:"action" gorm:"not null"`   // The action allowed (create, read, update, delete)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditLog represents a security audit log entry
type AuditLog struct {
	ID          string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID      string    `json:"user_id" gorm:"type:uuid;index"`
	Action      string    `json:"action" gorm:"not null"`
	Resource    string    `json:"resource" gorm:"not null"`
	ResourceID  string    `json:"resource_id"`
	OldValue    string    `json:"old_value,omitempty"`
	NewValue    string    `json:"new_value,omitempty"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	Timestamp   time.Time `json:"timestamp" gorm:"not null;index"`
	Success     bool      `json:"success" gorm:"not null"`
	Description string    `json:"description"`
}

// OAuthAccount represents a user's OAuth connection
type OAuthAccount struct {
	ID             string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID         string    `json:"user_id" gorm:"type:uuid;not null"`
	Provider       string    `json:"provider" gorm:"not null"` // e.g., "google", "facebook"
	ProviderUserID string    `json:"provider_user_id" gorm:"not null"`
	AccessToken    string    `json:"-"` // Encrypted
	RefreshToken   string    `json:"-"` // Encrypted
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
