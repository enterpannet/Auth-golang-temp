package config

import (
	"time"
)

// Config represents the application configuration
type Config struct {
	Environment    string           `json:"environment"`
	Debug          bool             `json:"debug"`
	Server         ServerConfig     `json:"server"`
	Database       DatabaseConfig   `json:"database"`
	Auth           AuthConfig       `json:"auth"`
	Encryption     EncryptionConfig `json:"encryption"`
	Audit          AuditConfig      `json:"audit"`
	Security       SecurityConfig   `json:"security"`
	AllowedOrigins []string         `json:"allowed_origins"`
}

// ServerConfig represents the server configuration
type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// DatabaseConfig represents the database configuration
type DatabaseConfig struct {
	Driver       string `json:"driver"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	Password     string `json:"password"`
	Name         string `json:"name"`
	SSLMode      string `json:"ssl_mode"`
	MaxOpenConns int    `json:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns"`
	AutoMigrate  bool   `json:"auto_migrate"`
}

// AuthConfig represents the authentication configuration
type AuthConfig struct {
	SecretKey                string                         `json:"secret_key"`
	AccessTokenExpiry        time.Duration                  `json:"access_token_expiry"`
	RefreshTokenExpiry       time.Duration                  `json:"refresh_token_expiry"`
	TOTPIssuer               string                         `json:"totp_issuer"`
	PasswordMinLength        int                            `json:"password_min_length"`
	PasswordRequireUppercase bool                           `json:"password_require_uppercase"`
	PasswordRequireSpecial   bool                           `json:"password_require_special"`
	PasswordRequireNumber    bool                           `json:"password_require_number"`
	OAuthProviders           map[string]OAuthProviderConfig `json:"oauth_providers"`
	CookieDomain             string                         `json:"cookie_domain"`
	CookieSecure             bool                           `json:"cookie_secure"`
	SessionCookieName        string                         `json:"session_cookie_name"`
	CookieSameSite           string                         `json:"cookie_same_site"`
}

// OAuthProviderConfig represents configuration for an OAuth provider
type OAuthProviderConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	UserInfoURL  string   `json:"user_info_url"`
}

// EncryptionConfig represents encryption settings
type EncryptionConfig struct {
	AESKey        []byte `json:"-"` // Not serialized to JSON
	DataEncrypted bool   `json:"data_encrypted"`
}

// AuditConfig represents audit logging settings
type AuditConfig struct {
	Enabled bool   `json:"enabled"`
	File    string `json:"file"`
	Output  string `json:"output"` // "file", "db", or "both"
}

// SecurityConfig represents security settings
type SecurityConfig struct {
	EnableCSRFProtection bool            `json:"enable_csrf_protection"`
	CSRFTokenName        string          `json:"csrf_token_name"`
	CSRFTokenExpiry      time.Duration   `json:"csrf_token_expiry"`
	RateLimit            RateLimitConfig `json:"rate_limit"`
}

// RateLimitConfig represents rate limiting settings
type RateLimitConfig struct {
	Enabled             bool          `json:"enabled"`
	RequestsPerSecond   int           `json:"requests_per_second"`
	Burst               int           `json:"burst"`
	LoginLimitPerIP     int           `json:"login_limit_per_ip"`
	LoginLimitExpiry    time.Duration `json:"login_limit_expiry"`
	RegisterLimitPerIP  int           `json:"register_limit_per_ip"`
	RegisterLimitExpiry time.Duration `json:"register_limit_expiry"`
	WhitelistedIPs      []string      `json:"whitelisted_ips"`
	BlacklistedIPs      []string      `json:"blacklisted_ips"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Environment: "development",
		Debug:       true,
		Server: ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Driver:       "postgres",
			Host:         "localhost",
			Port:         5432,
			User:         "postgres",
			Password:     "postgres",
			Name:         "auth_service",
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 25,
			AutoMigrate:  true,
		},
		Auth: AuthConfig{
			SecretKey:                "super-secret-key-change-in-production",
			AccessTokenExpiry:        15 * time.Minute,
			RefreshTokenExpiry:       7 * 24 * time.Hour,
			TOTPIssuer:               "Auth Service",
			PasswordMinLength:        8,
			PasswordRequireUppercase: false,
			PasswordRequireSpecial:   false,
			PasswordRequireNumber:    false,
			OAuthProviders: map[string]OAuthProviderConfig{
				"google": {
					ClientID:     "",
					ClientSecret: "",
					RedirectURL:  "http://localhost:8080/auth/callback/google",
					Scopes:       []string{"openid", "profile", "email"},
					UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
				},
				"facebook": {
					ClientID:     "",
					ClientSecret: "",
					RedirectURL:  "http://localhost:8080/auth/callback/facebook",
					Scopes:       []string{"email", "public_profile"},
					UserInfoURL:  "https://graph.facebook.com/me?fields=id,name,email,picture",
				},
				"github": {
					ClientID:     "",
					ClientSecret: "",
					RedirectURL:  "http://localhost:8080/auth/callback/github",
					Scopes:       []string{"user:email"},
					UserInfoURL:  "https://api.github.com/user",
				},
			},
			CookieDomain:      "localhost",
			CookieSecure:      false,
			SessionCookieName: "refresh_token",
			CookieSameSite:    "lax",
		},
		Encryption: EncryptionConfig{
			AESKey:        []byte("a-thirty-two-byte-key-for-aes-gcm!"),
			DataEncrypted: false,
		},
		Audit: AuditConfig{
			Enabled: true,
			File:    "logs/audit",
			Output:  "both",
		},
		Security: SecurityConfig{
			EnableCSRFProtection: true,
			CSRFTokenName:        "csrf_token",
			CSRFTokenExpiry:      24 * time.Hour,
			RateLimit: RateLimitConfig{
				Enabled:             true,
				RequestsPerSecond:   10,
				Burst:               20,
				LoginLimitPerIP:     5,
				LoginLimitExpiry:    15 * time.Minute,
				RegisterLimitPerIP:  3,
				RegisterLimitExpiry: 1 * time.Hour,
				WhitelistedIPs:      []string{},
				BlacklistedIPs:      []string{},
			},
		},
		AllowedOrigins: []string{"*"},
	}
}
