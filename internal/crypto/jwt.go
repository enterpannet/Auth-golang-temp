package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/auth-service/config"
)

// Constants for JWT claims
const (
	ClaimUserID        = "sub"
	ClaimRoles         = "roles"
	ClaimPermissions   = "permissions"
	ClaimTokenID       = "jti"
	ClaimIssuer        = "iss"
	ClaimIssuedAt      = "iat"
	ClaimExpiry        = "exp"
	ClaimNotBefore     = "nbf"
	ClaimAudience      = "aud"
	ClaimEmailVerified = "email_verified"
	ClaimTokenType     = "token_type"
	ClaimSessionID     = "sid"
)

// TokenType defines the type of JWT token
type TokenType string

const (
	// AccessToken represents a short-lived token for API access
	AccessToken TokenType = "access"

	// RefreshToken represents a long-lived token for refreshing access tokens
	RefreshToken TokenType = "refresh"

	// EmailVerificationToken represents a token for email verification
	EmailVerificationToken TokenType = "email_verification"

	// PasswordResetToken represents a token for password reset
	PasswordResetToken TokenType = "password_reset"
)

// Common JWT errors
var (
	ErrTokenInvalid     = errors.New("token is invalid")
	ErrTokenExpired     = errors.New("token is expired")
	ErrTokenNotValidYet = errors.New("token not valid yet")
	ErrTokenMalformed   = errors.New("token is malformed")
	ErrTokenUnexpected  = errors.New("unexpected signing method")
)

// Claims represents the JWT claims
type Claims struct {
	// Standard claims
	Subject   string    `json:"sub"`
	Issuer    string    `json:"iss,omitempty"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	ID        string    `json:"jti,omitempty"`

	// Custom claims
	UserID        string   `json:"user_id"`
	Email         string   `json:"email,omitempty"`
	Username      string   `json:"username,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
}

// JWTManager handles JWT token operations
type JWTManager struct {
	Config        *config.Config
	secret        []byte
	tokenDuration time.Duration
}

// NewJWTManager creates a new JWTManager
func NewJWTManager(cfg *config.Config) *JWTManager {
	return &JWTManager{
		Config:        cfg,
		secret:        []byte(cfg.Auth.SecretKey),
		tokenDuration: cfg.Auth.AccessTokenExpiry,
	}
}

// GenerateToken creates a new JWT token
func (m *JWTManager) GenerateToken(userID, email, username string, roles, permissions []string, sessionID string, emailVerified bool, duration time.Duration) (string, error) {
	now := time.Now()
	expires := now.Add(duration)

	// Create the claims
	claims := Claims{
		Subject:       userID,
		IssuedAt:      now,
		ExpiresAt:     expires,
		UserID:        userID,
		Email:         email,
		Username:      username,
		Roles:         roles,
		Permissions:   permissions,
		SessionID:     sessionID,
		EmailVerified: emailVerified,
	}

	// Create the payload
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Base64 encode the payload
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	// Create a simple hmac signature
	signedData := m.createSignature(encodedPayload)

	// Combine into a token
	token := fmt.Sprintf("%s.%s", encodedPayload, signedData)

	return token, nil
}

// ValidateToken validates a JWT token and returns the claims
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	// Split the token into payload and signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 2 {
		return nil, ErrTokenMalformed
	}

	encodedPayload := parts[0]
	signature := parts[1]

	// Verify the signature
	expectedSignature := m.createSignature(encodedPayload)
	if signature != expectedSignature {
		return nil, ErrTokenInvalid
	}

	// Decode the payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	// Parse the claims
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	// Validate expiration
	if time.Now().After(claims.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Validate not before
	if time.Now().Before(claims.IssuedAt) {
		return nil, ErrTokenNotValidYet
	}

	return &claims, nil
}

// createSignature creates a simple HMAC signature
func (m *JWTManager) createSignature(data string) string {
	// In a production environment, use a proper HMAC function
	// This is a simple hash for demonstration purposes
	combined := data + string(m.secret)
	return base64.RawURLEncoding.EncodeToString([]byte(combined))
}

// GenerateAccessToken creates a short-lived access token
func (m *JWTManager) GenerateAccessToken(userID, email, username string, roles, permissions []string, sessionID string, emailVerified bool) (string, error) {
	return m.GenerateToken(userID, email, username, roles, permissions, sessionID, emailVerified, m.tokenDuration)
}

// GenerateRefreshToken creates a long-lived refresh token
func (m *JWTManager) GenerateRefreshToken(userID, sessionID string) (string, error) {
	return m.GenerateToken(userID, "", "", nil, nil, sessionID, false, time.Hour*24*30) // 30 days
}
