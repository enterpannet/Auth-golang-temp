package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/auth-service/config"
)

var (
	// ErrVerificationTokenInvalid when verification token is invalid
	ErrVerificationTokenInvalid = errors.New("verification token is invalid")

	// ErrVerificationTokenExpired when verification token is expired
	ErrVerificationTokenExpired = errors.New("verification token has expired")
)

// EmailVerifier handles email verification token operations
type EmailVerifier struct {
	Config *config.Config
	secret []byte
}

// NewEmailVerifier creates a new email verifier
func NewEmailVerifier(cfg *config.Config) *EmailVerifier {
	return &EmailVerifier{
		Config: cfg,
		secret: []byte(cfg.Auth.SecretKey),
	}
}

// GenerateVerificationToken creates a new email verification token
func (e *EmailVerifier) GenerateVerificationToken(userID, email string) (string, error) {
	// Create a random token
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Format: base64(random_token)_userID_timestamp
	randomToken := base64.URLEncoding.EncodeToString(tokenBytes)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Create the combined token
	verificationToken := fmt.Sprintf("%s_%s_%s", randomToken, userID, timestamp)

	// Sign the token
	signature := e.createSignature(verificationToken)
	return fmt.Sprintf("%s.%s", verificationToken, signature), nil
}

// VerifyToken validates the email verification token
func (e *EmailVerifier) VerifyToken(token string) (string, error) {
	// Split the token into data and signature
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", ErrVerificationTokenInvalid
	}

	tokenData := parts[0]
	signature := parts[1]

	// Verify the signature
	expectedSignature := e.createSignature(tokenData)
	if signature != expectedSignature {
		return "", ErrVerificationTokenInvalid
	}

	// Parse the token data
	tokenParts := strings.Split(tokenData, "_")
	if len(tokenParts) != 3 {
		return "", ErrVerificationTokenInvalid
	}

	// Extract userID and timestamp
	userID := tokenParts[1]
	timestampStr := tokenParts[2]

	// Validate timestamp
	timestamp, err := parseInt64(timestampStr)
	if err != nil {
		return "", ErrVerificationTokenInvalid
	}

	// Check if token is expired
	tokenTime := time.Unix(timestamp, 0)
	if time.Since(tokenTime) > e.Config.Auth.VerificationTokenExpiry {
		return "", ErrVerificationTokenExpired
	}

	return userID, nil
}

// createSignature creates a simple signature for the token
func (e *EmailVerifier) createSignature(data string) string {
	// In a production environment, use a proper HMAC function
	// This is a simple signature for demonstration
	combined := data + string(e.secret)
	return base64.URLEncoding.EncodeToString([]byte(combined))
}

// parseInt64 converts a string to int64
func parseInt64(s string) (int64, error) {
	var i int64
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
