package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/example/auth-service/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPManager handles TOTP operations
type TOTPManager struct {
	Config *config.Config
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(cfg *config.Config) *TOTPManager {
	return &TOTPManager{
		Config: cfg,
	}
}

// TOTPOptions contains options for TOTP generation and validation
type TOTPOptions struct {
	// Issuer is the name of the issuing organization (required)
	Issuer string

	// AccountName is the user's account name/email (required)
	AccountName string

	// SecretSize is the size of the TOTP secret in bytes (default: 20 bytes = 160 bits)
	SecretSize uint

	// Digits is the number of digits in the OTP (default: 6)
	Digits otp.Digits

	// Algorithm is the HMAC algorithm used (default: SHA1)
	Algorithm otp.Algorithm

	// Period is the TOTP period in seconds (default: 30)
	Period uint

	// Skew is the number of periods before/after to allow (default: 1)
	Skew uint
}

// GenerateTOTPSecret generates a new TOTP secret and provisioning URI
func (t *TOTPManager) GenerateTOTPSecret(opts TOTPOptions) (string, string, error) {
	// Set defaults for unspecified options
	if opts.SecretSize == 0 {
		opts.SecretSize = 20 // 160 bits
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = otp.AlgorithmSHA1
	}
	if opts.Period == 0 {
		opts.Period = 30
	}
	if opts.Issuer == "" {
		opts.Issuer = t.Config.Auth.TOTPIssuer
	}

	// Validate required fields
	if opts.AccountName == "" {
		return "", "", fmt.Errorf("account name is required")
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      opts.Issuer,
		AccountName: opts.AccountName,
		SecretSize:  opts.SecretSize,
		Digits:      opts.Digits,
		Algorithm:   opts.Algorithm,
		Period:      opts.Period,
	})
	if err != nil {
		return "", "", err
	}

	// Return the secret and provisioning URI
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP validates a TOTP code against a secret
func (t *TOTPManager) ValidateTOTP(secret, code string, skew uint) (bool, error) {
	// Normalize the secret - remove spaces and capitalize
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Default skew to 1 if not provided
	if skew == 0 {
		skew = 1
	}

	// Validate the TOTP code
	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      skew,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	return valid, err
}

// GenerateRecoveryCode generates a secure random recovery code
func (t *TOTPManager) GenerateRecoveryCode() (string, error) {
	// Generate 8 random bytes (64 bits)
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	// Encode as base32 for easy reading (removes confusing chars like 0, O, 1, I)
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	code := encoder.EncodeToString(buf)

	// Split into groups of 4 characters for readability
	var codeGroups []string
	for i := 0; i < len(code); i += 4 {
		end := i + 4
		if end > len(code) {
			end = len(code)
		}
		codeGroups = append(codeGroups, code[i:end])
	}

	return strings.Join(codeGroups, "-"), nil
}

// GenerateBackupCodes generates multiple backup codes
func (t *TOTPManager) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 10 // Default to 10 backup codes
	}

	var codes []string
	for i := 0; i < count; i++ {
		code, err := t.GenerateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	return codes, nil
}

// GenerateQRCodeURL generates a URL that can be rendered as a QR code for TOTP setup
func (t *TOTPManager) GenerateQRCodeURL(issuer, accountName, secret string) string {
	// Clean the values to ensure they're URL-safe
	issuer = url.QueryEscape(issuer)
	accountName = url.QueryEscape(accountName)

	// Generate the otpauth URL
	// Format: otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, accountName, secret, issuer,
	)
}
