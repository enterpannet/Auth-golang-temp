package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/example/auth-service/config"
	"golang.org/x/crypto/argon2"
)

// Password format errors
var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrMismatchedPassword  = errors.New("passwords do not match")
)

// Argon2 parameters - these are conservative and strong defaults
const (
	argon2Version = argon2.Version
	argon2Memory  = 64 * 1024 // 64MB
	argon2Time    = 3         // number of iterations
	argon2Threads = 4         // number of threads
	argon2KeyLen  = 32        // 32-byte key length
	argon2SaltLen = 16        // 16-byte salt
)

// PasswordHasher manages password hashing operations
type PasswordHasher struct {
	Config *config.Config
}

// NewPasswordHasher creates a new password hasher
func NewPasswordHasher(cfg *config.Config) *PasswordHasher {
	return &PasswordHasher{
		Config: cfg,
	}
}

// HashPassword creates a secure hash of a password using Argon2id
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func (p *PasswordHasher) HashPassword(password string) (string, error) {
	// Generate a cryptographically secure random salt
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash the password with Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)

	// Encode as base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format the final string
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		argon2Memory,
		argon2Time,
		argon2Threads,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// VerifyPassword checks if a password matches a hash
func (p *PasswordHasher) VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the hash
	params, salt, hash, err := p.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Compute the hash of the provided password
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	// Check that the contents of the hashed passwords are identical using constant-time comparison
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// argon2Params contains the parameters used for Argon2id hashing
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	saltLength  uint32
}

// decodeHash extracts the parameters, salt, and derived key from an encoded hash
func (p *PasswordHasher) decodeHash(encodedHash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	var params argon2Params
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.saltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.keyLength = uint32(len(hash))

	return &params, salt, hash, nil
}

// GenerateRandomPassword generates a cryptographically secure random password
func (p *PasswordHasher) GenerateRandomPassword(length int) (string, error) {
	if length < 8 {
		length = 16 // Minimum secure length
	}

	// Define character sets
	const (
		lowerChars   = "abcdefghijklmnopqrstuvwxyz"
		upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digitChars   = "0123456789"
		specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
		allChars     = lowerChars + upperChars + digitChars + specialChars
	)

	// Ensure at least one character from each set
	result := make([]byte, length)
	randomBytes := make([]byte, length)

	// Read random bytes
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Ensure we have at least one of each required character
	result[0] = lowerChars[randomBytes[0]%byte(len(lowerChars))]
	result[1] = upperChars[randomBytes[1]%byte(len(upperChars))]
	result[2] = digitChars[randomBytes[2]%byte(len(digitChars))]
	result[3] = specialChars[randomBytes[3]%byte(len(specialChars))]

	// Fill the rest of the password
	for i := 4; i < length; i++ {
		result[i] = allChars[randomBytes[i]%byte(len(allChars))]
	}

	// Shuffle the result to avoid predictable placement of character types
	for i := length - 1; i > 0; i-- {
		j := int(randomBytes[i]) % (i + 1)
		result[i], result[j] = result[j], result[i]
	}

	return string(result), nil
}

// ValidatePasswordStrength checks if a password meets security requirements
func (p *PasswordHasher) ValidatePasswordStrength(password string) error {
	// Minimum length check
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters long")
	}

	// Check for different character types
	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	// Build error message for failing criteria
	var missingCriteria []string
	if !hasUpper {
		missingCriteria = append(missingCriteria, "an uppercase letter")
	}
	if !hasLower {
		missingCriteria = append(missingCriteria, "a lowercase letter")
	}
	if !hasDigit {
		missingCriteria = append(missingCriteria, "a digit")
	}
	if !hasSpecial {
		missingCriteria = append(missingCriteria, "a special character")
	}

	if len(missingCriteria) > 0 {
		return fmt.Errorf("password must contain %s", strings.Join(missingCriteria, ", "))
	}

	return nil
}
