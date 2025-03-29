package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/example/auth-service/config"
)

// Errors for encryption operations
var (
	ErrInvalidKeyLength  = errors.New("invalid key length, must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDataTooShort      = errors.New("ciphertext too short")
)

// Encryptor handles encryption operations
type Encryptor struct {
	Config *config.Config
}

// NewEncryptor creates a new encryption manager
func NewEncryptor(cfg *config.Config) *Encryptor {
	return &Encryptor{
		Config: cfg,
	}
}

// Encrypt encrypts a plaintext string using AES-GCM
// Returns the base64-encoded ciphertext
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	// Get the encryption key from config
	key := e.Config.Encryption.AESKey

	// Validate key length (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKeyLength
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher mode (includes authentication)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the plaintext
	// The ciphertext includes the nonce at the beginning and the authentication tag at the end
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode the ciphertext as base64 for storage/transmission
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext
func (e *Encryptor) Decrypt(encryptedBase64 string) (string, error) {
	// Get the encryption key from config
	key := e.Config.Encryption.AESKey

	// Validate key length
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", ErrInvalidKeyLength
	}

	// Decode the base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Check if the ciphertext is valid
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrDataTooShort
	}

	// Extract the nonce from the beginning of the ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext (this will also verify the authentication tag)
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// EncryptIfNeeded conditionally encrypts data if encryption is enabled
func (e *Encryptor) EncryptIfNeeded(plaintext string) (string, error) {
	if !e.Config.Encryption.DataEncrypted {
		return plaintext, nil
	}
	return e.Encrypt(plaintext)
}

// DecryptIfNeeded conditionally decrypts data if encryption is enabled
func (e *Encryptor) DecryptIfNeeded(data string) (string, error) {
	if !e.Config.Encryption.DataEncrypted {
		return data, nil
	}
	return e.Decrypt(data)
}
