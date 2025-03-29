package auth

import (
	"errors"
)

// Centralized error definitions for the auth package
var (
	// User-related errors
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUsernameTaken         = errors.New("username already taken")
	ErrEmailTaken            = errors.New("email already taken")
	ErrEmailAlreadyExists    = errors.New("email already exists")
	ErrUsernameAlreadyExists = errors.New("username already exists")
	ErrPasswordMismatch      = errors.New("passwords do not match")
	ErrPasswordTooWeak       = errors.New("password does not meet strength requirements")
	ErrAccountLocked         = errors.New("account is locked")
	ErrEmailNotVerified      = errors.New("email is not verified")

	// Token-related errors
	ErrTokenInvalid        = errors.New("token is invalid")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenRevoked        = errors.New("token has been revoked")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")

	// Verification-related errors
	ErrEmailAlreadyVerified      = errors.New("email is already verified")
	ErrEmailVerificationRequired = errors.New("email verification required")
	ErrEmailVerificationFailed   = errors.New("email verification failed")

	// MFA-related errors
	ErrMFARequired       = errors.New("multi-factor authentication required")
	ErrMFAInvalid        = errors.New("invalid MFA code")
	ErrMFAAlreadyEnabled = errors.New("multi-factor authentication is already enabled")
	ErrMFANotEnabled     = errors.New("multi-factor authentication is not enabled")

	// Recovery-related errors
	ErrInvalidRecoveryCode = errors.New("invalid or expired recovery code")

	// OAuth-related errors
	ErrOAuthProviderNotFound  = errors.New("OAuth provider not found")
	ErrOAuthProviderSetupFail = errors.New("failed to setup OAuth provider")
)
