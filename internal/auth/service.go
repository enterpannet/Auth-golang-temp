package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/crypto"
	"github.com/example/auth-service/internal/logging"
	"github.com/example/auth-service/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Common errors
var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserNotFound           = errors.New("user not found")
	ErrEmailAlreadyExists     = errors.New("email already exists")
	ErrUsernameAlreadyExists  = errors.New("username already exists")
	ErrTokenInvalid           = errors.New("token is invalid or expired")
	ErrTokenRevoked           = errors.New("token has been revoked")
	ErrAccountLocked          = errors.New("account is locked")
	ErrEmailNotVerified       = errors.New("email is not verified")
	ErrMFARequired            = errors.New("multi-factor authentication required")
	ErrMFAInvalid             = errors.New("invalid multi-factor authentication code")
	ErrPasswordTooWeak        = errors.New("password does not meet strength requirements")
	ErrInvalidRecoveryCode    = errors.New("invalid or expired recovery code")
	ErrMFAAlreadyEnabled      = errors.New("multi-factor authentication is already enabled")
	ErrMFANotEnabled          = errors.New("multi-factor authentication is not enabled")
	ErrOAuthProviderNotFound  = errors.New("OAuth provider not found")
	ErrOAuthProviderSetupFail = errors.New("failed to setup OAuth provider")
)

// Service provides authentication and authorization functionality
type Service struct {
	Config       *config.Config
	DB           *gorm.DB
	PasswordHash *crypto.PasswordHasher
	JWTManager   *crypto.JWTManager
	TOTPManager  *crypto.TOTPManager
	OAuthManager *crypto.OAuthManager
	Encryptor    *crypto.Encryptor
	AuditLogger  *logging.AuditLogger
}

// NewService creates a new authentication service
func NewService(
	cfg *config.Config,
	db *gorm.DB,
	passwordHash *crypto.PasswordHasher,
	jwtManager *crypto.JWTManager,
	totpManager *crypto.TOTPManager,
	oauthManager *crypto.OAuthManager,
	encryptor *crypto.Encryptor,
	auditLogger *logging.AuditLogger,
) *Service {
	return &Service{
		Config:       cfg,
		DB:           db,
		PasswordHash: passwordHash,
		JWTManager:   jwtManager,
		TOTPManager:  totpManager,
		OAuthManager: oauthManager,
		Encryptor:    encryptor,
		AuditLogger:  auditLogger,
	}
}

// RegisterUserInput represents the input for user registration
type RegisterUserInput struct {
	Email           string
	Username        string
	Password        string
	ConfirmPassword string
	FirstName       string
	LastName        string
	ClientIP        string
	UserAgent       string
}

// RegisterUserOutput represents the output for user registration
type RegisterUserOutput struct {
	User  models.User
	Token string
}

// RegisterUser registers a new user
func (s *Service) RegisterUser(ctx context.Context, input RegisterUserInput) (*RegisterUserOutput, error) {
	// Validate passwords match
	if input.Password != input.ConfirmPassword {
		return nil, errors.New("passwords do not match")
	}

	// Validate password strength
	if err := s.PasswordHash.ValidatePasswordStrength(input.Password); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordTooWeak, err)
	}

	// Begin transaction
	tx := s.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check if email already exists
	var existingUser models.User
	if err := tx.Where("email = ?", input.Email).First(&existingUser).Error; err == nil {
		tx.Rollback()
		return nil, ErrEmailAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}

	// Check if username already exists
	if err := tx.Where("username = ?", input.Username).First(&existingUser).Error; err == nil {
		tx.Rollback()
		return nil, ErrUsernameAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}

	// Hash password
	passwordHash, err := s.PasswordHash.HashPassword(input.Password)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate verification token
	verificationToken := uuid.New().String()

	// Get user role
	var userRole models.Role
	if err := tx.Where("name = ?", "user").First(&userRole).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}

	// Create user
	user := models.User{
		Email:             input.Email,
		Username:          input.Username,
		PasswordHash:      passwordHash,
		FirstName:         input.FirstName,
		LastName:          input.LastName,
		IsEmailVerified:   false,
		VerificationToken: verificationToken,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		Roles:             []models.Role{userRole},
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Generate JWT token for the new user
	sessionID := uuid.New().String()
	token, err := s.JWTManager.GenerateAccessToken(
		user.ID,
		user.Email,
		user.Username,
		extractRoleNames(user.Roles),
		extractPermissions(user.Roles),
		sessionID,
		user.IsEmailVerified,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Log the registration
	s.AuditLogger.Log(ctx, logging.AuditEvent{
		UserID:      user.ID,
		Action:      "register",
		Resource:    "user",
		ResourceID:  user.ID,
		ClientIP:    input.ClientIP,
		UserAgent:   input.UserAgent,
		Success:     true,
		Description: "User registration",
	})

	return &RegisterUserOutput{
		User:  user,
		Token: token,
	}, nil
}

// LoginInput represents the input for user login
type LoginInput struct {
	Email      string
	Password   string
	TOTPCode   string
	RememberMe bool
	ClientIP   string
	UserAgent  string
}

// LoginOutput represents the output for user login
type LoginOutput struct {
	User         models.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	RequiresMFA  bool
}

// Login authenticates a user
func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	var user models.User

	// Find user by email
	if err := s.DB.Preload("Roles.Permissions").Where("email = ?", input.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Log failed login attempt
			s.AuditLogger.LogLogin(ctx, "", input.ClientIP, input.UserAgent, false, "User not found")
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Check if account is locked
	if user.Locked {
		s.AuditLogger.LogLogin(ctx, user.ID, input.ClientIP, input.UserAgent, false, "Account locked")
		return nil, ErrAccountLocked
	}

	// Verify password
	valid, err := s.PasswordHash.VerifyPassword(input.Password, user.PasswordHash)
	if err != nil || !valid {
		// Update failed login attempts
		s.DB.Model(&user).Updates(map[string]interface{}{
			"failed_login_attempts": user.FailedLoginAttempts + 1,
			"last_failed_login":     sql.NullTime{Time: time.Now(), Valid: true},
		})

		// Lock account if too many failed attempts
		if user.FailedLoginAttempts+1 >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			s.DB.Model(&user).Updates(map[string]interface{}{
				"locked":       true,
				"locked_until": sql.NullTime{Time: lockUntil, Valid: true},
			})
		}

		// Log failed login attempt
		s.AuditLogger.LogLogin(ctx, user.ID, input.ClientIP, input.UserAgent, false, "Invalid password")
		return nil, ErrInvalidCredentials
	}

	// If MFA is enabled, check TOTP code
	if user.TOTPEnabled {
		// If TOTP code is not provided, return MFA required error
		if input.TOTPCode == "" {
			return &LoginOutput{
				User:        user,
				RequiresMFA: true,
			}, nil
		}

		// Verify TOTP code
		valid, err := s.TOTPManager.ValidateTOTP(user.TOTPSecret, input.TOTPCode, 1)
		if err != nil || !valid {
			// Log failed MFA attempt
			s.AuditLogger.LogLogin(ctx, user.ID, input.ClientIP, input.UserAgent, false, "Invalid MFA code")
			return nil, ErrMFAInvalid
		}
	}

	// Reset failed login attempts
	s.DB.Model(&user).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"last_login":            sql.NullTime{Time: time.Now(), Valid: true},
	})

	// Generate session ID
	sessionID := uuid.New().String()

	// Generate access token
	accessToken, err := s.JWTManager.GenerateAccessToken(
		user.ID,
		user.Email,
		user.Username,
		extractRoleNames(user.Roles),
		extractPermissions(user.Roles),
		sessionID,
		user.IsEmailVerified,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenString, err := s.JWTManager.GenerateRefreshToken(user.ID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate a unique ID for the refresh token
	refreshTokenID := uuid.New().String()

	// Hash the refresh token for storage
	hashedRefreshToken, err := s.PasswordHash.HashPassword(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Store refresh token in database
	refreshToken := models.RefreshToken{
		ID:        refreshTokenID,
		UserID:    user.ID,
		Token:     hashedRefreshToken,
		UserAgent: input.UserAgent,
		ClientIP:  input.ClientIP,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.Config.Auth.RefreshTokenExpiry),
		CreatedAt: time.Now(),
	}

	if err := s.DB.Create(&refreshToken).Error; err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Log successful login
	s.AuditLogger.LogLogin(ctx, user.ID, input.ClientIP, input.UserAgent, true, "Login successful")

	return &LoginOutput{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		ExpiresAt:    time.Now().Add(s.Config.Auth.AccessTokenExpiry),
		RequiresMFA:  false,
	}, nil
}

// LogoutInput represents the input for user logout
type LogoutInput struct {
	UserID       string
	RefreshToken string
	ClientIP     string
	UserAgent    string
}

// Logout logs out a user by invalidating their refresh token
func (s *Service) Logout(ctx context.Context, input LogoutInput) error {
	// Begin transaction
	tx := s.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Find all refresh tokens for the user
	var tokens []models.RefreshToken
	if err := tx.Where("user_id = ?", input.UserID).Find(&tokens).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to find refresh tokens: %w", err)
	}

	// Revoke refresh tokens
	for _, token := range tokens {
		// Update token to be revoked
		if err := tx.Model(&token).Updates(map[string]interface{}{
			"revoked_at": sql.NullTime{Time: time.Now(), Valid: true},
		}).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to revoke refresh token: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log logout
	s.AuditLogger.LogLogout(ctx, input.UserID, input.ClientIP, input.UserAgent)

	return nil
}

// RefreshTokenInput represents the input for refreshing an access token
type RefreshTokenInput struct {
	RefreshToken string
	ClientIP     string
	UserAgent    string
}

// RefreshTokenOutput represents the output for refreshing an access token
type RefreshTokenOutput struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// RefreshToken refreshes an access token
func (s *Service) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	// Validate refresh token
	claims, err := s.JWTManager.ValidateToken(input.RefreshToken)
	if err != nil {
		s.AuditLogger.LogTokenRefresh(ctx, "", input.ClientIP, input.UserAgent, false, "Invalid refresh token")
		return nil, ErrTokenInvalid
	}

	// Get user ID from claims
	userID := claims.Subject
	sessionID := claims.SessionID

	// Find user
	var user models.User
	if err := s.DB.Preload("Roles.Permissions").Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.AuditLogger.LogTokenRefresh(ctx, userID, input.ClientIP, input.UserAgent, false, "User not found")
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Begin transaction
	tx := s.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Find the stored refresh token
	var storedToken models.RefreshToken
	if err := tx.Where("id = ? AND user_id = ?", claims.ID, userID).First(&storedToken).Error; err != nil {
		tx.Rollback()
		s.AuditLogger.LogTokenRefresh(ctx, userID, input.ClientIP, input.UserAgent, false, "Refresh token not found")
		return nil, ErrTokenInvalid
	}

	// Check if token is revoked
	if storedToken.RevokedAt.Valid {
		tx.Rollback()
		s.AuditLogger.LogTokenRefresh(ctx, userID, input.ClientIP, input.UserAgent, false, "Refresh token revoked")
		return nil, ErrTokenRevoked
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		tx.Rollback()
		s.AuditLogger.LogTokenRefresh(ctx, userID, input.ClientIP, input.UserAgent, false, "Refresh token expired")
		return nil, ErrTokenInvalid
	}

	// Generate new access token
	accessToken, err := s.JWTManager.GenerateAccessToken(
		user.ID,
		user.Email,
		user.Username,
		extractRoleNames(user.Roles),
		extractPermissions(user.Roles),
		sessionID,
		user.IsEmailVerified,
	)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := s.JWTManager.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Generate a unique ID for the refresh token
	refreshTokenID := uuid.New().String()

	// Hash the new refresh token for storage
	hashedRefreshToken, err := s.PasswordHash.HashPassword(newRefreshToken)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Mark old token as replaced
	if err := tx.Model(&storedToken).Updates(map[string]interface{}{
		"revoked_at":  sql.NullTime{Time: time.Now(), Valid: true},
		"replaced_by": sql.NullString{String: refreshTokenID, Valid: true},
	}).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Store new refresh token
	newToken := models.RefreshToken{
		ID:        refreshTokenID,
		UserID:    userID,
		Token:     hashedRefreshToken,
		UserAgent: input.UserAgent,
		ClientIP:  input.ClientIP,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.Config.Auth.RefreshTokenExpiry),
		CreatedAt: time.Now(),
	}

	if err := tx.Create(&newToken).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to store new refresh token: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log token refresh
	s.AuditLogger.LogTokenRefresh(ctx, userID, input.ClientIP, input.UserAgent, true, "Token refreshed")

	return &RefreshTokenOutput{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(s.Config.Auth.AccessTokenExpiry),
	}, nil
}

// Helper functions
func extractRoleNames(roles []models.Role) []string {
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.Name
	}
	return names
}

func extractPermissions(roles []models.Role) []string {
	var permissions []string
	for _, role := range roles {
		for _, perm := range role.Permissions {
			permissions = append(permissions, fmt.Sprintf("%s:%s", perm.Resource, perm.Action))
		}
	}
	return permissions
}
