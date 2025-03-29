package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/example/auth-service/internal/logging"
	"github.com/example/auth-service/internal/models"
	"gorm.io/gorm"
)

// VerifyEmail verifies a user's email using the verification token
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	// Verify the token
	userID, err := s.EmailVerifier.VerifyToken(token)
	if err != nil {
		return err
	}

	// Find the user
	var user models.User
	result := s.DB.First(&user, "id = ?", userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return result.Error
	}

	// Check if already verified
	if user.IsEmailVerified {
		return ErrEmailAlreadyVerified
	}

	// Update user's verification status
	updates := map[string]interface{}{
		"is_email_verified":  true,
		"verification_token": "",
		"verified_at": sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}

	result = s.DB.Model(&user).Updates(updates)
	if result.Error != nil {
		return result.Error
	}

	// Log the successful verification
	s.AuditLogger.Log(ctx, logging.AuditEvent{
		UserID:      userID,
		Action:      "email_verified",
		Resource:    "user",
		ResourceID:  userID,
		Success:     true,
		Description: "Email verified successfully",
	})

	return nil
}

// ResendVerificationEmail resends the verification email to the user
func (s *Service) ResendVerificationEmail(ctx context.Context, userID string) error {
	// Find the user
	var user models.User
	result := s.DB.First(&user, "id = ?", userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return result.Error
	}

	// Check if already verified
	if user.IsEmailVerified {
		return ErrEmailAlreadyVerified
	}

	// Generate a new verification token
	token, err := s.EmailVerifier.GenerateVerificationToken(user.ID, user.Email)
	if err != nil {
		return err
	}

	// Save the token in the database
	result = s.DB.Model(&user).Update("verification_token", token)
	if result.Error != nil {
		return result.Error
	}

	// Send the email
	err = s.Mailer.SendVerificationEmail(user.Email, user.Username, token)
	if err != nil {
		return err
	}

	// Log the email resend event
	s.AuditLogger.Log(ctx, logging.AuditEvent{
		UserID:      userID,
		Action:      "resend_verification_email",
		Resource:    "user",
		ResourceID:  userID,
		Success:     true,
		Description: "Verification email resent",
	})

	return nil
}

// SendVerificationEmail sends an email verification to a newly registered user
func (s *Service) SendVerificationEmail(user *models.User) error {
	// Check if verification is required
	if !s.Config.Auth.VerificationRequired {
		// If not required, mark as verified
		s.DB.Model(user).Updates(map[string]interface{}{
			"is_email_verified": true,
			"verified_at": sql.NullTime{
				Time:  time.Now(),
				Valid: true,
			},
		})
		return nil
	}

	// Generate a verification token
	token, err := s.EmailVerifier.GenerateVerificationToken(user.ID, user.Email)
	if err != nil {
		return err
	}

	// Save the token in the database
	result := s.DB.Model(user).Update("verification_token", token)
	if result.Error != nil {
		return result.Error
	}

	// Send the email
	return s.Mailer.SendVerificationEmail(user.Email, user.Username, token)
}
