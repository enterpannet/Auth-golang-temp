package controllers

import (
	"net/http"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/example/auth-service/internal/crypto"
	"github.com/example/auth-service/internal/models"
	"github.com/gin-gonic/gin"
)

// MFAController handles MFA-related HTTP requests
type MFAController struct {
	Config  *config.Config
	Service *auth.Service
}

// NewMFAController creates a new MFA controller
func NewMFAController(cfg *config.Config, service *auth.Service) *MFAController {
	return &MFAController{
		Config:  cfg,
		Service: service,
	}
}

// SetupMFA handles MFA setup request
func (c *MFAController) SetupMFA(ctx *gin.Context) {
	// Get user ID from context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user := models.User{}
	if err := c.Service.DB.First(&user, "id = ?", userID).Error; err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate TOTP secret
	secret, qrCodeURL, err := c.Service.TOTPManager.GenerateTOTPSecret(crypto.TOTPOptions{
		AccountName: user.Email,
		Issuer:      c.Config.Auth.TOTPIssuer,
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP secret"})
		return
	}

	// Store temporary secret in user record
	if err := c.Service.DB.Model(&user).Update("totp_secret", secret).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP secret"})
		return
	}

	// Return the secret and QR code URL
	ctx.JSON(http.StatusOK, auth.SetupMFAResponse{
		Secret:    secret,
		QRCodeURL: qrCodeURL,
	})
}

// VerifyMFA handles MFA verification and enabling
func (c *MFAController) VerifyMFA(ctx *gin.Context) {
	// Get user ID from context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse request
	var req auth.VerifyMFARequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Get user
	user := models.User{}
	if err := c.Service.DB.First(&user, "id = ?", userID).Error; err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify TOTP code
	valid, err := c.Service.TOTPManager.ValidateTOTP(user.TOTPSecret, req.TOTPCode, 1)
	if err != nil || !valid {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// Generate backup codes
	backupCodes, err := c.Service.TOTPManager.GenerateBackupCodes(10)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// TODO: Store backup codes securely (hashed)

	// Enable MFA for the user
	if err := c.Service.DB.Model(&user).Updates(map[string]interface{}{
		"totp_enabled": true,
	}).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable MFA"})
		return
	}

	// Log MFA enable
	c.Service.AuditLogger.LogMFAEnable(ctx.Request.Context(),
		user.ID, ctx.ClientIP(), ctx.Request.UserAgent(), true, "MFA enabled")

	// Return response
	ctx.JSON(http.StatusOK, auth.VerifyMFAResponse{
		Enabled:     true,
		BackupCodes: backupCodes,
	})
}

// DisableMFA handles disabling MFA
func (c *MFAController) DisableMFA(ctx *gin.Context) {
	// Get user ID from context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user
	user := models.User{}
	if err := c.Service.DB.First(&user, "id = ?", userID).Error; err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if MFA is enabled
	if !user.TOTPEnabled {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Disable MFA
	if err := c.Service.DB.Model(&user).Updates(map[string]interface{}{
		"totp_enabled": false,
		"totp_secret":  "",
	}).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable MFA"})
		return
	}

	// Log MFA disable
	c.Service.AuditLogger.LogMFADisable(ctx.Request.Context(),
		user.ID, ctx.ClientIP(), ctx.Request.UserAgent(), true, "MFA disabled")

	// Return response
	ctx.JSON(http.StatusOK, gin.H{"disabled": true})
}

// GenerateBackupCodes handles generating new backup codes
func (c *MFAController) GenerateBackupCodes(ctx *gin.Context) {
	// Get user ID from context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user
	user := models.User{}
	if err := c.Service.DB.First(&user, "id = ?", userID).Error; err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if MFA is enabled
	if !user.TOTPEnabled {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Generate new backup codes
	backupCodes, err := c.Service.TOTPManager.GenerateBackupCodes(10)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// TODO: Store backup codes securely (hashed)

	// Return response
	ctx.JSON(http.StatusOK, gin.H{"backup_codes": backupCodes})
}
