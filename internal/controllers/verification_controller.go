package controllers

import (
	"net/http"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/gin-gonic/gin"
)

// VerificationController handles email verification operations
type VerificationController struct {
	Config  *config.Config
	Service *auth.Service
}

// NewVerificationController creates a new verification controller
func NewVerificationController(cfg *config.Config, service *auth.Service) *VerificationController {
	return &VerificationController{
		Config:  cfg,
		Service: service,
	}
}

// VerifyEmail handles email verification requests
func (c *VerificationController) VerifyEmail(ctx *gin.Context) {
	// Get the verification token from the query parameters
	token := ctx.Query("token")
	if token == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing verification token",
		})
		return
	}

	// Verify the token
	err := c.Service.VerifyEmail(ctx, token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Redirect user to the frontend if the verification is successful
	if c.Config.Auth.VerificationRedirectURL != "" {
		ctx.Redirect(http.StatusTemporaryRedirect, c.Config.Auth.VerificationRedirectURL)
		return
	}

	// If no redirect URL is specified, return a success message
	ctx.JSON(http.StatusOK, gin.H{
		"message": "Email verified successfully",
	})
}

// ResendVerificationEmail resends the verification email
func (c *VerificationController) ResendVerificationEmail(ctx *gin.Context) {
	// Get user ID from authenticated context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized",
		})
		return
	}

	// Cast to string
	userIDStr, ok := userID.(string)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	// Resend verification email
	err := c.Service.ResendVerificationEmail(ctx, userIDStr)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Verification email sent successfully",
	})
}
