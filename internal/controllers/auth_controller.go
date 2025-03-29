package controllers

import (
	"net/http"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/gin-gonic/gin"
)

// AuthController handles HTTP requests for auth operations
type AuthController struct {
	Config  *config.Config
	Service *auth.Service
}

// NewAuthController creates a new auth controller
func NewAuthController(cfg *config.Config, service *auth.Service) *AuthController {
	return &AuthController{
		Config:  cfg,
		Service: service,
	}
}

// Register handles user registration
func (c *AuthController) Register(ctx *gin.Context) {
	// Parse request body
	var req auth.RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate required fields
	if req.Email == "" || req.Username == "" || req.Password == "" || req.ConfirmPassword == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	// Register user
	result, err := c.Service.RegisterUser(ctx.Request.Context(), auth.RegisterUserInput{
		Email:           req.Email,
		Username:        req.Username,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		ClientIP:        ctx.ClientIP(),
		UserAgent:       ctx.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrEmailAlreadyExists, auth.ErrUsernameAlreadyExists:
			ctx.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case auth.ErrPasswordTooWeak:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		}
		return
	}

	// Return JWT token
	ctx.JSON(http.StatusCreated, auth.TokenResponse{
		AccessToken: result.Token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(c.Config.Auth.AccessTokenExpiry),
	})
}

// Login handles user login
func (c *AuthController) Login(ctx *gin.Context) {
	// Parse request body
	var req auth.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	// Login user
	result, err := c.Service.Login(ctx.Request.Context(), auth.LoginInput{
		Email:      req.Email,
		Password:   req.Password,
		TOTPCode:   req.TOTPCode,
		RememberMe: req.RememberMe,
		ClientIP:   ctx.ClientIP(),
		UserAgent:  ctx.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		case auth.ErrAccountLocked:
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Account is locked"})
		case auth.ErrMFAInvalid:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid MFA code"})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	// Check if MFA is required
	if result.RequiresMFA {
		response := gin.H{"requires_mfa": true}

		// Add flag if MFA setup is needed
		if result.NeedsMFASetup {
			response["needs_mfa_setup"] = true
		}

		ctx.JSON(http.StatusOK, response)
		return
	}

	// Set refresh token cookie
	if result.RefreshToken != "" {
		ctx.SetCookie(
			c.Config.Auth.SessionCookieName,
			result.RefreshToken,
			int(c.Config.Auth.RefreshTokenExpiry.Seconds()),
			"/",
			c.Config.Auth.CookieDomain,
			c.Config.Auth.CookieSecure,
			true, // HttpOnly
		)
	}

	// Return JWT token
	ctx.JSON(http.StatusOK, auth.TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.ExpiresAt,
	})
}

// Logout handles user logout
func (c *AuthController) Logout(ctx *gin.Context) {
	// Get user ID from context
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get refresh token from cookie
	refreshToken, err := ctx.Cookie(c.Config.Auth.SessionCookieName)
	if err != nil || refreshToken == "" {
		// If no cookie, still return success
		ctx.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	// Logout user
	err = c.Service.Logout(ctx.Request.Context(), auth.LogoutInput{
		UserID:       userID.(string),
		RefreshToken: refreshToken,
		ClientIP:     ctx.ClientIP(),
		UserAgent:    ctx.Request.UserAgent(),
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	// Clear cookie
	ctx.SetCookie(
		c.Config.Auth.SessionCookieName,
		"",
		-1, // MaxAge
		"/",
		c.Config.Auth.CookieDomain,
		c.Config.Auth.CookieSecure,
		true, // HttpOnly
	)

	ctx.JSON(http.StatusOK, gin.H{"success": true})
}

// RefreshToken handles token refresh
func (c *AuthController) RefreshToken(ctx *gin.Context) {
	// Get refresh token from cookie or request body
	var refreshToken string

	// Try to get from cookie first
	refreshToken, err := ctx.Cookie(c.Config.Auth.SessionCookieName)
	if err != nil || refreshToken == "" {
		// Try to get from request body
		var req auth.RefreshTokenRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		refreshToken = req.RefreshToken
	}

	// Validate refresh token
	if refreshToken == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
		return
	}

	// Refresh token
	result, err := c.Service.RefreshToken(ctx.Request.Context(), auth.RefreshTokenInput{
		RefreshToken: refreshToken,
		ClientIP:     ctx.ClientIP(),
		UserAgent:    ctx.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrTokenInvalid, auth.ErrTokenRevoked:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	// Set new refresh token cookie
	ctx.SetCookie(
		c.Config.Auth.SessionCookieName,
		result.RefreshToken,
		int(c.Config.Auth.RefreshTokenExpiry.Seconds()),
		"/",
		c.Config.Auth.CookieDomain,
		c.Config.Auth.CookieSecure,
		true, // HttpOnly
	)

	// Return new access token
	ctx.JSON(http.StatusOK, auth.TokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt,
	})
}
