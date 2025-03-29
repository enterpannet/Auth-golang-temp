package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/example/auth-service/config"
	"github.com/gin-gonic/gin"
)

// Handler handles HTTP requests for auth operations
type Handler struct {
	Config  *config.Config
	Service *Service
}

// NewHandler creates a new auth handler
func NewHandler(cfg *config.Config, service *Service) *Handler {
	return &Handler{
		Config:  cfg,
		Service: service,
	}
}

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Email           string `json:"email"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPCode   string `json:"totp_code,omitempty"`
	RememberMe bool   `json:"remember_me,omitempty"`
}

// RefreshTokenRequest represents the request body for refreshing tokens
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse represents the response for token-related endpoints
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RequiresMFA  bool      `json:"requires_mfa,omitempty"`
}

// errorResponse represents a JSON error response
type errorResponse struct {
	Error string `json:"error"`
}

// Register handles user registration
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Username == "" || req.Password == "" || req.ConfirmPassword == "" {
		sendJSONError(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Register user
	result, err := h.Service.RegisterUser(r.Context(), RegisterUserInput{
		Email:           req.Email,
		Username:        req.Username,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		ClientIP:        getClientIP(r),
		UserAgent:       r.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrEmailAlreadyExists, ErrUsernameAlreadyExists:
			sendJSONError(w, err.Error(), http.StatusConflict)
		case ErrPasswordTooWeak:
			sendJSONError(w, err.Error(), http.StatusBadRequest)
		default:
			sendJSONError(w, "Registration failed", http.StatusInternalServerError)
		}
		return
	}

	// Return JWT token
	sendJSON(w, TokenResponse{
		AccessToken: result.Token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(h.Config.Auth.AccessTokenExpiry),
	}, http.StatusCreated)
}

// Login handles user login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		sendJSONError(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Login user
	result, err := h.Service.Login(r.Context(), LoginInput{
		Email:      req.Email,
		Password:   req.Password,
		TOTPCode:   req.TOTPCode,
		RememberMe: req.RememberMe,
		ClientIP:   getClientIP(r),
		UserAgent:  r.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrInvalidCredentials:
			sendJSONError(w, "Invalid email or password", http.StatusUnauthorized)
		case ErrAccountLocked:
			sendJSONError(w, "Account is locked", http.StatusForbidden)
		case ErrMFAInvalid:
			sendJSONError(w, "Invalid MFA code", http.StatusUnauthorized)
		default:
			sendJSONError(w, "Login failed", http.StatusInternalServerError)
		}
		return
	}

	// Check if MFA is required
	if result.RequiresMFA {
		sendJSON(w, map[string]interface{}{
			"requires_mfa": true,
		}, http.StatusOK)
		return
	}

	// Set refresh token cookie
	if result.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     h.Config.Auth.SessionCookieName,
			Value:    result.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   h.Config.Auth.CookieSecure,
			SameSite: convertSameSite(h.Config.Auth.CookieSameSite),
			Expires:  time.Now().Add(h.Config.Auth.RefreshTokenExpiry),
		})
	}

	// Return JWT token
	sendJSON(w, TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.ExpiresAt,
	}, http.StatusOK)
}

// Logout handles user logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		sendJSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get refresh token from cookie
	cookie, err := r.Cookie(h.Config.Auth.SessionCookieName)
	if err != nil || cookie.Value == "" {
		// If no cookie, still return success
		sendJSON(w, map[string]bool{"success": true}, http.StatusOK)
		return
	}

	// Logout user
	err = h.Service.Logout(r.Context(), LogoutInput{
		UserID:       userID,
		RefreshToken: cookie.Value,
		ClientIP:     getClientIP(r),
		UserAgent:    r.UserAgent(),
	})

	if err != nil {
		sendJSONError(w, "Logout failed", http.StatusInternalServerError)
		return
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Config.Auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Config.Auth.CookieSecure,
		SameSite: convertSameSite(h.Config.Auth.CookieSameSite),
		MaxAge:   -1,
	})

	sendJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// RefreshToken handles token refresh
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from cookie or request body
	var refreshToken string

	// Try to get from cookie first
	cookie, err := r.Cookie(h.Config.Auth.SessionCookieName)
	if err == nil && cookie.Value != "" {
		refreshToken = cookie.Value
	} else {
		// Try to get from request body
		var req RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		refreshToken = req.RefreshToken
	}

	// Validate refresh token
	if refreshToken == "" {
		sendJSONError(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	// Refresh token
	result, err := h.Service.RefreshToken(r.Context(), RefreshTokenInput{
		RefreshToken: refreshToken,
		ClientIP:     getClientIP(r),
		UserAgent:    r.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrTokenInvalid, ErrTokenRevoked:
			sendJSONError(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		default:
			sendJSONError(w, "Token refresh failed", http.StatusInternalServerError)
		}
		return
	}

	// Set new refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Config.Auth.SessionCookieName,
		Value:    result.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Config.Auth.CookieSecure,
		SameSite: convertSameSite(h.Config.Auth.CookieSameSite),
		Expires:  time.Now().Add(h.Config.Auth.RefreshTokenExpiry),
	})

	// Return new access token
	sendJSON(w, TokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt,
	}, http.StatusOK)
}

// Helper functions

// sendJSON sends a JSON response
func sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// sendJSONError sends a JSON error response
func sendJSONError(w http.ResponseWriter, message string, status int) {
	sendJSON(w, errorResponse{Error: message}, status)
}

// getClientIP gets the client IP from the request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	// Try X-Real-IP header
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

// convertSameSite converts a string same-site value to http.SameSite
func convertSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// GinRegister handles user registration for Gin
func (h *Handler) GinRegister(c *gin.Context) {
	// Parse request body
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate required fields
	if req.Email == "" || req.Username == "" || req.Password == "" || req.ConfirmPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	// Register user
	result, err := h.Service.RegisterUser(c.Request.Context(), RegisterUserInput{
		Email:           req.Email,
		Username:        req.Username,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		ClientIP:        c.ClientIP(),
		UserAgent:       c.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrEmailAlreadyExists, ErrUsernameAlreadyExists:
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case ErrPasswordTooWeak:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		}
		return
	}

	// Return JWT token
	c.JSON(http.StatusCreated, TokenResponse{
		AccessToken: result.Token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(h.Config.Auth.AccessTokenExpiry),
	})
}

// GinLogin handles user login for Gin
func (h *Handler) GinLogin(c *gin.Context) {
	// Parse request body
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	// Login user
	result, err := h.Service.Login(c.Request.Context(), LoginInput{
		Email:      req.Email,
		Password:   req.Password,
		TOTPCode:   req.TOTPCode,
		RememberMe: req.RememberMe,
		ClientIP:   c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		case ErrAccountLocked:
			c.JSON(http.StatusForbidden, gin.H{"error": "Account is locked"})
		case ErrMFAInvalid:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid MFA code"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	// Check if MFA is required
	if result.RequiresMFA {
		c.JSON(http.StatusOK, gin.H{"requires_mfa": true})
		return
	}

	// Set refresh token cookie
	if result.RefreshToken != "" {
		c.SetCookie(
			h.Config.Auth.SessionCookieName,
			result.RefreshToken,
			int(h.Config.Auth.RefreshTokenExpiry.Seconds()),
			"/",
			h.Config.Auth.CookieDomain,
			h.Config.Auth.CookieSecure,
			true, // HttpOnly
		)
	}

	// Return JWT token
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.ExpiresAt,
	})
}

// GinLogout handles user logout for Gin
func (h *Handler) GinLogout(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get refresh token from cookie
	refreshToken, err := c.Cookie(h.Config.Auth.SessionCookieName)
	if err != nil || refreshToken == "" {
		// If no cookie, still return success
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	// Logout user
	err = h.Service.Logout(c.Request.Context(), LogoutInput{
		UserID:       userID.(string),
		RefreshToken: refreshToken,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	// Clear cookie
	c.SetCookie(
		h.Config.Auth.SessionCookieName,
		"",
		-1, // MaxAge
		"/",
		h.Config.Auth.CookieDomain,
		h.Config.Auth.CookieSecure,
		true, // HttpOnly
	)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GinRefreshToken handles token refresh for Gin
func (h *Handler) GinRefreshToken(c *gin.Context) {
	// Get refresh token from cookie or request body
	var refreshToken string

	// Try to get from cookie first
	refreshToken, err := c.Cookie(h.Config.Auth.SessionCookieName)
	if err != nil || refreshToken == "" {
		// Try to get from request body
		var req RefreshTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		refreshToken = req.RefreshToken
	}

	// Validate refresh token
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
		return
	}

	// Refresh token
	result, err := h.Service.RefreshToken(c.Request.Context(), RefreshTokenInput{
		RefreshToken: refreshToken,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})

	if err != nil {
		switch err {
		case ErrTokenInvalid, ErrTokenRevoked:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	// Set new refresh token cookie
	c.SetCookie(
		h.Config.Auth.SessionCookieName,
		result.RefreshToken,
		int(h.Config.Auth.RefreshTokenExpiry.Seconds()),
		"/",
		h.Config.Auth.CookieDomain,
		h.Config.Auth.CookieSecure,
		true, // HttpOnly
	)

	// Return new access token
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt,
	})
}
