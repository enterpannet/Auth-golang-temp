package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/crypto"
	"github.com/example/auth-service/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Common errors
var (
	ErrNoAuthHeader      = errors.New("authorization header is required")
	ErrInvalidAuthHeader = errors.New("invalid authorization format")
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserLocked        = errors.New("user account is locked")
	ErrInsufficientPerms = errors.New("insufficient permissions")
)

// AuthMiddleware handles authentication for protected routes
type AuthMiddleware struct {
	Config     *config.Config
	JWTManager *crypto.JWTManager
	DB         *gorm.DB
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(cfg *config.Config) *AuthMiddleware {
	jwtManager := crypto.NewJWTManager(cfg)

	return &AuthMiddleware{
		Config:     cfg,
		JWTManager: jwtManager,
	}
}

// Authenticate validates the JWT token and adds user info to the request context
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendJSONError(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Check format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			sendJSONError(w, "Invalid authorization format, should be 'Bearer <token>'", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		if token == "" {
			sendJSONError(w, "Token is required", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := m.JWTManager.ValidateToken(token)
		if err != nil {
			sendJSONError(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		userID := claims.Subject
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", userID)
		ctx = context.WithValue(ctx, "user_claims", claims)

		// Proceed to next handler with new context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GinAuthMiddleware validates the JWT token for Gin routes
func GinAuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	jwtManager := crypto.NewJWTManager(cfg)

	return func(c *gin.Context) {
		// Get token from header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Check format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format, should be 'Bearer <token>'"})
			c.Abort()
			return
		}

		token := parts[1]
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is required"})
			c.Abort()
			return
		}

		// Validate token
		claims, err := jwtManager.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Add claims to context
		userID := claims.Subject
		c.Set("user_id", userID)
		c.Set("user_claims", claims)
		c.Next()
	}
}

// sendJSONError sends a JSON error response
func sendJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, message)))
}

// RequireRole checks if the user has a specific role
func (a *AuthMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user roles from context
			ctxRoles, ok := r.Context().Value("user_roles").([]string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if the user has the required role
			hasRole := false
			for _, r := range ctxRoles {
				if r == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission checks if the user has a specific permission
func (a *AuthMiddleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user permissions from context
			ctxPermissions, ok := r.Context().Value("user_permissions").([]string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if the user has the required permission
			hasPermission := false
			for _, p := range ctxPermissions {
				if p == permission {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireVerifiedEmail checks if the user's email is verified
func (a *AuthMiddleware) RequireVerifiedEmail(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get email verified status from context
		isVerified, ok := r.Context().Value("is_email_verified").(bool)
		if !ok || !isVerified {
			http.Error(w, "Email verification required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireMFA checks if the user has MFA enabled
func (a *AuthMiddleware) RequireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from context
		userID, ok := r.Context().Value("user_id").(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user from database
		var user models.User
		result := a.DB.First(&user, "id = ?", userID)
		if result.Error != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Check if MFA is enabled
		if !user.TOTPEnabled {
			http.Error(w, "MFA required for this operation", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext gets the user from the database using the ID from context
func (a *AuthMiddleware) GetUserFromContext(r *http.Request) (*models.User, error) {
	// Get user ID from context
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Get user from database
	var user models.User
	result := a.DB.Preload("Roles.Permissions").First(&user, "id = ?", userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}

	return &user, nil
}

// HasPermission checks if the user has a specific permission
func HasPermission(ctx context.Context, permission string) bool {
	// Get user permissions from context
	ctxPermissions, ok := ctx.Value("user_permissions").([]string)
	if !ok {
		return false
	}

	// Check if the user has the required permission
	for _, p := range ctxPermissions {
		if p == permission {
			return true
		}
	}

	return false
}

// HasRole checks if the user has a specific role
func HasRole(ctx context.Context, role string) bool {
	// Get user roles from context
	ctxRoles, ok := ctx.Value("user_roles").([]string)
	if !ok {
		return false
	}

	// Check if the user has the required role
	for _, r := range ctxRoles {
		if r == role {
			return true
		}
	}

	return false
}

// IsEmailVerified checks if the user's email is verified
func IsEmailVerified(ctx context.Context) bool {
	// Get email verified status from context
	isVerified, ok := ctx.Value("is_email_verified").(bool)
	return ok && isVerified
}
