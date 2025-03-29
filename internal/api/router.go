package api

import (
	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/example/auth-service/internal/middleware"
	"github.com/gin-gonic/gin"
)

// Router is the HTTP router for the API
type Router struct {
	Config      *config.Config
	AuthHandler *auth.Handler
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Config, authHandler *auth.Handler) *Router {
	return &Router{
		Config:      cfg,
		AuthHandler: authHandler,
	}
}

// Setup sets up the router and returns the HTTP handler
func (r *Router) Setup() *gin.Engine {
	// Set gin mode based on environment
	if r.Config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else if r.Config.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.TestMode)
	}

	router := gin.New()

	// Set trusted proxies
	// Use specific IP ranges for production
	if r.Config.Environment == "production" {
		// Set specific trusted proxy IPs for production
		// Example: router.SetTrustedProxies([]string{"192.168.1.1", "10.0.0.1"})
		router.SetTrustedProxies([]string{}) // Empty slice means trust no proxies
	} else {
		// For local development, you might trust localhost
		router.SetTrustedProxies([]string{"127.0.0.1"})
	}

	// Global middleware
	router.Use(gin.Recovery())
	if r.Config.Debug {
		router.Use(gin.Logger())
	}

	// Use custom security middleware
	securityMiddleware := middleware.NewSecurityMiddleware(r.Config)
	router.Use(r.ginSecurityHeadersMiddleware(securityMiddleware))

	// CORS middleware
	router.Use(r.ginCorsMiddleware())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Auth routes - public
	auth := router.Group("/auth")
	{
		auth.POST("/register", r.AuthHandler.GinRegister)
		auth.POST("/login", r.AuthHandler.GinLogin)
		auth.POST("/refresh", r.AuthHandler.GinRefreshToken)

		// Auth routes - protected
		protected := auth.Group("")
		protected.Use(middleware.GinAuthMiddleware(r.Config))
		protected.POST("/logout", r.AuthHandler.GinLogout)
	}

	return router
}

// ginCorsMiddleware adds CORS headers to the response
func (r *Router) ginCorsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set CORS headers
		if r.Config.Environment != "production" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else if len(r.Config.AllowedOrigins) > 0 {
			// Check if origin is allowed
			origin := c.Request.Header.Get("Origin")
			for _, allowed := range r.Config.AllowedOrigins {
				if allowed == origin || allowed == "*" {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

// ginSecurityHeadersMiddleware converts the security headers middleware to gin
func (r *Router) ginSecurityHeadersMiddleware(securityMiddleware *middleware.SecurityMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content-Security-Policy to prevent XSS attacks
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self'; style-src 'self'; frame-ancestors 'none'")

		// X-Content-Type-Options to prevent MIME sniffing
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")

		// X-Frame-Options to prevent clickjacking
		c.Writer.Header().Set("X-Frame-Options", "DENY")

		// X-XSS-Protection for older browsers that don't support CSP
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy to control how much referrer info is included
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Strict-Transport-Security to enforce HTTPS
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Cache control for sensitive pages
		if c.Request.URL.Path == "/auth/login" || c.Request.URL.Path == "/auth/register" {
			c.Writer.Header().Set("Cache-Control", "no-store, max-age=0")
			c.Writer.Header().Set("Pragma", "no-cache")
			c.Writer.Header().Set("Expires", "0")
		}

		c.Next()
	}
}
