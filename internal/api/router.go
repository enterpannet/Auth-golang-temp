package api

import (
	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/example/auth-service/internal/controllers"
	"github.com/example/auth-service/internal/crypto"
	"github.com/example/auth-service/internal/middleware"
	"github.com/example/auth-service/internal/webhook"
	"github.com/gin-gonic/gin"
)

// Router is the HTTP router for the API
type Router struct {
	Config         *config.Config
	AuthService    *auth.Service
	WebhookService *webhook.WebhookService
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Config, authService *auth.Service, webhookService *webhook.WebhookService) *Router {
	return &Router{
		Config:         cfg,
		AuthService:    authService,
		WebhookService: webhookService,
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

	// Create controllers
	authController := controllers.NewAuthController(r.Config, r.AuthService)
	mfaController := controllers.NewMFAController(r.Config, r.AuthService)
	adminController := controllers.NewAdminController(r.Config, r.AuthService)
	verificationController := controllers.NewVerificationController(r.Config, r.AuthService)

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Auth routes - public
	auth := router.Group("/auth")
	{
		auth.POST("/register", authController.Register)
		auth.POST("/login", authController.Login)
		auth.POST("/refresh", authController.RefreshToken)

		// Auth routes - protected
		protected := auth.Group("")
		protected.Use(middleware.GinAuthMiddleware(r.Config))
		protected.POST("/logout", authController.Logout)

		// MFA routes - protected
		mfa := protected.Group("/mfa")
		{
			// Setup MFA - returns secret and QR code URL
			mfa.POST("/setup", mfaController.SetupMFA)

			// Verify and enable MFA with a TOTP code
			mfa.POST("/verify", mfaController.VerifyMFA)

			// Disable MFA
			mfa.POST("/disable", mfaController.DisableMFA)

			// Generate new backup codes
			mfa.POST("/backup-codes", mfaController.GenerateBackupCodes)
		}

		// Email verification routes
		auth.GET("/verify-email", verificationController.VerifyEmail)
		auth.GET("/resend-verification", middleware.GinAuthMiddleware(r.Config), verificationController.ResendVerificationEmail)
	}

	// Example CRUD API routes
	// This demonstrates how to structure both public and protected routes
	api := router.Group("/api/v1")
	{
		// Public routes - no authentication required
		// Example: Product listing and details can be viewed without login
		products := api.Group("/products")
		{
			products.GET("", r.handleListProducts)          // List all products
			products.GET("/:id", r.handleGetProduct)        // Get a product by ID
			products.GET("/search", r.handleSearchProducts) // Search products
		}

		// Protected routes - authentication required
		// Adding the GinAuthMiddleware to the group makes all routes inside require authentication
		protected := api.Group("")
		protected.Use(middleware.GinAuthMiddleware(r.Config))
		{
			// User profile - requires authentication
			users := protected.Group("/users")
			{
				users.GET("/me", r.handleGetCurrentUser)              // Get current user profile
				users.PUT("/me", r.handleUpdateCurrentUser)           // Update current user profile
				users.DELETE("/me", r.handleDeleteCurrentUser)        // Delete current user account
				users.GET("/me/orders", r.handleGetCurrentUserOrders) // Get current user orders
			}

			// Admin routes - requires authentication + admin role
			// You can add role-based middleware here if needed
			admin := protected.Group("/admin")
			admin.Use(r.adminRoleRequired())
			{
				// User management (admin only)
				admin.GET("/users", adminController.ListUsers)                             // List all users
				admin.GET("/users/:id", adminController.GetUser)                           // Get a user by ID
				admin.POST("/users", adminController.CreateUser)                           // Create a user
				admin.PUT("/users/:id", adminController.UpdateUser)                        // Update a user
				admin.DELETE("/users/:id", adminController.DeleteUser)                     // Delete a user
				admin.POST("/users/:id/reset-password", adminController.ResetUserPassword) // Reset user password

				// Roles management
				admin.GET("/roles", adminController.ListRoles) // List all roles

				// Product management (admin only) - Legacy examples
				admin.POST("/products", r.handleCreateProduct)       // Create a product
				admin.PUT("/products/:id", r.handleUpdateProduct)    // Update a product
				admin.DELETE("/products/:id", r.handleDeleteProduct) // Delete a product
			}

			// Customer specific routes - requires authentication
			orders := protected.Group("/orders")
			{
				orders.POST("", r.handleCreateOrder)           // Create an order
				orders.GET("", r.handleListOrders)             // List user's orders
				orders.GET("/:id", r.handleGetOrder)           // Get order by ID
				orders.PUT("/:id/cancel", r.handleCancelOrder) // Cancel an order
			}
		}
	}

	// Webhook routes
	webhooks := router.Group("/webhooks")
	{
		webhooks.POST("/line", func(c *gin.Context) {
			r.WebhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformLine)
		})

		// Facebook needs both GET (for verification) and POST (for events)
		webhooks.Any("/facebook", func(c *gin.Context) {
			r.WebhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformFacebook)
		})

		webhooks.POST("/twitter", func(c *gin.Context) {
			r.WebhookService.HandleWebhook(c.Writer, c.Request, webhook.PlatformTwitter)
		})
	}

	return router
}

// adminRoleRequired middleware checks if the user has admin role
func (r *Router) adminRoleRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get claims from context
		claims, exists := c.Get("user_claims")
		if !exists {
			c.JSON(403, gin.H{"error": "Forbidden: admin access required"})
			c.Abort()
			return
		}

		// Type assert to get roles
		claimsObj, ok := claims.(*crypto.Claims)
		if !ok {
			c.JSON(403, gin.H{"error": "Forbidden: invalid claims"})
			c.Abort()
			return
		}

		// Check if user has admin role
		hasAdminRole := false
		for _, role := range claimsObj.Roles {
			if role == "admin" {
				hasAdminRole = true
				break
			}
		}

		if !hasAdminRole {
			c.JSON(403, gin.H{"error": "Forbidden: admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Example handler implementations (placeholders)
func (r *Router) handleListProducts(c *gin.Context) {
	// Example implementation
	c.JSON(200, gin.H{"products": []gin.H{
		{"id": "1", "name": "Product 1", "price": 99.99},
		{"id": "2", "name": "Product 2", "price": 149.99},
	}})
}

func (r *Router) handleGetProduct(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{"id": id, "name": "Product " + id, "price": 99.99})
}

func (r *Router) handleSearchProducts(c *gin.Context) {
	query := c.Query("q")
	c.JSON(200, gin.H{"query": query, "products": []gin.H{
		{"id": "1", "name": "Product 1", "price": 99.99},
	}})
}

func (r *Router) handleGetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	c.JSON(200, gin.H{"id": userID, "name": "Current User", "email": "user@example.com"})
}

func (r *Router) handleUpdateCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	c.JSON(200, gin.H{"id": userID, "message": "User updated successfully"})
}

func (r *Router) handleDeleteCurrentUser(c *gin.Context) {
	c.JSON(200, gin.H{"message": "User deleted successfully"})
}

func (r *Router) handleGetCurrentUserOrders(c *gin.Context) {
	userID, _ := c.Get("user_id")
	c.JSON(200, gin.H{"user_id": userID, "orders": []gin.H{
		{"id": "1", "total": 99.99, "status": "completed"},
		{"id": "2", "total": 149.99, "status": "processing"},
	}})
}

func (r *Router) handleCreateProduct(c *gin.Context) {
	c.JSON(201, gin.H{"id": "3", "message": "Product created successfully"})
}

func (r *Router) handleUpdateProduct(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{"id": id, "message": "Product updated successfully"})
}

func (r *Router) handleDeleteProduct(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{"id": id, "message": "Product deleted successfully"})
}

func (r *Router) handleCreateOrder(c *gin.Context) {
	userID, _ := c.Get("user_id")
	c.JSON(201, gin.H{"user_id": userID, "order_id": "3", "message": "Order created successfully"})
}

func (r *Router) handleListOrders(c *gin.Context) {
	userID, _ := c.Get("user_id")
	c.JSON(200, gin.H{"user_id": userID, "orders": []gin.H{
		{"id": "1", "total": 99.99, "status": "completed"},
		{"id": "2", "total": 149.99, "status": "processing"},
	}})
}

func (r *Router) handleGetOrder(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("user_id")
	c.JSON(200, gin.H{"id": id, "user_id": userID, "total": 99.99, "status": "completed"})
}

func (r *Router) handleCancelOrder(c *gin.Context) {
	id := c.Param("id")
	c.JSON(200, gin.H{"id": id, "message": "Order cancelled successfully"})
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
