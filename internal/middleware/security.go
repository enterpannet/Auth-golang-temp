package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/crypto"
	"golang.org/x/time/rate"
)

// SecurityMiddleware provides security-related middleware
type SecurityMiddleware struct {
	Config *config.Config
	// Map to store rate limiters per IP
	ipLimiters     map[string]*rate.Limiter
	loginLimiters  map[string]*rateLimiterWithExpiry
	signupLimiters map[string]*rateLimiterWithExpiry
}

// rateLimiterWithExpiry adds expiration to rate limiter
type rateLimiterWithExpiry struct {
	limiter  *rate.Limiter
	expireAt time.Time
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(cfg *config.Config) *SecurityMiddleware {
	return &SecurityMiddleware{
		Config:         cfg,
		ipLimiters:     make(map[string]*rate.Limiter),
		loginLimiters:  make(map[string]*rateLimiterWithExpiry),
		signupLimiters: make(map[string]*rateLimiterWithExpiry),
	}
}

// SecurityHeaders adds security headers to prevent XSS, clickjacking, etc.
func (s *SecurityMiddleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content-Security-Policy to prevent XSS attacks
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self'; style-src 'self'; frame-ancestors 'none'")

		// X-Content-Type-Options to prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// X-Frame-Options to prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// X-XSS-Protection for older browsers that don't support CSP
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy to control how much referrer info is included
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Strict-Transport-Security to enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Cache control for sensitive pages
		if strings.HasPrefix(r.URL.Path, "/api/auth") {
			w.Header().Set("Cache-Control", "no-store, max-age=0")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimiter limits the number of requests per IP address
func (s *SecurityMiddleware) RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if disabled
		if !s.Config.Security.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Check whitelist
		for _, whiteIP := range s.Config.Security.RateLimit.WhitelistedIPs {
			if clientIP == whiteIP {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check blacklist
		for _, blackIP := range s.Config.Security.RateLimit.BlacklistedIPs {
			if clientIP == blackIP {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		// Get or create rate limiter for this IP
		limiter, exists := s.ipLimiters[clientIP]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(s.Config.Security.RateLimit.RequestsPerSecond), s.Config.Security.RateLimit.Burst)
			s.ipLimiters[clientIP] = limiter
		}

		// Allow or reject request based on rate limit
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoginRateLimiter specifically limits login attempts by IP address
func (s *SecurityMiddleware) LoginRateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to login endpoint and POST method
		if r.URL.Path != "/api/auth/login" || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Skip rate limiting if disabled
		if !s.Config.Security.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Get current time
		now := time.Now()

		// Clean expired limiters
		for ip, limiter := range s.loginLimiters {
			if now.After(limiter.expireAt) {
				delete(s.loginLimiters, ip)
			}
		}

		// Get or create rate limiter for this IP
		limiter, exists := s.loginLimiters[clientIP]
		if !exists {
			limiter = &rateLimiterWithExpiry{
				limiter:  rate.NewLimiter(rate.Limit(s.Config.Security.RateLimit.LoginLimitPerIP), s.Config.Security.RateLimit.LoginLimitPerIP),
				expireAt: now.Add(s.Config.Security.RateLimit.LoginLimitExpiry),
			}
			s.loginLimiters[clientIP] = limiter
		}

		// Allow or reject request based on rate limit
		if !limiter.limiter.Allow() {
			http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RegistrationRateLimiter limits user registration attempts by IP address
func (s *SecurityMiddleware) RegistrationRateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to registration endpoint and POST method
		if r.URL.Path != "/api/auth/register" || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Skip rate limiting if disabled
		if !s.Config.Security.RateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Get current time
		now := time.Now()

		// Clean expired limiters
		for ip, limiter := range s.signupLimiters {
			if now.After(limiter.expireAt) {
				delete(s.signupLimiters, ip)
			}
		}

		// Get or create rate limiter for this IP
		limiter, exists := s.signupLimiters[clientIP]
		if !exists {
			limiter = &rateLimiterWithExpiry{
				limiter:  rate.NewLimiter(rate.Limit(s.Config.Security.RateLimit.RegisterLimitPerIP), s.Config.Security.RateLimit.RegisterLimitPerIP),
				expireAt: now.Add(s.Config.Security.RateLimit.RegisterLimitExpiry),
			}
			s.signupLimiters[clientIP] = limiter
		}

		// Allow or reject request based on rate limit
		if !limiter.limiter.Allow() {
			http.Error(w, "Too many registration attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CSRF generates and validates CSRF tokens
type CSRF struct {
	Config     *config.Config
	Encryptor  *crypto.Encryptor
	CookieName string
	HeaderName string
	FormField  string
}

// NewCSRF creates a new CSRF middleware
func NewCSRF(cfg *config.Config, enc *crypto.Encryptor) *CSRF {
	return &CSRF{
		Config:     cfg,
		Encryptor:  enc,
		CookieName: cfg.Security.CSRFTokenName,
		HeaderName: "X-CSRF-Token",
		FormField:  "csrf_token",
	}
}

// Middleware provides CSRF protection
func (c *CSRF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF check if disabled
		if !c.Config.Security.EnableCSRFProtection {
			next.ServeHTTP(w, r)
			return
		}

		// Don't check CSRF for GET, HEAD, OPTIONS, TRACE
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || r.Method == http.MethodTrace {
			// Generate a new token for these methods
			token, err := c.generateToken()
			if err == nil {
				c.setTokenCookie(w, token)
			}
			next.ServeHTTP(w, r)
			return
		}

		// For all other methods, validate CSRF token
		// Get the token from the request
		requestToken := c.getRequestToken(r)
		cookieToken := c.getCookieToken(r)

		// If either token is missing, reject the request
		if requestToken == "" || cookieToken == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		// Compare tokens
		if !c.compareTokens(requestToken, cookieToken) {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		// Generate a new token for the next request
		newToken, err := c.generateToken()
		if err == nil {
			c.setTokenCookie(w, newToken)
		}

		next.ServeHTTP(w, r)
	})
}

// generateToken creates a new CSRF token
func (c *CSRF) generateToken() (string, error) {
	// Generate random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode as base64
	token := base64.StdEncoding.EncodeToString(bytes)

	return token, nil
}

// setTokenCookie sets the CSRF token cookie
func (c *CSRF) setTokenCookie(w http.ResponseWriter, token string) {
	// Get expiration time
	expiry := time.Now().Add(c.Config.Security.CSRFTokenExpiry)

	// Set the cookie
	cookie := &http.Cookie{
		Name:     c.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Config.Auth.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiry,
	}

	// Set domain if configured
	if c.Config.Auth.CookieDomain != "" {
		cookie.Domain = c.Config.Auth.CookieDomain
	}

	http.SetCookie(w, cookie)
}

// getRequestToken gets the token from the request (header or form)
func (c *CSRF) getRequestToken(r *http.Request) string {
	// Check header first
	token := r.Header.Get(c.HeaderName)
	if token != "" {
		return token
	}

	// Check form field
	err := r.ParseForm()
	if err == nil {
		token = r.Form.Get(c.FormField)
	}

	return token
}

// getCookieToken gets the token from the cookie
func (c *CSRF) getCookieToken(r *http.Request) string {
	cookie, err := r.Cookie(c.CookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// compareTokens compares two tokens for equality
func (c *CSRF) compareTokens(token1, token2 string) bool {
	return token1 == token2
}

// GetToken puts a CSRF token in the context
func (c *CSRF) GetToken(ctx context.Context) (string, error) {
	token, err := c.generateToken()
	if err != nil {
		return "", err
	}
	return token, nil
}

// Require404 returns 404 for all requests
func Require404(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
}

// RecoverPanic recovers from panics and logs them
func RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the error
				fmt.Printf("PANIC: %v\n", err)

				// Return a 500 Internal Server Error response
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP address from a request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Try X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}
