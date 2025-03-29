package controllers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/auth"
	"github.com/example/auth-service/internal/logging"
	"github.com/example/auth-service/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AdminController handles admin-related HTTP requests
type AdminController struct {
	Config  *config.Config
	Service *auth.Service
}

// NewAdminController creates a new admin controller
func NewAdminController(cfg *config.Config, service *auth.Service) *AdminController {
	return &AdminController{
		Config:  cfg,
		Service: service,
	}
}

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Email           string   `json:"email" binding:"required,email"`
	Username        string   `json:"username" binding:"required,min=3,max=50"`
	Password        string   `json:"password" binding:"required,min=8"`
	ConfirmPassword string   `json:"confirm_password" binding:"required,eqfield=Password"`
	FirstName       string   `json:"first_name"`
	LastName        string   `json:"last_name"`
	Roles           []string `json:"roles"`
	IsVerified      bool     `json:"is_verified"`
}

// UpdateUserRequest represents the request body for updating a user
type UpdateUserRequest struct {
	Email      string   `json:"email" binding:"omitempty,email"`
	Username   string   `json:"username" binding:"omitempty,min=3,max=50"`
	FirstName  string   `json:"first_name"`
	LastName   string   `json:"last_name"`
	Roles      []string `json:"roles"`
	IsVerified bool     `json:"is_verified"`
	IsLocked   bool     `json:"is_locked"`
}

// UserResponse represents the response for a user
type UserResponse struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	FirstName       string    `json:"first_name,omitempty"`
	LastName        string    `json:"last_name,omitempty"`
	Roles           []string  `json:"roles,omitempty"`
	IsEmailVerified bool      `json:"is_email_verified"`
	TOTPEnabled     bool      `json:"totp_enabled"`
	LastLogin       time.Time `json:"last_login,omitempty"`
	Locked          bool      `json:"locked"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ListUsers handles listing all users with pagination
func (c *AdminController) ListUsers(ctx *gin.Context) {
	var users []models.User
	var count int64

	// Parse query parameters
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	// Search filters
	search := ctx.Query("search")
	role := ctx.Query("role")

	// Base query
	query := c.Service.DB.Model(&models.User{})

	// Apply filters
	if search != "" {
		searchTerm := "%" + search + "%"
		query = query.Where("email LIKE ? OR username LIKE ? OR first_name LIKE ? OR last_name LIKE ?",
			searchTerm, searchTerm, searchTerm, searchTerm)
	}

	// Join with roles if role filter applied
	if role != "" {
		query = query.Joins("JOIN user_roles ON users.id = user_roles.user_id").
			Joins("JOIN roles ON user_roles.role_id = roles.id").
			Where("roles.name = ?", role)
	}

	// Get total count for pagination
	query.Count(&count)

	// Get users with roles
	err := query.Preload("Roles").Limit(limit).Offset(offset).Order("created_at DESC").Find(&users).Error
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	// Transform to response objects
	var responses []UserResponse
	for _, user := range users {
		responses = append(responses, userToResponse(user))
	}

	// Build pagination info
	totalPages := (count + int64(limit) - 1) / int64(limit)

	ctx.JSON(http.StatusOK, gin.H{
		"users": responses,
		"pagination": gin.H{
			"total":       count,
			"total_pages": totalPages,
			"page":        page,
			"limit":       limit,
		},
	})
}

// GetUser handles getting a single user by ID
func (c *AdminController) GetUser(ctx *gin.Context) {
	id := ctx.Param("id")

	var user models.User
	if err := c.Service.DB.Preload("Roles").First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	ctx.JSON(http.StatusOK, userToResponse(user))
}

// CreateUser handles creating a new user
func (c *AdminController) CreateUser(ctx *gin.Context) {
	var req CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate unique email and username
	var existingUser models.User
	if err := c.Service.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	if err := c.Service.DB.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Hash password
	passwordHash, err := c.Service.PasswordHash.HashPassword(req.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Begin transaction
	tx := c.Service.DB.Begin()
	if tx.Error != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Get roles
	var roles []models.Role
	if len(req.Roles) > 0 {
		if err := tx.Where("name IN ?", req.Roles).Find(&roles).Error; err != nil {
			tx.Rollback()
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "One or more roles not found"})
			return
		}
	} else {
		// Default to 'user' role if none specified
		if err := tx.Where("name = ?", "user").First(&roles).Error; err != nil {
			tx.Rollback()
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Default role not found"})
			return
		}
	}

	// Create user
	now := time.Now()
	user := models.User{
		Email:           req.Email,
		Username:        req.Username,
		PasswordHash:    passwordHash,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		IsEmailVerified: req.IsVerified,
		Roles:           roles,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if req.IsVerified {
		user.VerifiedAt = sql.NullTime{Time: now, Valid: true}
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log the user creation
	c.Service.AuditLogger.Log(ctx.Request.Context(), logging.AuditEvent{
		UserID:      ctx.GetString("user_id"),
		Action:      "create",
		Resource:    "user",
		ResourceID:  user.ID,
		ClientIP:    ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
		Success:     true,
		Description: "User created by admin",
		NewValue:    user,
	})

	// Return the created user
	ctx.JSON(http.StatusCreated, userToResponse(user))
}

// UpdateUser handles updating a user
func (c *AdminController) UpdateUser(ctx *gin.Context) {
	id := ctx.Param("id")

	var req UpdateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user
	var user models.User
	if err := c.Service.DB.Preload("Roles").First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	// Save old user for audit log
	oldUser := user

	// Begin transaction
	tx := c.Service.DB.Begin()
	if tx.Error != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Check email uniqueness if changed
	if req.Email != "" && req.Email != user.Email {
		var existingUser models.User
		if err := tx.Where("email = ? AND id != ?", req.Email, id).First(&existingUser).Error; err == nil {
			tx.Rollback()
			ctx.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
		user.Email = req.Email
	}

	// Check username uniqueness if changed
	if req.Username != "" && req.Username != user.Username {
		var existingUser models.User
		if err := tx.Where("username = ? AND id != ?", req.Username, id).First(&existingUser).Error; err == nil {
			tx.Rollback()
			ctx.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		user.Username = req.Username
	}

	// Update other fields
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Locked = req.IsLocked
	user.UpdatedAt = time.Now()

	// Update email verification if changed
	if req.IsVerified != user.IsEmailVerified {
		user.IsEmailVerified = req.IsVerified
		if req.IsVerified {
			user.VerifiedAt = sql.NullTime{Time: time.Now(), Valid: true}
		} else {
			user.VerifiedAt = sql.NullTime{Valid: false}
		}
	}

	// Update role associations if provided
	if len(req.Roles) > 0 {
		var roles []models.Role
		if err := tx.Where("name IN ?", req.Roles).Find(&roles).Error; err != nil {
			tx.Rollback()
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "One or more roles not found"})
			return
		}

		// Replace the roles
		if err := tx.Model(&user).Association("Roles").Replace(roles); err != nil {
			tx.Rollback()
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update roles"})
			return
		}
		user.Roles = roles
	}

	// Save user
	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log the user update
	c.Service.AuditLogger.Log(ctx.Request.Context(), logging.AuditEvent{
		UserID:      ctx.GetString("user_id"),
		Action:      "update",
		Resource:    "user",
		ResourceID:  user.ID,
		ClientIP:    ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
		Success:     true,
		Description: "User updated by admin",
		OldValue:    oldUser,
		NewValue:    user,
	})

	// Return the updated user
	ctx.JSON(http.StatusOK, userToResponse(user))
}

// DeleteUser handles deleting a user
func (c *AdminController) DeleteUser(ctx *gin.Context) {
	id := ctx.Param("id")

	// Check if user exists
	var user models.User
	if err := c.Service.DB.First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	// Check if attempting to delete themselves
	currentUserID := ctx.GetString("user_id")
	if currentUserID == id {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete yourself"})
		return
	}

	// Soft delete the user
	if err := c.Service.DB.Delete(&user).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	// Log the user deletion
	c.Service.AuditLogger.Log(ctx.Request.Context(), logging.AuditEvent{
		UserID:      ctx.GetString("user_id"),
		Action:      "delete",
		Resource:    "user",
		ResourceID:  user.ID,
		ClientIP:    ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
		Success:     true,
		Description: "User deleted by admin",
		OldValue:    user,
	})

	ctx.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ResetUserPassword resets a user's password
func (c *AdminController) ResetUserPassword(ctx *gin.Context) {
	id := ctx.Param("id")

	// Check if user exists
	var user models.User
	if err := c.Service.DB.First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	// Parse request
	var req struct {
		Password        string `json:"password" binding:"required,min=8"`
		ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate password strength
	if err := c.Service.PasswordHash.ValidatePasswordStrength(req.Password); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the new password
	hashedPassword, err := c.Service.PasswordHash.HashPassword(req.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update user's password
	if err := c.Service.DB.Model(&user).Updates(map[string]interface{}{
		"password_hash":         hashedPassword,
		"failed_login_attempts": 0,
		"locked":                false,
		"updated_at":            time.Now(),
	}).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Revoke all refresh tokens
	if err := c.Service.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", user.ID).
		Updates(map[string]interface{}{
			"revoked_at": sql.NullTime{Time: time.Now(), Valid: true},
		}).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke refresh tokens"})
		return
	}

	// Log the password reset
	c.Service.AuditLogger.Log(ctx.Request.Context(), logging.AuditEvent{
		UserID:      ctx.GetString("user_id"),
		Action:      "password_reset",
		Resource:    "user",
		ResourceID:  user.ID,
		ClientIP:    ctx.ClientIP(),
		UserAgent:   ctx.Request.UserAgent(),
		Success:     true,
		Description: "Password reset by admin",
	})

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// ListRoles handles listing all roles
func (c *AdminController) ListRoles(ctx *gin.Context) {
	var roles []models.Role

	if err := c.Service.DB.Preload("Permissions").Find(&roles).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch roles"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"roles": roles})
}

// Helper functions

// userToResponse converts a user model to a response object
func userToResponse(user models.User) UserResponse {
	// Extract role names
	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}

	lastLogin := time.Time{}
	if user.LastLogin.Valid {
		lastLogin = user.LastLogin.Time
	}

	return UserResponse{
		ID:              user.ID,
		Email:           user.Email,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		Roles:           roles,
		IsEmailVerified: user.IsEmailVerified,
		TOTPEnabled:     user.TOTPEnabled,
		LastLogin:       lastLogin,
		Locked:          user.Locked,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}
}
