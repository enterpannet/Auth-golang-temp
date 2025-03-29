package database

import (
	"context"
	"fmt"
	"time"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database represents a database connection
type Database struct {
	DB     *gorm.DB
	Config *config.Config
}

// New creates a new database connection
func New(cfg *config.Config) (*Database, error) {
	// Create the connection string
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	// Set up GORM logger based on app config
	var logLevel logger.LogLevel
	switch cfg.Environment {
	case "debug":
		logLevel = logger.Info
	case "info":
		logLevel = logger.Info
	case "warn", "warning":
		logLevel = logger.Warn
	case "error":
		logLevel = logger.Error
	default:
		logLevel = logger.Silent
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	}

	// Connect to the database
	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.Database.MaxOpenConns) * time.Minute)

	return &Database{
		DB:     db,
		Config: cfg,
	}, nil
}

// Migrate automatically migrates the database schema
func (d *Database) Migrate() error {
	// Auto-migrate the schema
	err := d.DB.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Role{},
		&models.Permission{},
		&models.AuditLog{},
		&models.OAuthAccount{},
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Create default roles and permissions if they don't exist
	tx := d.DB.Begin()

	// Create default roles
	roles := []models.Role{
		{Name: "admin", Description: "Administrator with full system access"},
		{Name: "user", Description: "Regular user with limited access"},
	}

	for _, role := range roles {
		if err := tx.Where("name = ?", role.Name).FirstOrCreate(&role).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create default role %s: %w", role.Name, err)
		}
	}

	// Create default permissions
	permissions := []models.Permission{
		{Name: "user:read", Description: "Read user information", Resource: "user", Action: "read"},
		{Name: "user:create", Description: "Create users", Resource: "user", Action: "create"},
		{Name: "user:update", Description: "Update user information", Resource: "user", Action: "update"},
		{Name: "user:delete", Description: "Delete users", Resource: "user", Action: "delete"},
		{Name: "role:read", Description: "Read role information", Resource: "role", Action: "read"},
		{Name: "role:create", Description: "Create roles", Resource: "role", Action: "create"},
		{Name: "role:update", Description: "Update role information", Resource: "role", Action: "update"},
		{Name: "role:delete", Description: "Delete roles", Resource: "role", Action: "delete"},
	}

	for _, perm := range permissions {
		if err := tx.Where("name = ?", perm.Name).FirstOrCreate(&perm).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create default permission %s: %w", perm.Name, err)
		}
	}

	// Assign all permissions to admin role
	var adminRole models.Role
	if err := tx.Where("name = ?", "admin").First(&adminRole).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to find admin role: %w", err)
	}

	var allPermissions []models.Permission
	if err := tx.Find(&allPermissions).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to get all permissions: %w", err)
	}

	if err := tx.Model(&adminRole).Association("Permissions").Append(allPermissions); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to assign permissions to admin role: %w", err)
	}

	// Assign user:read and user:update permissions to user role
	var userRole models.Role
	if err := tx.Where("name = ?", "user").First(&userRole).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to find user role: %w", err)
	}

	var userPermissions []models.Permission
	if err := tx.Where("name IN ?", []string{"user:read", "user:update"}).Find(&userPermissions).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to get user permissions: %w", err)
	}

	if err := tx.Model(&userRole).Association("Permissions").Append(userPermissions); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to assign permissions to user role: %w", err)
	}

	return tx.Commit().Error
}

// Close closes the database connection
func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}
	return sqlDB.Close()
}

// Ping checks if the database connection is healthy
func (d *Database) Ping() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}

	ctx, cancel := d.createPingContext()
	defer cancel()

	return sqlDB.PingContext(ctx)
}

// createPingContext creates a context with timeout for ping operations
func (d *Database) createPingContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}
