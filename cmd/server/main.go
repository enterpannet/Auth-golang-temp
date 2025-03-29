package main

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/example/auth-service/config"
	"github.com/example/auth-service/internal/api"
	"github.com/example/auth-service/internal/auth"
	"github.com/example/auth-service/internal/crypto"
	"github.com/example/auth-service/internal/database"
	"github.com/example/auth-service/internal/logging"
	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg := config.DefaultConfig()

	// Create dependencies
	jwtManager := crypto.NewJWTManager(cfg)
	passwordHasher := crypto.NewPasswordHasher(cfg)

	// Check if database exists and create if not
	if err := ensureDatabaseExists(cfg); err != nil {
		log.Fatalf("Failed to ensure database exists: %v", err)
	}

	// Setup database
	db, err := database.New(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations if needed
	if cfg.Database.AutoMigrate {
		if err := db.Migrate(); err != nil {
			log.Fatalf("Failed to migrate database: %v", err)
		}
	}

	// Create TOTP manager
	totpManager := crypto.NewTOTPManager(cfg)

	// Create OAuth manager
	oauthManager := crypto.NewOAuthManager(cfg)

	// Create encryptor
	encryptor := crypto.NewEncryptor(cfg)

	// Create audit logger
	auditLogger, err := logging.NewAuditLogger(db.DB, cfg)
	if err != nil {
		log.Fatalf("Failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	// Create auth service with all dependencies
	authService := auth.NewService(
		cfg,
		db.DB,
		passwordHasher,
		jwtManager,
		totpManager,
		oauthManager,
		encryptor,
		auditLogger,
	)

	// Create auth handler
	authHandler := auth.NewHandler(cfg, authService)

	// Setup router
	router := api.NewRouter(cfg, authHandler)
	ginEngine := router.Setup()

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Starting server on %s", addr)
	log.Fatal(ginEngine.Run(addr))
}

// ensureDatabaseExists checks if the database exists and creates it if not
func ensureDatabaseExists(cfg *config.Config) error {
	// Connect to postgres database to check if our target DB exists
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer db.Close()

	// Check if database exists
	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT datname FROM pg_catalog.pg_database WHERE datname = '%s')", cfg.Database.Name)
	err = db.QueryRow(query).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if database exists: %w", err)
	}

	// Create database if it doesn't exist
	if !exists {
		log.Printf("Database %s does not exist, creating it now", cfg.Database.Name)
		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", cfg.Database.Name))
		if err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
		log.Printf("Database %s created successfully", cfg.Database.Name)
	} else {
		log.Printf("Database %s already exists", cfg.Database.Name)
	}

	return nil
}
