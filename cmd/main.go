package main

import (
	"log"

	"github.com/PTSS-Support/identity-service/api/controllers"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/core/services"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	keycloakRepo := repositories.NewKeycloakRepository(&cfg.Keycloak)
	authService := services.NewAuthService(keycloakRepo)
	authFacade := facades.NewAuthFacade(authService)
	authController := controllers.NewAuthController(authFacade)

	// Setup Gin in appropriate mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DisableConsoleColor()
	}
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Register routes
	authController.RegisterRoutes(r)

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"version": "1.0.0",
		})
	})

	// Start server
	if err := r.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
