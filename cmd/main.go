package main

import (
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"log"

	"github.com/PTSS-Support/identity-service/api/controllers"
	"github.com/PTSS-Support/identity-service/api/middleware"
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

	loggerFactory := util.NewLoggerFactory()

	// Initialize dependencies
	baseKeycloakRepo := repositories.NewBaseKeycloakRepository(&cfg.Keycloak, loggerFactory)
	cookieUtil := util.NewCookieUtil(cfg)

	// Health
	healthRepo := repositories.NewHealthRepository(baseKeycloakRepo)
	healthService := services.NewHealthService(healthRepo, loggerFactory)
	healthController := controllers.NewHealthController(healthService)

	// Repositories
	identityRepo := repositories.NewIdentityRepository(baseKeycloakRepo, loggerFactory)
	authRepo := repositories.NewAuthRepository(baseKeycloakRepo, loggerFactory)

	// Services
	identityService := services.NewIdentityService(identityRepo, loggerFactory)
	encryptionService := services.NewEncryptionService()
	authService := services.NewAuthService(authRepo, cfg, loggerFactory)

	// Facades
	authFacade := facades.NewAuthFacade(authService, identityService, encryptionService, loggerFactory)
	identityFacade := facades.NewIdentityFacade(identityService, encryptionService, loggerFactory, authService)

	// Controllers
	authController := controllers.NewAuthController(authFacade, cookieUtil)
	identityController := controllers.NewIdentityController(identityFacade, cookieUtil)

	errorHandler := middleware.NewErrorHandler(loggerFactory)
	// Setup Gin in appropriate mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DisableConsoleColor()
	}
	r := gin.Default()

	// Add Prometheus middleware BEFORE other middleware
	r.Use(middleware.PrometheusMiddleware())
	r.Use(gin.Recovery())
	r.Use(errorHandler.Handle())

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
	// Middleware
	middleware.RegisterMetricsEndpoint(r)

	// Controllers
	authController.RegisterRoutes(r)
	identityController.RegisterRoutes(r)
	healthController.RegisterRoutes(r)

	// Start server
	if err := r.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
