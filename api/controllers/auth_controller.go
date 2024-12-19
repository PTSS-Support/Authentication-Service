package controllers

import (
	"github.com/PTSS-Support/identity-service/api/dtos/responses"
	"net/http"
	"strings"

	"github.com/PTSS-Support/identity-service/api/dtos/requests"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/gin-gonic/gin"
)

const (
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"
)

type AuthController struct {
	authFacade facades.AuthFacade
}

func NewAuthController(authFacade facades.AuthFacade) *AuthController {
	return &AuthController{
		authFacade: authFacade,
	}
}

func (c *AuthController) RegisterRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/register", c.Register)
		auth.POST("/login", c.Login)
		auth.GET("/validate-tokens", c.ValidateTokens)
		auth.GET("/me", c.GetUserInfo)
	}
}

func (c *AuthController) Register(ctx *gin.Context) {
	var req requests.RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := c.authFacade.HandleRegistration(ctx.Request.Context(), &req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Registration failed",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, response)
}

func (c *AuthController) Login(ctx *gin.Context) {
	var req requests.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := c.authFacade.HandleLogin(ctx.Request.Context(), &req)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Authentication failed",
			"details": err.Error(),
		})
		return
	}

	// Set cookies
	setAuthCookies(ctx, response)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
	})
}

func (c *AuthController) GetUserInfo(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "No authorization header",
		})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	userInfo, err := c.authFacade.GetUserInformation(ctx.Request.Context(), token)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Failed to get user info",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, userInfo)
}

func (c *AuthController) ValidateTokens(ctx *gin.Context) {
	accessToken := strings.TrimPrefix(ctx.GetHeader("Authorization"), "Bearer ")
	if accessToken == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "No access token provided",
		})
		return
	}

	refreshToken, err := ctx.Cookie(RefreshTokenCookie)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "No refresh token provided",
		})
		return
	}

	// If access token is invalid, try to refresh
	valid, err := c.authFacade.ValidateToken(ctx, accessToken)
	if !valid || err != nil {
		// Try to refresh
		newTokens, err := c.authFacade.HandleTokenRefresh(ctx, refreshToken)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication failed",
			})
			return
		}

		// Set new cookies
		setAuthCookies(ctx, newTokens)

		ctx.JSON(http.StatusOK, gin.H{
			"status":       "tokens_refreshed",
			"access_token": newTokens.AccessToken,
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status": "valid",
	})
}

func setAuthCookies(ctx *gin.Context, tokens *responses.AuthResponse) {
	// Access token cookie - NOT HTTP only, can be accessed by JavaScript
	ctx.SetCookie(
		AccessTokenCookie,
		tokens.AccessToken,
		900, // 15 minutes in seconds
		"/",
		"",
		true,
		false,
	)

	// Refresh token cookie - HTTP only, secure
	ctx.SetCookie(
		RefreshTokenCookie,
		tokens.RefreshToken,
		2592000, // 30 days in seconds
		"/",
		"",
		true,
		true,
	)
}
