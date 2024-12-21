package controllers

import (
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"net/http"
	"strings"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/gin-gonic/gin"
)

type AuthController struct {
	BaseController
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
		auth.POST("/login", c.Login)
		auth.POST("/validate", c.ValidateTokens)
	}
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

	util.SetRefreshTokenCookie(ctx, response.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"access_token": response.AccessToken,
	})
}

func (c *AuthController) ValidateTokens(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing access token",
			"details": "Authorization header is missing or invalid",
		})
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	refreshToken, err := util.GetRefreshTokenFromCookie(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing refresh token",
			"details": err.Error(),
		})
		return
	}

	response, err := c.authFacade.HandleTokenValidation(ctx.Request.Context(), accessToken, refreshToken)
	if err != nil {
		status := http.StatusBadRequest

		switch err {
		case errors.ErrTokenExpired:
			status = http.StatusUnauthorized
		case errors.ErrInvalidToken:
			status = http.StatusUnauthorized
		case errors.ErrInvalidCredentials:
			status = http.StatusUnauthorized
		}

		ctx.JSON(status, gin.H{
			"error":   "Token validation failed",
			"details": err.Error(),
		})
		return
	}

	if response != nil {
		util.SetRefreshTokenCookie(ctx, response.RefreshToken)
		ctx.JSON(http.StatusOK, gin.H{
			"access_token": response.AccessToken,
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}
