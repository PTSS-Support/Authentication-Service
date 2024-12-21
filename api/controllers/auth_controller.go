package controllers

import (
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"net/http"

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

	util.SetAuthCookies(ctx, response.AccessToken, response.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
	})
}

func (c *AuthController) ValidateTokens(ctx *gin.Context) {
	accessToken, err := util.GetAccessTokenFromCookie(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing access token",
			"details": err.Error(),
		})
		return
	}

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

	// If response is nil, tokens are valid and don't need refresh
	if response != nil {
		util.SetAuthCookies(ctx, response.AccessToken, response.RefreshToken)
	}

	ctx.Status(http.StatusNoContent)
}
