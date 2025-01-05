package controllers

import (
	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthController struct {
	BaseController
	authFacade facades.AuthFacade
	cookieUtil util.CookieUtil
}

func NewAuthController(authFacade facades.AuthFacade, cookieUtil *util.CookieUtil) *AuthController {
	return &AuthController{
		authFacade: authFacade,
		cookieUtil: *cookieUtil,
	}
}

func (c *AuthController) RegisterRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/login", c.Login)
		auth.POST("/validate", c.ValidateOrRefreshTokens)
		auth.POST("login/pin", c.ValidateWithPIN)
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

	c.cookieUtil.SetAuthCookies(ctx, response.AccessToken, response.RefreshToken)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
	})
}

func (c *AuthController) ValidateOrRefreshTokens(ctx *gin.Context) {
	accessToken, _ := c.cookieUtil.GetAccessTokenFromCookie(ctx)
	refreshToken, _ := c.cookieUtil.GetRefreshTokenFromCookie(ctx)

	response, err := c.authFacade.HandleTokenValidation(ctx.Request.Context(), accessToken, refreshToken)
	if err != nil {
		// Let the global error handler deal with it
		ctx.Error(err)
		return
	}

	if response != nil {
		c.cookieUtil.SetAuthCookies(ctx, response.AccessToken, response.RefreshToken)
	}
	ctx.Status(http.StatusNoContent)
}

func (c *AuthController) ValidateWithPIN(ctx *gin.Context) {
	refreshToken, _ := c.cookieUtil.GetRefreshTokenFromCookie(ctx)
	pin, _ := c.cookieUtil.GetPINFromCookie(ctx)

	response, err := c.authFacade.HandlePINValidation(ctx.Request.Context(), refreshToken, pin)
	if err != nil {
		ctx.Error(err)
		return
	}

	c.cookieUtil.SetAuthCookies(ctx, response.AccessToken, response.RefreshToken)
	ctx.Status(http.StatusNoContent)
}
