package controllers

import (
	"net/http"
	"strings"

	"github.com/PTSS-Support/identity-service/api/dtos/requests"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/gin-gonic/gin"
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

	ctx.JSON(http.StatusOK, response)
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
