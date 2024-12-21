package controllers

import (
	"net/http"
	"strings"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/gin-gonic/gin"
)

type IdentityController struct {
	BaseController
	identityFacade facades.IdentityFacade
}

func NewIdentityController(identityFacade facades.IdentityFacade) *IdentityController {
	return &IdentityController{
		identityFacade: identityFacade,
	}
}

func (c *IdentityController) RegisterRoutes(r *gin.Engine) {
	identity := r.Group("/auth/identity")
	{
		identity.POST("", c.CreateIdentity)
		identity.DELETE("/:id", c.DeleteIdentity)
		identity.PATCH("/:id/role", c.UpdateRole)
		identity.PATCH("/:id/password", c.UpdatePassword)
		identity.POST("/:id/pin", c.CreatePIN)
		identity.PATCH("/:id/pin", c.UpdatePIN)
	}
}

func (c *IdentityController) CreateIdentity(ctx *gin.Context) {
	var req requests.CreateIdentityRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := c.identityFacade.HandleIdentityCreation(ctx.Request.Context(), &req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Identity creation failed",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, response)
}

func (c *IdentityController) UpdateRole(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.UpdateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	response, err := c.identityFacade.HandleRoleUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Role update failed",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

func (c *IdentityController) DeleteIdentity(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	err := c.identityFacade.HandleIdentityDeletion(ctx.Request.Context(), id)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Identity deletion failed",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusNoContent, nil)
}

func (c *IdentityController) UpdatePassword(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.UpdatePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	err := c.identityFacade.HandlePasswordUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Password update failed",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusNoContent, nil)
}

func (c *IdentityController) CreatePIN(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.CreatePINRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	err := c.identityFacade.HandlePINCreation(ctx.Request.Context(), id, &req)
	if err != nil {
		status := http.StatusBadRequest
		if err == errors.ErrPINAlreadyExists {
			status = http.StatusConflict
		}

		ctx.JSON(status, gin.H{
			"error":   "PIN creation failed",
			"details": err.Error(),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (c *IdentityController) UpdatePIN(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.UpdatePINRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	err := c.identityFacade.HandlePINUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		status := http.StatusBadRequest
		var details string = err.Error()

		switch {
		case err == errors.ErrNoPINSet:
			status = http.StatusNotFound
			details = "No PIN is set for this user"
		case err == errors.ErrInvalidCredentials:
			status = http.StatusUnauthorized
			details = "Invalid PIN provided"
		case strings.Contains(err.Error(), "invalid hash format"):
			status = http.StatusInternalServerError
			details = "Error verifying PIN. Please contact support."
		}

		ctx.JSON(status, gin.H{
			"error":   "PIN update failed",
			"details": details,
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}
