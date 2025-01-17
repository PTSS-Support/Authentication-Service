package controllers

import (
	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/gin-gonic/gin"
	"net/http"
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
	if err := c.bindJSON(ctx, &req); err != nil {
		return
	}

	response, err := c.identityFacade.HandleIdentityCreation(ctx.Request.Context(), &req)
	if err != nil {
		ctx.Error(err)
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
	if err := c.bindJSON(ctx, &req); err != nil {
		return
	}

	response, err := c.identityFacade.HandleRoleUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.Error(err)
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
		ctx.Error(err)
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (c *IdentityController) UpdatePassword(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.UpdatePasswordRequest
	if err := c.bindJSON(ctx, &req); err != nil {
		return
	}

	err := c.identityFacade.HandlePasswordUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (c *IdentityController) CreatePIN(ctx *gin.Context) {
	id := ctx.Param("id")
	if !c.validateUUID(ctx, id) {
		return
	}

	var req requests.CreatePINRequest
	if err := c.bindJSON(ctx, &req); err != nil {
		return
	}

	err := c.identityFacade.HandlePINCreation(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.Error(err)
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
	if err := c.bindJSON(ctx, &req); err != nil {
		return
	}

	err := c.identityFacade.HandlePINUpdate(ctx.Request.Context(), id, &req)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (c *IdentityController) bindJSON(ctx *gin.Context, req interface{}) error {
	if err := ctx.ShouldBindJSON(req); err != nil {
		ctx.Error(&errors.AppError{
			Code:          "INVALID_REQUEST",
			Err:           err,
			ClientMessage: "Invalid request body",
			StatusCode:    http.StatusBadRequest,
		})
		return err
	}
	return nil
}
