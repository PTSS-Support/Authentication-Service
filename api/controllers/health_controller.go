package controllers

import (
	"context"
	"net/http"

	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/health"
	"github.com/PTSS-Support/identity-service/core/services"
	HealthStatus "github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/gin-gonic/gin"
)

type HealthController struct {
	healthService *services.HealthService
}

type healthCheck func(ctx context.Context) (*responses.HealthResponse, error)

// Due to this being a standardized, never-changing endpoint, we don't need a facade layer, this will only add unnecessary code to maintain.
func NewHealthController(healthService *services.HealthService) *HealthController {
	return &HealthController{
		healthService: healthService,
	}
}

func (c *HealthController) RegisterRoutes(router *gin.Engine) {
	router.GET("/q/health", c.getHealth)
	router.GET("/q/health/live", c.getLiveness)
	router.GET("/q/health/ready", c.getReadiness)
}

func (c *HealthController) getHealth(ctx *gin.Context) {
	c.handleHealthCheck(ctx, c.healthService.CheckHealth)
}

func (c *HealthController) getLiveness(ctx *gin.Context) {
	c.handleHealthCheck(ctx, c.healthService.CheckLiveness)
}

func (c *HealthController) getReadiness(ctx *gin.Context) {
	c.handleHealthCheck(ctx, c.healthService.CheckReadiness)
}

func (c *HealthController) handleHealthCheck(ctx *gin.Context, check healthCheck) {
	response, err := check(ctx)
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, responses.HealthResponse{
			Status: HealthStatus.StatusDown,
			Checks: []responses.Check{{
				Name:   "Health check error",
				Status: HealthStatus.StatusDown,
				Data: map[string]interface{}{
					"error": err.Error(),
				},
			}},
		})
		return
	}

	statusCode := http.StatusOK
	if response.Status == HealthStatus.StatusDown {
		statusCode = http.StatusServiceUnavailable
	}
	ctx.JSON(statusCode, response)
}
