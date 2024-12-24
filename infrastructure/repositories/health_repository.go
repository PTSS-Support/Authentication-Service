package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/health"
	HealthStatus "github.com/PTSS-Support/identity-service/domain/enums"
)

type HealthRepository interface {
	CheckHealth(ctx context.Context) (*responses.HealthResponse, error)
}

type healthRepository struct {
	*BaseKeycloakRepository
}

func NewHealthRepository(keycloak *BaseKeycloakRepository) HealthRepository {
	return &healthRepository{
		BaseKeycloakRepository: keycloak,
	}
}

func (r *healthRepository) CheckHealth(ctx context.Context) (*responses.HealthResponse, error) {
	log := r.logger.WithContext(ctx)
	healthURL := fmt.Sprintf("%s/health/ready", r.config.BaseURL)

	resp, err := r.makeJSONRequest(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		log.Error("Failed to check Keycloak health", "error", err)
		return &responses.HealthResponse{
			Status: HealthStatus.StatusDown,
			Checks: []responses.Check{{
				Name:   "Keycloak health check",
				Status: HealthStatus.StatusDown,
				Data: map[string]interface{}{
					"error":     err.Error(),
					"<default>": "DOWN",
				},
			}},
		}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read health response body", "error", err)
		return &responses.HealthResponse{
			Status: HealthStatus.StatusDown,
			Checks: []responses.Check{{
				Name:   "Keycloak health check",
				Status: HealthStatus.StatusDown,
				Data: map[string]interface{}{
					"error":     fmt.Sprintf("failed to read health response: %v", err),
					"<default>": "DOWN",
				},
			}},
		}, nil
	}

	var healthResponse responses.HealthResponse
	if err := json.Unmarshal(body, &healthResponse); err != nil {
		log.Error("Failed to parse health response", "error", err)
		return &responses.HealthResponse{
			Status: HealthStatus.StatusDown,
			Checks: []responses.Check{{
				Name:   "Keycloak health check",
				Status: HealthStatus.StatusDown,
				Data: map[string]interface{}{
					"error":     fmt.Sprintf("failed to parse health response: %v", err),
					"<default>": "DOWN",
				},
			}},
		}, nil
	}

	return &healthResponse, nil
}
