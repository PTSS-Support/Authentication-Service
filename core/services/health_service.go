package services

import (
	"context"

	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/health"
	HealthStatus "github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
)

type HealthService struct {
	healthRepo repositories.HealthRepository
	logger     util.Logger
}

func NewHealthService(healthRepo repositories.HealthRepository) *HealthService {
	return &HealthService{
		healthRepo: healthRepo,
		logger:     util.NewLogger("HealthService"),
	}
}

func (s *HealthService) CheckReadiness(ctx context.Context) (*responses.HealthResponse, error) {
	keycloakHealth, err := s.healthRepo.CheckHealth(ctx)

	if err != nil {
		return &responses.HealthResponse{
			Status: HealthStatus.StatusDown,
			Checks: []responses.Check{
				{
					Name:   "Keycloak health check",
					Status: HealthStatus.StatusDown,
					Data: map[string]interface{}{
						"error": err.Error(),
					},
				},
			},
		}, nil
	}

	return &responses.HealthResponse{
		Status: HealthStatus.StatusUp,
		Checks: []responses.Check{
			{
				Name:   "Keycloak health check",
				Status: HealthStatus.StatusUp,
				Data: map[string]interface{}{
					"response": keycloakHealth,
				},
			},
		},
	}, nil
}

func (s *HealthService) CheckLiveness(ctx context.Context) (*responses.HealthResponse, error) {
	return &responses.HealthResponse{
		Status: HealthStatus.StatusUp,
		Checks: []responses.Check{},
	}, nil
}
