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

func NewHealthService(healthRepo repositories.HealthRepository, loggerFactory util.LoggerFactory) *HealthService {
	return &HealthService{
		healthRepo: healthRepo,
		logger:     loggerFactory.NewLogger("HealthService"),
	}
}

func (s *HealthService) CheckHealth(ctx context.Context) (*responses.HealthResponse, error) {
	// Get liveness check
	livenessResp, err := s.CheckLiveness(ctx)
	if err != nil {
		return nil, err
	}

	// Get readiness check
	readinessResp, err := s.CheckReadiness(ctx)
	if err != nil {
		return nil, err
	}

	// Combine the checks
	combinedResponse := &responses.HealthResponse{
		Status: HealthStatus.StatusUp,
		Checks: append(livenessResp.Checks, readinessResp.Checks...),
	}

	// If either check is down, mark overall status as down
	if livenessResp.Status == HealthStatus.StatusDown ||
		readinessResp.Status == HealthStatus.StatusDown {
		combinedResponse.Status = HealthStatus.StatusDown
	}

	return combinedResponse, nil
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
