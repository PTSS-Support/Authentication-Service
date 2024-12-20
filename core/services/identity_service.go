package services

import (
	"context"
	"fmt"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/domain/models"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
)

type IdentityService interface {
	CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword string) (*responses.IdentityResponse, error)
	UpdateRole(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error)
	DeleteIdentity(ctx context.Context, id string) error
	GetCurrentPasswordHash(ctx context.Context, id string) (string, error)
	GetCurrentPINHash(ctx context.Context, id string) (string, error)
	VerifyPassword(ctx context.Context, id string, password string) error
	UpdatePassword(ctx context.Context, id string, hashedPassword string) error
	UpdatePIN(ctx context.Context, id string, hashedPIN string) error
}

type identityService struct {
	identityRepo repositories.IdentityRepository
	logger       util.Logger
}

func NewIdentityService(identityRepo repositories.IdentityRepository) IdentityService {
	return &identityService{
		identityRepo: identityRepo,
		logger:       util.NewLogger("IdentityService"),
	}
}

func (s *identityService) CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword string) (*responses.IdentityResponse, error) {
	log := s.logger.WithContext(ctx)
	log.Info("Creating new identity", "email", req.Email, "role", req.Role)

	// Create domain model
	identity := &models.Identity{
		Email: req.Email,
		Role:  req.Role,
	}

	// Convert to Keycloak entity
	keycloakIdentity := entities.FromModel(identity, hashedPassword)
	log.Debug("Converted to Keycloak entity", "username", keycloakIdentity.Email)

	// Create identity in repository
	createdIdentity, err := s.identityRepo.CreateIdentity(ctx, keycloakIdentity)
	if err != nil {
		log.Error("Failed to create identity in repository", "error", err)
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	log.Debug("Successfully created identity in Keycloak", "id", createdIdentity.ID)

	// Extract role from attributes
	var role enums.Role
	if roleValues, exists := createdIdentity.Attributes["role"]; exists && len(roleValues) > 0 {
		role = enums.Role(roleValues[0])
		log.Debug("Extracted role from attributes", "role", role)
	}

	// Convert to response
	response := &responses.IdentityResponse{
		ID:    createdIdentity.ID,
		Email: createdIdentity.Email,
		Role:  role,
	}
	log.Info("Successfully created identity", "id", response.ID, "email", response.Email)

	return response, nil
}

func (s *identityService) UpdateRole(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error) {
	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update role in attributes
	identity.Attributes["role"] = []string{string(req.Role)}

	// Update in repository
	updatedIdentity, err := s.identityRepo.UpdateIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	// Extract role from attributes
	var role enums.Role
	if roleValues, exists := updatedIdentity.Attributes["role"]; exists && len(roleValues) > 0 {
		role = enums.Role(roleValues[0])
	}

	// Convert to response
	return &responses.IdentityResponse{
		ID:    updatedIdentity.ID,
		Email: updatedIdentity.Email,
		Role:  role,
	}, nil
}

func (s *identityService) DeleteIdentity(ctx context.Context, id string) error {
	return s.identityRepo.DeleteIdentity(ctx, id)
}

func (s *identityService) GetCurrentPasswordHash(ctx context.Context, id string) (string, error) {
	// Get identity from repository
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return "", err
	}

	// Find password credential
	for _, cred := range identity.Credentials {
		if cred.Type == "password" {
			return cred.Value, nil
		}
	}

	return "", errors.ErrInvalidCredentials
}

func (s *identityService) GetCurrentPINHash(ctx context.Context, id string) (string, error) {
	// Get identity from repository
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return "", err
	}

	// Get PIN from attributes
	if pinValues, exists := identity.Attributes["pin"]; exists && len(pinValues) > 0 {
		return pinValues[0], nil
	}

	return "", errors.ErrInvalidCredentials
}

func (s *identityService) VerifyPassword(ctx context.Context, id string, password string) error {
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return err
	}

	return s.identityRepo.VerifyPassword(ctx, identity.Email, password)
}

func (s *identityService) UpdatePassword(ctx context.Context, id string, newPassword string) error {
	return s.identityRepo.UpdatePassword(ctx, id, newPassword)
}

func (s *identityService) UpdatePIN(ctx context.Context, id string, hashedPIN string) error {
	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return err
	}

	// Update PIN in attributes
	identity.Attributes["pin"] = []string{hashedPIN}

	// Update in repository
	_, err = s.identityRepo.UpdateIdentity(ctx, identity)
	return err
}
