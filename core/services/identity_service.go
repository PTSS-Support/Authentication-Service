package services

import (
	"context"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/domain/models"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
)

type IdentityService interface {
	CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword, hashedPIN string) (*responses.IdentityResponse, error)
	UpdateRole(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error)
	DeleteIdentity(ctx context.Context, id string) error
	GetCurrentPasswordHash(ctx context.Context, id string) (string, error)
	GetCurrentPINHash(ctx context.Context, id string) (string, error)
	UpdatePassword(ctx context.Context, id string, hashedPassword string) error
	UpdatePIN(ctx context.Context, id string, hashedPIN string) error
}

type identityService struct {
	identityRepo repositories.IdentityRepository
}

func NewIdentityService(identityRepo repositories.IdentityRepository) IdentityService {
	return &identityService{
		identityRepo: identityRepo,
	}
}

func (s *identityService) CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword, hashedPIN string) (*responses.IdentityResponse, error) {
	// Create domain model
	identity := &models.Identity{
		Email: req.Email,
		Role:  req.Role,
	}

	if req.PIN != "" {
		identity.PIN = &hashedPIN
	}

	// Convert to Keycloak entity
	keycloakIdentity := entities.FromModel(identity, hashedPassword)

	// Create identity in repository
	createdIdentity, err := s.identityRepo.CreateIdentity(ctx, keycloakIdentity)
	if err != nil {
		return nil, err
	}

	// Extract role from attributes
	var role enums.Role
	if roleValues, exists := createdIdentity.Attributes["role"]; exists && len(roleValues) > 0 {
		role = enums.Role(roleValues[0])
	}

	// Convert to response
	return &responses.IdentityResponse{
		ID:    createdIdentity.ID,
		Email: createdIdentity.Email,
		Role:  role,
	}, nil
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

func (s *identityService) UpdatePassword(ctx context.Context, id string, hashedPassword string) error {
	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return err
	}

	// Update password credential
	identity.Credentials = []entities.KeycloakCredential{
		{
			Type:      "password",
			Value:     hashedPassword,
			Temporary: false,
		},
	}

	// Update in repository
	_, err = s.identityRepo.UpdateIdentity(ctx, identity)
	return err
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
