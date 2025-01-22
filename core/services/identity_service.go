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
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"regexp"
)

type IdentityService interface {
	CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword string) (*responses.IdentityResponse, error)
	UpdateRole(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error)
	DeleteIdentity(ctx context.Context, id string) error
	VerifyPassword(ctx context.Context, id string, password string) error
	UpdatePassword(ctx context.Context, id string, newPassword string) error
	GetCurrentPINHash(ctx context.Context, id string) (string, error)
	UpdatePIN(ctx context.Context, id string, hashedPIN string) error
	SetPIN(ctx context.Context, id string, hashedPIN string) error
	GetHashedPIN(ctx context.Context, userID string) (string, error)
	GetIdentityByEmail(ctx context.Context, email string) (*entities.KeycloakIdentity, error)
	ValidatePasswordResetEligibility(ctx context.Context, email string) (*entities.KeycloakIdentity, error)
	ResetPassword(ctx context.Context, id string, newPassword string) error
}

type identityService struct {
	identityRepo repositories.IdentityRepository
	logger       util.Logger
}

func NewIdentityService(identityRepo repositories.IdentityRepository, loggerFactory util.LoggerFactory) IdentityService {
	return &identityService{
		identityRepo: identityRepo,
		logger:       loggerFactory.NewLogger("IdentityService"),
	}
}

func (s *identityService) CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword string) (*responses.IdentityResponse, error) {
	log := s.logger.WithContext(ctx)
	log.Info("Creating new identity", "email", req.Email, "role", req.Role)

	if err := validateName(req.FirstName, req.LastName); err != nil {
		return nil, err
	}

	if req.Role != enums.RoleHealthcareProfessional && req.Role != enums.RoleAdmin {
		if req.GroupID == "" {
			log.Error("GroupID is required for this role", "role", req.Role)
			return nil, errors.ErrGroupIDRequired
		}
	}

	existingUser, err := s.identityRepo.GetIdentityByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		log.Error("User already exists", "email", req.Email)
		return nil, errors.ErrUserAlreadyExists
	}

	// Create domain model
	identity := &models.Identity{
		UserID:    req.UserId,
		Email:     req.Email,
		Role:      req.Role,
		GroupID:   req.GroupID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	// Convert to Keycloak entity
	keycloakIdentity := entities.FromModel(identity, hashedPassword)
	log.Debug("Converted to Keycloak entity", "username", keycloakIdentity.Email)

	// Create identity in repository
	createdIdentity, err := s.identityRepo.CreateIdentity(ctx, keycloakIdentity)
	if err != nil {
		log.Error("Failed to create identity in repository", "error", err)
		return nil, err
	}

	log.Debug("Successfully created identity in Keycloak", "id", createdIdentity.ID)

	// Convert to response
	response := &responses.IdentityResponse{
		ID:    createdIdentity.ID,
		Email: createdIdentity.Email,
		Role:  req.Role,
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

	groupIDValues, hasGroupID := identity.Attributes["groupId"]
	hasValidGroupID := hasGroupID && len(groupIDValues) > 0 && groupIDValues[0] != ""

	if req.Role != enums.RoleHealthcareProfessional && req.Role != enums.RoleAdmin && !hasValidGroupID {
		return nil, errors.ErrGroupIDRequired
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

func (s *identityService) GetCurrentPINHash(ctx context.Context, id string) (string, error) {
	log := s.logger.WithContext(ctx)

	// Get identity from repository
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		log.Error("Failed to get identity", "error", err)
		return "", err
	}

	// Get PIN from attributes
	if pinValues, exists := identity.Attributes["pin"]; exists && len(pinValues) > 0 {
		return pinValues[0], nil
	}

	return "", nil // Return empty string if no PIN set
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
	log := s.logger.WithContext(ctx)

	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		log.Error("Failed to get identity", "error", err)
		return err
	}

	// Update PIN in attributes
	if identity.Attributes == nil {
		identity.Attributes = make(map[string][]string)
	}
	identity.Attributes["pin"] = []string{hashedPIN}

	// Update in repository
	log.Debug("Updating PIN in Keycloak")
	_, err = s.identityRepo.UpdateIdentity(ctx, identity)
	if err != nil {
		log.Error("Failed to update identity", "error", err)
		return err
	}

	return nil
}

func (s *identityService) SetPIN(ctx context.Context, id string, hashedPIN string) error {
	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, id)
	if err != nil {
		return err
	}

	// Check if PIN already exists in attributes
	if pinValues, exists := identity.Attributes["pin"]; exists && len(pinValues) > 0 {
		return errors.ErrPINAlreadyExists
	}

	// Set PIN in attributes
	identity.Attributes["pin"] = []string{hashedPIN}
	identity.Attributes["hasPin"] = []string{"true"}

	// Update in repository
	_, err = s.identityRepo.UpdateIdentity(ctx, identity)
	return err
}

func (s *identityService) GetHashedPIN(ctx context.Context, userID string) (string, error) {
	log := s.logger.WithContext(ctx)

	// Get current identity
	identity, err := s.identityRepo.GetIdentity(ctx, userID)
	if err != nil {
		log.Error("Failed to get identity", "error", err)
		return "", err
	}

	// Check PIN in attributes
	pinValues, exists := identity.Attributes["pin"]
	if !exists || len(pinValues) == 0 {
		log.Info("PIN not set for user")
		return "", errors.ErrNoPINSet
	}

	return pinValues[0], nil
}

func (s *identityService) ValidatePasswordResetEligibility(ctx context.Context, email string) (*entities.KeycloakIdentity, error) {
	log := s.logger.WithContext(ctx)

	// Get user details by email
	identity, err := s.GetIdentityByEmail(ctx, email)
	if err != nil {
		log.Error("Failed to get identity by email", "error", err)
		return nil, err
	}

	// Extract role from attributes
	roleValues, exists := identity.Attributes["role"]
	if !exists || len(roleValues) == 0 {
		log.Error("User has no role", "id", identity.ID)
		return nil, errors.ErrRoleLacksPermission
	}

	role := roleValues[0]

	// Validate role
	if role == string(enums.RoleHealthcareProfessional) || role == string(enums.RoleAdmin) {
		log.Warn("Unauthorized role attempting password reset", "role", role)
		return nil, errors.ErrUnauthorizedReset
	}

	return identity, nil
}

func (s *identityService) GetIdentityByEmail(ctx context.Context, email string) (*entities.KeycloakIdentity, error) {
	return s.identityRepo.GetIdentityByEmail(ctx, email)
}

func (s *identityService) ResetPassword(ctx context.Context, id string, newPassword string) error {
	log := s.logger.WithContext(ctx)
	log.Info("Starting password reset process", "id", id)

	// Optional: Add password complexity checks if needed
	err := s.identityRepo.ResetPassword(ctx, id, newPassword)
	if err != nil {
		log.Error("Failed to reset password", "error", err, "id", id)
		return err
	}

	log.Info("Successfully reset password", "id", id)
	return nil
}

func validateName(firstName, lastName string) error {
	// More flexible validation logic
	nameRegex := regexp.MustCompile(`^[a-zA-ZÀ-ÿ\s'-]+$`)

	if !nameRegex.MatchString(firstName) || !nameRegex.MatchString(lastName) {
		return errors.ErrFirstnameOrLastnameInvalidFormat
	}

	return nil
}
