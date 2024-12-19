package facades

import (
	"context"
	"fmt"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/core/services"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
)

type IdentityFacade interface {
	HandleIdentityCreation(ctx context.Context, req *requests.CreateIdentityRequest) (*responses.IdentityResponse, error)
	HandleRoleUpdate(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error)
	HandleIdentityDeletion(ctx context.Context, id string) error
	HandlePasswordUpdate(ctx context.Context, id string, req *requests.UpdatePasswordRequest) error
	HandlePINUpdate(ctx context.Context, id string, req *requests.UpdatePINRequest) error
}

type identityFacade struct {
	identityService   services.IdentityService
	encryptionService services.EncryptionService
	logger            util.Logger
}

func NewIdentityFacade(identityService services.IdentityService, encryptionService services.EncryptionService) IdentityFacade {
	return &identityFacade{
		identityService:   identityService,
		encryptionService: encryptionService,
		logger:            util.NewLogger("IdentityFacade"),
	}
}

func (f *identityFacade) HandleIdentityCreation(ctx context.Context, req *requests.CreateIdentityRequest) (*responses.IdentityResponse, error) {
	log := f.logger.WithContext(ctx)
	log.Info("Starting identity creation process", "email", req.Email)

	// Hash the password before creating the identity
	hashedPassword, err := f.encryptionService.HashPassword(req.Password)
	if err != nil {
		log.Error("Failed to hash password", "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create identity with hashed credentials
	response, err := f.identityService.CreateIdentity(ctx, req, hashedPassword)
	if err != nil {
		log.Error("Failed to create identity", "error", err, "email", req.Email)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	log.Info("Successfully created identity", "id", response.ID, "email", req.Email)
	return response, nil
}

func (f *identityFacade) HandleRoleUpdate(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error) {
	return f.identityService.UpdateRole(ctx, id, req)
}

func (f *identityFacade) HandleIdentityDeletion(ctx context.Context, id string) error {
	return f.identityService.DeleteIdentity(ctx, id)
}

func (f *identityFacade) HandlePasswordUpdate(ctx context.Context, id string, req *requests.UpdatePasswordRequest) error {
	log := f.logger.WithContext(ctx)
	log.Info("Starting password update process", "id", id)

	// Get current password hash
	currentHash, err := f.identityService.GetCurrentPasswordHash(ctx, id)
	if err != nil {
		log.Error("Failed to get current password hash", "error", err, "id", id)
		return fmt.Errorf("failed to get current password: %w", err)
	}

	// Verify old password
	valid, err := f.encryptionService.VerifyPassword(currentHash, req.OldPassword)
	if err != nil {
		log.Error("Failed to verify password", "error", err, "id", id)
		return fmt.Errorf("failed to verify password: %w", err)
	}
	if !valid {
		log.Warn("Invalid password provided", "id", id)
		return errors.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := f.encryptionService.HashPassword(req.NewPassword)
	if err != nil {
		log.Error("Failed to hash new password", "error", err, "id", id)
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	err = f.identityService.UpdatePassword(ctx, id, hashedPassword)
	if err != nil {
		log.Error("Failed to update password", "error", err, "id", id)
		return fmt.Errorf("failed to update password: %w", err)
	}

	log.Info("Successfully updated password", "id", id)
	return nil
}

func (f *identityFacade) HandlePINUpdate(ctx context.Context, id string, req *requests.UpdatePINRequest) error {
	// Get current PIN hash
	currentHash, err := f.identityService.GetCurrentPINHash(ctx, id)
	if err != nil {
		return err
	}

	// Verify old PIN
	valid, err := f.encryptionService.VerifyPIN(currentHash, req.OldPIN)
	if err != nil {
		return err
	}
	if !valid {
		return errors.ErrInvalidCredentials
	}

	// Hash new PIN
	hashedPIN, err := f.encryptionService.HashPIN(req.NewPIN)
	if err != nil {
		return err
	}

	// Update PIN
	return f.identityService.UpdatePIN(ctx, id, hashedPIN)
}
