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
	HandlePINCreation(ctx context.Context, id string, req *requests.CreatePINRequest) error
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

	// Pass the raw password to the service
	response, err := f.identityService.CreateIdentity(ctx, req, req.Password)
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

	// Verify old password
	err := f.identityService.VerifyPassword(ctx, id, req.OldPassword)
	if err != nil {
		log.Error("Failed to verify old password", "error", err, "id", id)
		return err
	}

	// Update to new password
	err = f.identityService.UpdatePassword(ctx, id, req.NewPassword)
	if err != nil {
		log.Error("Failed to update password", "error", err, "id", id)
		return fmt.Errorf("failed to update password: %w", err)
	}

	log.Info("Successfully updated password", "id", id)
	return nil
}

func (f *identityFacade) HandlePINUpdate(ctx context.Context, id string, req *requests.UpdatePINRequest) error {
	log := f.logger.WithContext(ctx)
	log.Info("Starting PIN update process", "id", id)

	// Get current PIN hash
	currentHash, err := f.identityService.GetCurrentPINHash(ctx, id)
	if err != nil {
		log.Error("Failed to get current PIN hash", "error", err, "id", id)
		return fmt.Errorf("failed to get current PIN: %w", err)
	}

	if currentHash == "" {
		log.Error("No PIN set for user", "id", id)
		return errors.ErrNoPINSet
	}

	// Verify old PIN
	log.Debug("Verifying old PIN", "id", id)
	valid, err := f.encryptionService.VerifyPIN(currentHash, req.OldPIN)
	if err != nil {
		log.Error("Failed to verify PIN", "error", err, "id", id)
		return fmt.Errorf("failed to verify PIN: %w", err)
	}
	if !valid {
		log.Warn("Invalid PIN provided", "id", id)
		return errors.ErrInvalidCredentials
	}

	// Hash new PIN
	log.Debug("Hashing new PIN", "id", id)
	hashedPIN, err := f.encryptionService.HashPIN(req.NewPIN)
	if err != nil {
		log.Error("Failed to hash new PIN", "error", err, "id", id)
		return fmt.Errorf("failed to hash new PIN: %w", err)
	}

	// Update PIN
	err = f.identityService.UpdatePIN(ctx, id, hashedPIN)
	if err != nil {
		log.Error("Failed to update PIN", "error", err, "id", id)
		return fmt.Errorf("failed to update PIN: %w", err)
	}

	log.Info("Successfully updated PIN", "id", id)
	return nil
}

func (f *identityFacade) HandlePINCreation(ctx context.Context, id string, req *requests.CreatePINRequest) error {
	log := f.logger.WithContext(ctx)
	log.Info("Starting PIN creation process", "id", id)

	// Hash the PIN
	hashedPIN, err := f.encryptionService.HashPIN(req.PIN)
	if err != nil {
		log.Error("Failed to hash PIN", "error", err, "id", id)
		return fmt.Errorf("failed to hash PIN: %w", err)
	}

	// Check if PIN already exists
	currentPIN, err := f.identityService.GetCurrentPINHash(ctx, id)
	if err == nil && currentPIN != "" {
		log.Error("PIN already exists", "id", id)
		return errors.ErrPINAlreadyExists
	}

	// Create PIN
	err = f.identityService.SetPIN(ctx, id, hashedPIN)
	if err != nil {
		log.Error("Failed to create PIN", "error", err, "id", id)
		return fmt.Errorf("failed to create PIN: %w", err)
	}

	log.Info("Successfully created PIN", "id", id)
	return nil
}
