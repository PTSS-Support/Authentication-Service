package facades

import (
	"context"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/core/services"
	"github.com/PTSS-Support/identity-service/domain/errors"
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
}

func NewIdentityFacade(identityService services.IdentityService, encryptionService services.EncryptionService) IdentityFacade {
	return &identityFacade{
		identityService:   identityService,
		encryptionService: encryptionService,
	}
}

func (f *identityFacade) HandleIdentityCreation(ctx context.Context, req *requests.CreateIdentityRequest) (*responses.IdentityResponse, error) {
	// Hash the password before creating the identity
	hashedPassword, err := f.encryptionService.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// Hash the PIN if provided
	var hashedPIN string
	if req.PIN != "" {
		hashedPIN, err = f.encryptionService.HashPIN(req.PIN)
		if err != nil {
			return nil, err
		}
	}

	// Create identity with hashed credentials
	return f.identityService.CreateIdentity(ctx, req, hashedPassword, hashedPIN)
}

func (f *identityFacade) HandleRoleUpdate(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error) {
	return f.identityService.UpdateRole(ctx, id, req)
}

func (f *identityFacade) HandleIdentityDeletion(ctx context.Context, id string) error {
	return f.identityService.DeleteIdentity(ctx, id)
}

func (f *identityFacade) HandlePasswordUpdate(ctx context.Context, id string, req *requests.UpdatePasswordRequest) error {
	// Get current password hash
	currentHash, err := f.identityService.GetCurrentPasswordHash(ctx, id)
	if err != nil {
		return err
	}

	// Verify old password
	valid, err := f.encryptionService.VerifyPassword(currentHash, req.OldPassword)
	if err != nil {
		return err
	}
	if !valid {
		return errors.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := f.encryptionService.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	// Update password
	return f.identityService.UpdatePassword(ctx, id, hashedPassword)
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
