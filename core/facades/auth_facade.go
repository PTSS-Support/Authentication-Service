package facades

import (
	"context"
	responses "github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"strconv"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/core/services"
)

type AuthFacade interface {
	HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error)
	HandleLogout(ctx context.Context, refreshToken string) error
	HandleTokenValidation(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error)
	HandlePINValidation(ctx context.Context, refreshToken, pin string) (*responses.TokenPair, error)
}

type authFacade struct {
	authService       services.AuthService
	identityService   services.IdentityService
	encryptionService services.EncryptionService
	logger            util.Logger
}

func NewAuthFacade(authService services.AuthService,
	identityService services.IdentityService,
	encryptionService services.EncryptionService,
	loggerFactory util.LoggerFactory) AuthFacade {
	return &authFacade{
		authService:       authService,
		identityService:   identityService,
		encryptionService: encryptionService,
		logger:            loggerFactory.NewLogger("AuthFacade"),
	}
}

func (f *authFacade) HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error) {
	return f.authService.Login(ctx, req)
}

func (f *authFacade) HandleLogout(ctx context.Context, refreshToken string) error {
	log := f.logger.WithContext(ctx)

	if refreshToken == "" {
		log.Info("No refresh token provided for logout")
		//still return nil to avoid confusion
		return nil
	}

	return f.authService.Logout(ctx, refreshToken)
}

func (f *authFacade) HandleTokenValidation(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error) {
	return f.authService.ValidateAndRefreshIfNeeded(ctx, accessToken, refreshToken)
}

func (f *authFacade) HandlePINValidation(ctx context.Context, refreshToken, pin string) (*responses.TokenPair, error) {
	log := f.logger.WithContext(ctx)

	if err := ValidatePIN(pin); err != nil {
		return nil, err
	}

	userInfo, err := f.authService.ValidateAndIntrospectRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Debug("Invalid refresh token")
		return nil, err
	}

	storedHashedPIN, err := f.identityService.GetHashedPIN(ctx, userInfo.Sub)
	if err != nil {
		if err == errors.ErrNoPINSet {
			log.Debug("PIN not set for user")
		} else {
			log.Error("Failed to get hashed PIN", "error", err)
		}
		return nil, err
	}

	isValid, err := f.encryptionService.VerifyPIN(storedHashedPIN, pin)
	if err != nil {
		log.Error("Failed to verify PIN", "error", err)
		return nil, err
	}

	if !isValid {
		log.Info("Invalid PIN provided")
		return nil, errors.ErrWrongPin
	}

	newTokens, err := f.authService.RefreshTokens(ctx, refreshToken)
	if err != nil {
		log.Error("Failed to refresh tokens", "error", err)
		return nil, err
	}

	return newTokens, nil
}

func ValidatePIN(pin string) error {
	if len(pin) != 4 {
		return errors.ErrInvalidPINFormat
	}

	// Check if PIN is numeric
	if _, err := strconv.Atoi(pin); err != nil {
		return errors.ErrInvalidPINNumeric
	}

	return nil
}
