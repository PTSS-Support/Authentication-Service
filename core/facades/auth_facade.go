package facades

import (
	"context"
	responses "github.com/PTSS-Support/identity-service/domain/entities"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/core/services"
)

type AuthFacade interface {
	HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error)
	HandleTokenValidation(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error)
}

type authFacade struct {
	authService services.AuthService
}

func NewAuthFacade(authService services.AuthService) AuthFacade {
	return &authFacade{
		authService: authService,
	}
}

func (f *authFacade) HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error) {
	return f.authService.Login(ctx, req)
}

func (f *authFacade) HandleTokenValidation(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error) {
	return f.authService.ValidateAndRefreshIfNeeded(ctx, accessToken, refreshToken)
}
