package facades

import (
	"context"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/auth"
	"github.com/PTSS-Support/identity-service/core/services"
)

type AuthFacade interface {
	HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
}

type authFacade struct {
	authService services.AuthService
}

func NewAuthFacade(authService services.AuthService) AuthFacade {
	return &authFacade{
		authService: authService,
	}
}

func (f *authFacade) HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error) {
	return f.authService.Login(ctx, req)
}
