package facades

import (
	"context"

	"github.com/PTSS-Support/identity-service/api/dtos/requests"
	"github.com/PTSS-Support/identity-service/api/dtos/responses"
	"github.com/PTSS-Support/identity-service/core/services"
)

type AuthFacade interface {
	HandleLogin(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
	HandleRegistration(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error)
	GetUserInformation(ctx context.Context, token string) (*responses.UserResponse, error)
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

func (f *authFacade) HandleRegistration(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error) {
	return f.authService.Register(ctx, req)
}

func (f *authFacade) GetUserInformation(ctx context.Context, token string) (*responses.UserResponse, error) {
	return f.authService.GetUserInfo(ctx, token)
}
