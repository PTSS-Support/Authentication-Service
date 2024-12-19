package services

import (
	"context"

	"github.com/PTSS-Support/identity-service/api/dtos/requests"
	"github.com/PTSS-Support/identity-service/api/dtos/responses"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
)

type AuthService interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
	Register(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error)
	GetUserInfo(ctx context.Context, token string) (*responses.UserResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*responses.AuthResponse, error)
	ValidateToken(ctx context.Context, token string) (bool, error)
}

type authService struct {
	keycloakRepo repositories.KeycloakRepository
}

func NewAuthService(keycloakRepo repositories.KeycloakRepository) AuthService {
	return &authService{
		keycloakRepo: keycloakRepo,
	}
}

func (s *authService) Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error) {
	// TODO: Add pre-login validation if needed
	return s.keycloakRepo.Login(ctx, req)
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*responses.AuthResponse, error) {
	return s.keycloakRepo.RefreshToken(ctx, refreshToken)
}

func (s *authService) ValidateToken(ctx context.Context, token string) (bool, error) {
	return s.keycloakRepo.ValidateToken(ctx, token)
}

func (s *authService) Register(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error) {
	// TODO: Add additional validation
	// TODO: Add email verification flow
	// TODO: Add role validation
	return s.keycloakRepo.RegisterUser(ctx, req)
}

func (s *authService) GetUserInfo(ctx context.Context, token string) (*responses.UserResponse, error) {
	// TODO: Add token validation
	// TODO: Add caching
	return s.keycloakRepo.GetUserInfo(ctx, token)
}
