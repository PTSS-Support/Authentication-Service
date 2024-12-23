package services

import (
	"context"
	responses "github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"regexp"
	"strings"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
)

type AuthService interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error)
	ValidateAndRefreshIfNeeded(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error)
	ValidateLoginRequest(req *requests.LoginRequest) error
}

type authService struct {
	authRepo repositories.AuthRepository
	logger   util.Logger
	config   *config.Config
}

func NewAuthService(authRepo repositories.AuthRepository, config *config.Config) AuthService {
	return &authService{
		authRepo: authRepo,
		logger:   util.NewLogger("AuthService"),
		config:   config,
	}
}

func (s *authService) Login(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error) {
	if err := s.ValidateLoginRequest(req); err != nil {
		return nil, err
	}
	return s.authRepo.Login(ctx, req)
}

func (s *authService) ValidateAndRefreshIfNeeded(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error) {
	log := s.logger.WithContext(ctx)

	err := s.authRepo.ValidateAccessToken(ctx, accessToken)
	if err == nil {
		// Access token is still valid, no need to refresh
		log.Debug("Access token is valid")
		return nil, nil
	}

	if err != errors.ErrTokenExpired && err != errors.ErrInvalidToken {
		log.Error("Unexpected error during access token validation", "error", err)
		return nil, err
	}

	log.Debug("Access token is expired/invalid, attempting refresh")

	// Try to refresh the tokens
	newTokens, err := s.authRepo.RefreshTokens(ctx, refreshToken)
	if err != nil {
		if err == errors.ErrTokenExpired {
			log.Info("Refresh token is expired, user needs to login again")
		} else {
			log.Error("Failed to refresh tokens", "error", err)
		}
		return nil, err
	}

	log.Info("Successfully refreshed tokens")
	return newTokens, nil
}

func (s *authService) ValidateLoginRequest(req *requests.LoginRequest) error {
	if req.Email == "" {
		return errors.ErrInvalidEmail
	}

	if req.Password == "" {
		return errors.ErrInvalidPassword
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

	if !emailRegex.MatchString(strings.TrimSpace(req.Email)) {
		return errors.ErrInvalidEmail
	}

	return nil
}
