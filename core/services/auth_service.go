package services

import (
	"context"
	responses "github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"regexp"
	"strings"
	"time"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/infrastructure/repositories"
)

type AuthService interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error)
	ValidateAndRefreshIfNeeded(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error)
	ValidateLoginRequest(req *requests.LoginRequest) error
	ValidateAndIntrospectRefreshToken(ctx context.Context, refreshToken string) (*responses.TokenIntrospectionResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*responses.TokenPair, error)
}

type authService struct {
	authRepo      repositories.AuthRepository
	logger        util.Logger
	config        *config.Config
	refreshWindow int64
}

func NewAuthService(authRepo repositories.AuthRepository, config *config.Config, loggerFactory util.LoggerFactory) AuthService {
	return &authService{
		authRepo:      authRepo,
		logger:        loggerFactory.NewLogger("AuthService"),
		config:        config,
		refreshWindow: 300, // 5 minutes
	}
}

func (s *authService) Login(ctx context.Context, req *requests.LoginRequest) (*responses.TokenPair, error) {
	if err := s.ValidateLoginRequest(req); err != nil {
		return nil, err
	}
	return s.authRepo.Login(ctx, req)
}

func (s *authService) ValidateAndIntrospectRefreshToken(ctx context.Context, refreshToken string) (*responses.TokenIntrospectionResponse, error) {
	log := s.logger.WithContext(ctx)

	if refreshToken == "" {
		log.Info("Refresh token is missing")
		return nil, errors.ErrMissingToken
	}

	response, err := s.authRepo.IntrospectToken(ctx, refreshToken)
	if err != nil {
		log.Error("Failed to validate refresh token", "error", err)
		return nil, err
	}

	if !response.Active {
		log.Info("Refresh token is not active")
		return nil, errors.ErrInvalidToken
	}

	return response, nil
}

func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (*responses.TokenPair, error) {
	return s.authRepo.RefreshTokens(ctx, refreshToken)
}

func (s *authService) ValidateAndRefreshIfNeeded(ctx context.Context, accessToken, refreshToken string) (*responses.TokenPair, error) {
	log := s.logger.WithContext(ctx)

	if accessToken == "" {
		log.Info("Access token is missing")
		return nil, errors.ErrMissingToken
	}

	isValid, introspectedToken, err := s.isValidAccessToken(ctx, accessToken, log)
	if err != nil {
		log.Error("Error validating access token", "error", err)
		return nil, err
	}

	if !isValid {
		log.Info("Access token is invalid")
		return nil, errors.ErrInvalidToken
	}

	almostExpired, err := s.isAlmostExpired(introspectedToken)
	if err != nil {
		return nil, err
	}

	if !almostExpired {
		log.Debug("Token is valid and not near expiry")
		return nil, nil
	}

	if refreshToken == "" {
		log.Info("Refresh token is missing")
		return nil, errors.ErrMissingToken
	}

	log.Debug("Access token almost expired, attempting refresh")
	newTokens, err := s.authRepo.RefreshTokens(ctx, refreshToken)
	if err != nil {
		log.Error("Failed to refresh tokens", "error", err)
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

func (s *authService) isValidAccessToken(ctx context.Context, token string, log util.Logger) (bool, *responses.TokenIntrospectionResponse, error) {
	introspectResponse, err := s.authRepo.IntrospectToken(ctx, token)
	if err != nil {
		return false, nil, err
	}

	if !introspectResponse.Active {
		log.Debug("Token is invalid")
		return false, nil, errors.ErrInvalidToken
	}

	log.Debug("Token is valid")
	return true, introspectResponse, nil
}

func (s *authService) isAlmostExpired(introspectedToken *responses.TokenIntrospectionResponse) (bool, error) {
	if introspectedToken == nil {
		return false, errors.ErrInvalidToken
	}

	now := time.Now().Unix()

	return now > introspectedToken.Exp-s.refreshWindow, nil
}
