package services

import (
	"context"
	responses "github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
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
}

type authService struct {
	authRepo repositories.AuthRepository
	logger   util.Logger
	config   *config.Config
}

func NewAuthService(authRepo repositories.AuthRepository, config *config.Config, loggerFactory util.LoggerFactory) AuthService {
	return &authService{
		authRepo: authRepo,
		logger:   loggerFactory.NewLogger("AuthService"),
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

	if accessToken == "" {
		log.Info("Access token is missing")
		return nil, errors.ErrMissingToken
	}

	err := s.ValidateAccessToken(ctx, accessToken)
	if err == nil {
		log.Debug("Access token is valid")
		return nil, nil
	}

	if err == errors.ErrTokenInvalidSignature {
		log.Info("Access token has invalid signature")
		return nil, err
	}

	if err != errors.ErrTokenNearlyOrExpired {
		log.Error("Unexpected error during access token validation", "error", err)
		return nil, err
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

func (s *authService) ValidateAccessToken(ctx context.Context, token string) error {
	introspectResponse, err := s.authRepo.IntrospectAccessToken(ctx, token)
	if err != nil {
		return err
	}

	if !introspectResponse.Active {
		log.Debug("Token is invalid")
		return errors.ErrTokenInvalidSignature
	}

	almostExpired, err := s.isLocallyAlmostExpired(token)
	if err != nil {
		return err
	}

	if almostExpired {
		log.Debug("Token is near expiry")
		return errors.ErrTokenNearlyOrExpired
	}

	log.Debug("Token is valid")
	return nil
}

func (s *authService) isLocallyAlmostExpired(token string) (bool, error) {
	parser := jwt.Parser{}
	claims := jwt.MapClaims{}

	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return false, errors.ErrInvalidToken
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return false, errors.ErrInvalidToken
	}

	now := time.Now().Unix()
	refreshWindow := int64(300) // 5 minutes in seconds

	return now > int64(exp)-refreshWindow, nil
}
