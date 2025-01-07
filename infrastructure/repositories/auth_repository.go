package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"io"
	"net/http"
	"net/url"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
)

type AuthRepository interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*entities.TokenPair, error)
	IntrospectToken(ctx context.Context, token string) (*entities.TokenIntrospectionResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*entities.TokenPair, error)
}

type authRepository struct {
	*BaseKeycloakRepository
	logger util.Logger
}

func NewAuthRepository(keycloak *BaseKeycloakRepository, loggerFactory util.LoggerFactory) AuthRepository {
	return &authRepository{
		BaseKeycloakRepository: keycloak,
		logger:                 loggerFactory.NewLogger("AuthRepository"),
	}
}

func (r *authRepository) Login(ctx context.Context, req *requests.LoginRequest) (*entities.TokenPair, error) {
	log := r.logger.WithContext(ctx)
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := r.prepareLoginData(req.Email, req.Password)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		log.Error("Login request failed", "error", err)
		return nil, errors.ErrConnectionFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.ErrInvalidCredentials
	}

	var authResponse entities.TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Error("Failed to decode login response", "error", err)
		return nil, errors.ErrInvalidResponse
	}

	return &authResponse, nil
}

func (r *authRepository) IntrospectToken(ctx context.Context, token string) (*entities.TokenIntrospectionResponse, error) {
	log := r.logger.WithContext(ctx)

	if token == "" {
		return nil, errors.ErrMissingToken
	}

	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect",
		r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)

	resp, err := r.makeRequest(ctx, "POST", introspectURL, data)
	if err != nil {
		log.Error("Token introspection request failed", "error", err)
		return nil, errors.ErrConnectionFailed
	}

	defer resp.Body.Close()

	var introspectResponse entities.TokenIntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResponse); err != nil {
		log.Error("Failed to decode introspection response", "error", err)
		return nil, errors.ErrInvalidResponse
	}

	return &introspectResponse, nil
}

func (r *authRepository) ValidateRefreshToken(ctx context.Context, refreshToken string) (*entities.TokenIntrospectionResponse, error) {
	log := r.logger.WithContext(ctx)
	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect",
		r.config.BaseURL, r.config.Realm)

	if refreshToken == "" {
		return nil, errors.ErrMissingToken
	}

	data := url.Values{}
	data.Set("token", refreshToken)
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)

	resp, err := r.makeRequest(ctx, "POST", introspectURL, data)
	if err != nil {
		log.Error("Token introspection request failed", "error", err)
		return nil, errors.ErrConnectionFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error("Invalid response from introspection endpoint", "statusCode", resp.StatusCode)
		return nil, r.handleKeycloakError(resp)
	}

	var introspectResponse entities.TokenIntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResponse); err != nil {
		log.Error("Failed to decode introspection response", "error", err)
		return nil, errors.ErrInvalidResponse
	}

	if !introspectResponse.Active {
		log.Info("Refresh token is not active")
		return nil, errors.ErrInvalidToken
	}

	return &introspectResponse, nil
}

func (r *authRepository) RefreshTokens(ctx context.Context, refreshToken string) (*entities.TokenPair, error) {
	log := r.logger.WithContext(ctx)
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("refresh_token", refreshToken)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		log.Error("Refresh token request failed", "error", err)
		return nil, errors.ErrConnectionFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		return nil, errors.ErrTokenExpired
	}

	if resp.StatusCode != http.StatusOK {
		log.Error("Unexpected status code", "statusCode", resp.StatusCode)
		return nil, errors.ErrInvalidResponse
	}

	var authResponse entities.TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Error("Failed to decode refresh token response", "error", err)
		return nil, errors.ErrInvalidResponse
	}

	return &authResponse, nil
}

func (r *authRepository) prepareLoginData(email, password string) url.Values {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("username", email)
	data.Set("password", password)
	data.Set("scope", "openid")
	return data
}

func (r *authRepository) handleKeycloakError(resp *http.Response) error {
	log := r.logger.WithContext(context.Background())

	if resp.StatusCode != http.StatusBadRequest {
		log.Error("Unexpected status code", "statusCode", resp.StatusCode)
		return errors.ErrKeycloakUnexpected
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read error response", "error", err)
		return errors.ErrKeycloakUnexpected
	}

	var keycloakError entities.KeycloakError
	if err := json.Unmarshal(body, &keycloakError); err != nil {
		log.Error("Failed to parse error response", "error", err)
		return errors.ErrInvalidResponse
	}

	log.Debug("Received Keycloak error",
		"error", keycloakError.Error,
		"description", keycloakError.ErrorDescription)

	switch keycloakError.Error {
	case "token_expired":
		return errors.ErrTokenExpired
	case "not_linked":
		return errors.ErrAccountNotLinked
	case "invalid_token":
		return errors.ErrInvalidToken
	default:
		log.Error("Unexpected Keycloak error",
			"error", keycloakError.Error,
			"description", keycloakError.ErrorDescription)
		return errors.ErrKeycloakUnexpected
	}
}
