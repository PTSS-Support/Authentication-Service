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
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/auth"
)

type AuthRepository interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
	ValidateAccessToken(ctx context.Context, token string) error
	RefreshTokens(ctx context.Context, refreshToken string) (*responses.AuthResponse, error)
}

type authRepository struct {
	*BaseKeycloakRepository
	logger util.Logger
}

func NewAuthRepository(keycloak *BaseKeycloakRepository) AuthRepository {
	return &authRepository{
		BaseKeycloakRepository: keycloak,
		logger:                 util.NewLogger("AuthRepository"),
	}
}

func (r *authRepository) Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error) {
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

	var authResponse responses.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Error("Failed to decode login response", "error", err)
		return nil, errors.ErrInvalidResponse
	}

	return &authResponse, nil
}

func (r *authRepository) ValidateAccessToken(ctx context.Context, token string) error {
	log := r.logger.WithContext(ctx)
	userinfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo",
		r.config.BaseURL, r.config.Realm)

	log.Debug("Validating access token",
		"url", userinfoURL,
		"token_length", len(token))

	req, err := http.NewRequestWithContext(ctx, "GET", userinfoURL, nil)
	if err != nil {
		log.Error("Failed to create userinfo request", "error", err)
		return errors.ErrInvalidRequest
	}

	req.Header.Set("Authorization", "Bearer "+token)

	log.Debug("Sending userinfo request with headers",
		"headers", req.Header)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Error("Userinfo request failed", "error", err)
		return errors.ErrConnectionFailed
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Debug("Received userinfo response",
		"statusCode", resp.StatusCode,
		"body", string(body),
		"headers", resp.Header)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest {
			log.Debug("Received BadRequest response", "body", string(body))
			return r.handleKeycloakError(resp)
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			log.Debug("Received Unauthorized/Forbidden response", "body", string(body))
			return errors.ErrInvalidToken
		}
		log.Error("Unexpected response",
			"statusCode", resp.StatusCode,
			"body", string(body))
		return errors.ErrInvalidResponse
	}

	log.Debug("Access token validated successfully")
	return nil
}

func (r *authRepository) RefreshTokens(ctx context.Context, refreshToken string) (*responses.AuthResponse, error) {
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

	var authResponse responses.AuthResponse
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
