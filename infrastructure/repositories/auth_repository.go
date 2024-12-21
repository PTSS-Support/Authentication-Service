package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/auth"
)

type AuthRepository interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
}

type authRepository struct {
	*BaseKeycloakRepository
}

func NewAuthRepository(keycloak *BaseKeycloakRepository) AuthRepository {
	return &authRepository{
		BaseKeycloakRepository: keycloak,
	}
}

func (r *authRepository) Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error) {
	tokenURL := r.getTokenEndpoint()

	if _, err := url.Parse(tokenURL); err != nil {
		return nil, fmt.Errorf("invalid token URL: %w", err)
	}

	data := r.prepareLoginData(req.Email, req.Password)

	resp, err := r.makeRequest(ctx, http.MethodPost, tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to make login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResponse responses.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}

	return &authResponse, nil
}

func (r *authRepository) getTokenEndpoint() string {
	baseURL := strings.TrimSuffix(r.config.BaseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		baseURL,
		r.config.Realm,
	)
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
