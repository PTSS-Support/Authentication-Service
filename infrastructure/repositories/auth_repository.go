package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("username", req.Email)
	data.Set("password", req.Password)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed: %d", resp.StatusCode)
	}

	var authResponse responses.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, err
	}

	return &authResponse, nil
}
