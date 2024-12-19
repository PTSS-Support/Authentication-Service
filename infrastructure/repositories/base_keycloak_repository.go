package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PTSS-Support/identity-service/infrastructure/config"
)

// BaseKeycloakRepository contains common functionality for Keycloak repositories
type BaseKeycloakRepository struct {
	config     *config.KeycloakConfig
	httpClient *http.Client
}

// NewBaseKeycloakRepository creates a new base repository instance
func NewBaseKeycloakRepository(config *config.KeycloakConfig) *BaseKeycloakRepository {
	return &BaseKeycloakRepository{
		config:     config,
		httpClient: &http.Client{},
	}
}

// makeRequest is a helper method for making HTTP requests
func (r *BaseKeycloakRepository) makeRequest(ctx context.Context, method, url string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.httpClient.Do(req)
}

// getAdminToken retrieves an admin token from Keycloak
func (r *BaseKeycloakRepository) getAdminToken(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("username", r.config.AdminUsername)
	data.Set("password", r.config.AdminPassword)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

// getUserIDByEmail retrieves a user's ID using their email
func (r *BaseKeycloakRepository) getUserIDByEmail(ctx context.Context, email string) (string, error) {
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return "", err
	}

	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?email=%s", r.config.BaseURL, r.config.Realm, url.QueryEscape(email))

	req, err := http.NewRequestWithContext(ctx, "GET", usersURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var users []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", err
	}

	if len(users) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return users[0].ID, nil
}

// makeJSONRequest is a helper method for making HTTP requests with JSON body
func (r *BaseKeycloakRepository) makeJSONRequest(ctx context.Context, method, url string, body interface{}) (*http.Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	return r.httpClient.Do(req)
}
