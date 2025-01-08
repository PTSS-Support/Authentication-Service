package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/PTSS-Support/identity-service/infrastructure/cache"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BaseKeycloakRepository contains common functionality for Keycloak repositories
type BaseKeycloakRepository struct {
	config     *config.KeycloakConfig
	httpClient *http.Client
	logger     util.Logger
	tokenCache cache.TokenCache
}

// NewBaseKeycloakRepository creates a new base repository instance
func NewBaseKeycloakRepository(config *config.KeycloakConfig, loggerFactory util.LoggerFactory) *BaseKeycloakRepository {
	return &BaseKeycloakRepository{
		config:     config,
		httpClient: &http.Client{},
		logger:     loggerFactory.NewLogger("BaseKeycloakRepository"),
		tokenCache: cache.NewTokenCache(),
	}
}

// makeRequest is a helper method for making HTTP requests
func (r *BaseKeycloakRepository) makeRequest(ctx context.Context, method, url string, data url.Values) (*http.Response, error) {
	log := r.logger.WithContext(ctx)
	log.Debug("Making HTTP request",
		"method", method,
		"url", url,
		"data", data.Encode())

	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(data.Encode()))
	if err != nil {
		log.Error("Failed to create HTTP request", "error", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Error("HTTP request failed", "error", err)
		return nil, fmt.Errorf("request failed: %w", err)
	}

	log.Debug("Received HTTP response",
		"statusCode", resp.StatusCode,
		"headers", resp.Header)

	return resp, nil
}

func (r *BaseKeycloakRepository) getAdminToken(ctx context.Context) (string, error) {
	// Try to get cached token
	if token, valid := r.tokenCache.GetValidToken(); valid {
		return token, nil
	}

	// Token not valid or not found, refresh it
	token, expiresIn, err := r.refreshAdminToken(ctx)
	if err != nil {
		return "", err
	}

	r.tokenCache.SetToken(token, expiresIn)
	return token, nil
}

func (r *BaseKeycloakRepository) refreshAdminToken(ctx context.Context) (token string, expiresIn int, err error) {
	log := r.logger.WithContext(ctx)
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", r.config.BaseURL)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", r.config.AdminClientID)
	data.Set("username", r.config.AdminUsername)
	data.Set("password", r.config.AdminPassword)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		log.Error("Failed to make token request", "error", err)
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read response body", "error", err)
		return "", 0, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Error("Failed to get admin token",
			"statusCode", resp.StatusCode,
			"response", string(body))
		return "", 0, fmt.Errorf("failed to get token: status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Error("Failed to decode token response",
			"error", err,
			"response", string(body))
		return "", 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	log.Info("Successfully obtained admin token")
	return result.AccessToken, result.ExpiresIn, nil
}

func (r *BaseKeycloakRepository) makeJSONRequest(ctx context.Context, method, url string, body interface{}) (*http.Response, error) {
	log := r.logger.WithContext(ctx)
	log.Debug("Making JSON request",
		"method", method,
		"url", url)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		log.Error("Failed to marshal JSON body", "error", err)
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	log.Debug("Request body", "json", string(jsonBody))

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Error("Failed to create HTTP request", "error", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	token, err := r.getAdminToken(ctx)
	if err != nil {
		log.Error("Failed to get admin token for JSON request", "error", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Error("JSON request failed", "error", err)
		return nil, fmt.Errorf("request failed: %w", err)
	}

	log.Debug("Received JSON response",
		"statusCode", resp.StatusCode,
		"headers", resp.Header)

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Received error response",
			"statusCode", resp.StatusCode,
			"body", string(body))
		resp.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset the body for further reading
	}

	return resp, nil
}
