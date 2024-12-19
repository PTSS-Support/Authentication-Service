package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PTSS-Support/identity-service/api/dtos/requests"
	"github.com/PTSS-Support/identity-service/api/dtos/responses"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
)

type KeycloakRepository interface {
	Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*responses.AuthResponse, error)
	ValidateToken(ctx context.Context, token string) (bool, error)
	RegisterUser(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error)
	GetUserInfo(ctx context.Context, token string) (*responses.UserResponse, error)
	LoginWithPin(ctx context.Context, req *requests.PinLoginRequest) (*responses.AuthResponse, error)
	CreatePin(ctx context.Context, userID string, req *requests.PinCreateRequest) error
	UpdatePin(ctx context.Context, userID string, req *requests.PinUpdateRequest) error
}

type keycloakRepository struct {
	config     *config.KeycloakConfig
	httpClient *http.Client
}

func NewKeycloakRepository(config *config.KeycloakConfig) KeycloakRepository {
	return &keycloakRepository{
		config:     config,
		httpClient: &http.Client{},
	}
}

func (r *keycloakRepository) Login(ctx context.Context, req *requests.LoginRequest) (*responses.AuthResponse, error) {
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

func (r *keycloakRepository) RefreshToken(ctx context.Context, refreshToken string) (*responses.AuthResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("refresh_token", refreshToken)

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %d", resp.StatusCode)
	}

	var tokenResponse responses.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (r *keycloakRepository) ValidateToken(ctx context.Context, token string) (bool, error) {
	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)

	fmt.Printf("Validating token: %s\n", token[:10]) // Print first 10 chars of token
	fmt.Printf("URL: %s\n", introspectURL)

	resp, err := r.makeRequest(ctx, "POST", introspectURL, data)
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return false, err
	}
	defer resp.Body.Close()

	// Read the response body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response status: %d\n", resp.StatusCode)
	fmt.Printf("Response body: %s\n", string(bodyBytes))

	// Create new reader for the actual processing
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var result struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Decode error: %v\n", err)
		return false, err
	}

	return result.Active, nil
}
func (r *keycloakRepository) RegisterUser(ctx context.Context, req *requests.RegisterRequest) (*responses.CreateIdentityResponse, error) {
	// First, get admin token
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	// Create user in Keycloak
	usersURL := fmt.Sprintf("%s/admin/realms/%s/users", r.config.BaseURL, r.config.Realm)

	userReq := map[string]interface{}{
		"email":     req.Email,
		"username":  req.Email, // Using email as username
		"enabled":   true,
		"firstName": req.FirstName,
		"lastName":  req.LastName,
		"attributes": map[string][]string{
			"role": {string(req.Role)},
		},
		"credentials": []map[string]interface{}{
			{
				"type":      "password",
				"value":     req.Password,
				"temporary": false,
			},
		},
	}

	jsonBody, err := json.Marshal(userReq)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "POST", usersURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create user: %d", resp.StatusCode)
	}

	// Get user ID from Location header
	location := resp.Header.Get("Location")
	userID := strings.TrimPrefix(location, fmt.Sprintf("%s/admin/realms/%s/users/", r.config.BaseURL, r.config.Realm))

	return &responses.CreateIdentityResponse{
		ID:       userID,
		Username: req.Email,
	}, nil
}

func (r *keycloakRepository) GetUserInfo(ctx context.Context, token string) (*responses.UserResponse, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", r.config.BaseURL, r.config.Realm)

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %d", resp.StatusCode)
	}

	var userInfo responses.UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (r *keycloakRepository) LoginWithPin(ctx context.Context, req *requests.PinLoginRequest) (*responses.AuthResponse, error) {
	// First, get the user ID by email
	userID, err := r.getUserIDByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	// Verify PIN (you'll need to implement this based on how you store PINs)
	if err := r.verifyPin(ctx, userID, req.Pin); err != nil {
		return nil, err
	}

	// If PIN is valid, generate tokens using client credentials
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("scope", "openid")

	resp, err := r.makeRequest(ctx, "POST", tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authResponse responses.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, err
	}

	return &authResponse, nil
}

func (r *keycloakRepository) CreatePin(ctx context.Context, userID string, req *requests.PinCreateRequest) error {
	// Get admin token
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return err
	}

	// Update user attributes to store PIN (hashed)
	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, userID)

	// In a real implementation, you should hash the PIN before storing
	updateReq := map[string]interface{}{
		"attributes": map[string][]string{
			"pin": {req.Pin}, // In production, store a hashed version
		},
	}

	jsonBody, err := json.Marshal(updateReq)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, "PUT", userURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to create PIN: %d", resp.StatusCode)
	}

	return nil
}

func (r *keycloakRepository) UpdatePin(ctx context.Context, userID string, req *requests.PinUpdateRequest) error {
	// Verify old PIN first
	if err := r.verifyPin(ctx, userID, req.OldPin); err != nil {
		return err
	}

	// If old PIN is valid, update to new PIN
	return r.CreatePin(ctx, userID, &requests.PinCreateRequest{Pin: req.NewPin})
}

// Helper methods

func (r *keycloakRepository) makeRequest(ctx context.Context, method, url string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.httpClient.Do(req)
}

func (r *keycloakRepository) getAdminToken(ctx context.Context) (string, error) {
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

func (r *keycloakRepository) getUserIDByEmail(ctx context.Context, email string) (string, error) {
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

func (r *keycloakRepository) verifyPin(ctx context.Context, userID, pin string) error {
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var user struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return err
	}

	storedPin, exists := user.Attributes["pin"]
	if !exists || len(storedPin) == 0 {
		return fmt.Errorf("PIN not set")
	}

	// In production, you should compare hashed versions
	if storedPin[0] != pin {
		return fmt.Errorf("invalid PIN")
	}

	return nil
}
