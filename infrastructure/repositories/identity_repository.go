package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
)

type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error)
	GetIdentity(ctx context.Context, id string) (*entities.KeycloakIdentity, error)
	UpdateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error)
	DeleteIdentity(ctx context.Context, id string) error
	VerifyPassword(ctx context.Context, username string, password string) error
	UpdatePassword(ctx context.Context, id string, newPassword string) error
}

type identityRepository struct {
	*BaseKeycloakRepository
	logger util.Logger
}

func NewIdentityRepository(keycloak *BaseKeycloakRepository) IdentityRepository {
	return &identityRepository{
		BaseKeycloakRepository: keycloak,
		logger:                 util.NewLogger("IdentityRepository"),
	}
}

func (r *identityRepository) CreateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error) {
	log := r.logger.WithContext(ctx)
	log.Info("Starting Keycloak identity creation", "email", identity.Email)

	_, err := r.getAdminToken(ctx)
	if err != nil {
		log.Error("Failed to get admin token", "error", err)
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}
	log.Debug("Successfully obtained admin token")

	usersURL := fmt.Sprintf("%s/admin/realms/%s/users", r.config.BaseURL, r.config.Realm)
	log.Debug("Making request to Keycloak", "url", usersURL)

	// Get the raw password from credentials
	rawPassword := ""
	if len(identity.Credentials) > 0 {
		rawPassword = identity.Credentials[0].Value
	}

	// Create request body with raw password
	createReq := map[string]interface{}{
		"username":   identity.Email,
		"email":      identity.Email,
		"enabled":    true,
		"attributes": identity.Attributes,
		"credentials": []map[string]interface{}{
			{
				"type":      "password",
				"value":     rawPassword, // Send raw password, not hashed
				"temporary": false,
			},
		},
	}

	resp, err := r.makeJSONRequest(ctx, "POST", usersURL, createReq)
	if err != nil {
		log.Error("Failed to make request to Keycloak", "error", err)
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		// Read response body for more details
		body, _ := io.ReadAll(resp.Body)
		log.Error("Received non-201 status from Keycloak",
			"statusCode", resp.StatusCode,
			"body", string(body),
			"headers", resp.Header)
		return nil, fmt.Errorf("failed to create user: %d", resp.StatusCode)
	}

	// Get the created user's ID from Location header
	location := resp.Header.Get("Location")
	log.Debug("Got Location header", "location", location)

	userID := location[strings.LastIndex(location, "/")+1:]
	log.Info("Successfully created user in Keycloak", "id", userID)

	// Retrieve the created identity
	return r.GetIdentity(ctx, userID)
}

func (r *identityRepository) GetIdentity(ctx context.Context, id string) (*entities.KeycloakIdentity, error) {
	log := r.logger.WithContext(ctx)
	log.Debug("Getting identity from Keycloak", "id", id)

	token, err := r.getAdminToken(ctx)
	if err != nil {
		log.Error("Failed to get admin token", "error", err)
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, id)
	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		log.Error("Failed to create request", "error", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Error("Failed to get user", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Failed to get user",
			"statusCode", resp.StatusCode,
			"response", string(body))
		return nil, fmt.Errorf("failed to get user: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read response body", "error", err)
		return nil, err
	}

	log.Debug("Received user data", "response", string(body))

	var identity entities.KeycloakIdentity
	if err := json.Unmarshal(body, &identity); err != nil {
		log.Error("Failed to unmarshal user data",
			"error", err,
			"response", string(body))
		return nil, err
	}

	return &identity, nil
}

func (r *identityRepository) UpdateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error) {
	_, err := r.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, identity.ID)

	// Update user attributes and basic info
	updateReq := map[string]interface{}{
		"email":      identity.Email,
		"attributes": identity.Attributes,
	}

	resp, err := r.makeJSONRequest(ctx, "PUT", userURL, updateReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("failed to update user: %d", resp.StatusCode)
	}

	// If credentials are present, update them
	if len(identity.Credentials) > 0 {
		credentialsURL := fmt.Sprintf("%s/reset-password", userURL)
		for _, cred := range identity.Credentials {
			credReq := map[string]interface{}{
				"type":      cred.Type,
				"value":     cred.Value,
				"temporary": cred.Temporary,
			}

			resp, err := r.makeJSONRequest(ctx, "PUT", credentialsURL, credReq)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				return nil, fmt.Errorf("failed to update credentials: %d", resp.StatusCode)
			}
		}
	}

	// Return the updated identity
	return r.GetIdentity(ctx, identity.ID)
}

func (r *identityRepository) DeleteIdentity(ctx context.Context, id string) error {
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, id)

	req, err := http.NewRequestWithContext(ctx, "DELETE", userURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete user: %d", resp.StatusCode)
	}

	return nil
}

func (r *identityRepository) VerifyPassword(ctx context.Context, username string, password string) error {
	log := r.logger.WithContext(ctx)

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", r.config.BaseURL, r.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)

	log.Debug("Verifying password",
		"username", username,
		"tokenURL", tokenURL,
		"clientId", r.config.ClientID)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Error("Failed to create request", "error", err)
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("Failed to verify password", "error", err)
		return errors.ErrInvalidCredentials
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Invalid credentials",
			"statusCode", resp.StatusCode,
			"response", string(body))
		return errors.ErrInvalidCredentials
	}

	return nil
}

func (r *identityRepository) UpdatePassword(ctx context.Context, id string, newPassword string) error {
	log := r.logger.WithContext(ctx)

	resetURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", r.config.BaseURL, r.config.Realm, id)

	resetData := map[string]interface{}{
		"type":      "password",
		"value":     newPassword,
		"temporary": false,
	}

	resp, err := r.makeJSONRequest(ctx, "PUT", resetURL, resetData)
	if err != nil {
		log.Error("Failed to update password", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Failed to update password",
			"statusCode", resp.StatusCode,
			"response", string(body))
		return fmt.Errorf("failed to update password: %d", resp.StatusCode)
	}

	return nil
}
