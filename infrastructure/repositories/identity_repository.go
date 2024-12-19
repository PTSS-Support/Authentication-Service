package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/PTSS-Support/identity-service/domain/entities"
)

type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error)
	GetIdentity(ctx context.Context, id string) (*entities.KeycloakIdentity, error)
	UpdateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error)
	DeleteIdentity(ctx context.Context, id string) error
}

type identityRepository struct {
	*BaseKeycloakRepository
}

func NewIdentityRepository(keycloak *BaseKeycloakRepository) IdentityRepository {
	return &identityRepository{
		BaseKeycloakRepository: keycloak,
	}
}

func (r *identityRepository) CreateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error) {
	_, err := r.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	usersURL := fmt.Sprintf("%s/admin/realms/%s/users", r.config.BaseURL, r.config.Realm)

	// Create request body directly from KeycloakIdentity
	createReq := map[string]interface{}{
		"username":    identity.Email,
		"email":       identity.Email,
		"enabled":     true,
		"attributes":  identity.Attributes,
		"credentials": identity.Credentials,
	}

	resp, err := r.makeJSONRequest(ctx, "POST", usersURL, createReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create user: %d", resp.StatusCode)
	}

	// Get the created user's ID from Location header
	userID := resp.Header.Get("Location")
	// Extract actual ID from the URL
	userID = userID[strings.LastIndex(userID, "/")+1:]

	// Retrieve the created identity
	return r.GetIdentity(ctx, userID)
}

func (r *identityRepository) GetIdentity(ctx context.Context, id string) (*entities.KeycloakIdentity, error) {
	adminToken, err := r.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	userURL := fmt.Sprintf("%s/admin/realms/%s/users/%s", r.config.BaseURL, r.config.Realm, id)

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user: %d", resp.StatusCode)
	}

	var identity entities.KeycloakIdentity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, err
	}

	// Get user credentials separately as they're not included in the main user endpoint
	credentialsURL := fmt.Sprintf("%s/credentials", userURL)
	req, err = http.NewRequestWithContext(ctx, "GET", credentialsURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err = r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&identity.Credentials); err != nil {
			return nil, err
		}
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
