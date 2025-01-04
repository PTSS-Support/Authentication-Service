package entities

import (
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/models"
	"strconv"
)

// KeycloakIdentity represents the Keycloak user structure
type KeycloakIdentity struct {
	ID               string               `json:"id,omitempty"`
	CreatedTimestamp int64                `json:"createdTimestamp,omitempty"`
	Username         string               `json:"username"` // Required by Keycloak
	Email            string               `json:"email"`
	Enabled          bool                 `json:"enabled"` // Required by Keycloak
	FirstName        string               `json:"firstName"`
	LastName         string               `json:"lastName"`
	Attributes       map[string][]string  `json:"attributes"`
	Credentials      []KeycloakCredential `json:"credentials,omitempty"`
}

// ToModel converts a KeycloakIdentity to a domain Identity model
func (ki *KeycloakIdentity) ToModel() *models.Identity {
	var pin *string
	if pinValues, exists := ki.Attributes["pin"]; exists && len(pinValues) > 0 {
		pinValue := pinValues[0]
		pin = &pinValue
	}

	var role enums.Role
	if roleValues, exists := ki.Attributes["role"]; exists && len(roleValues) > 0 {
		role = enums.Role(roleValues[0])
	}

	var groupID string
	if groupValues, exists := ki.Attributes["groupId"]; exists && len(groupValues) > 0 {
		groupID = groupValues[0]
	}

	return &models.Identity{
		ID:        ki.ID,
		Email:     ki.Email,
		PIN:       pin,
		Role:      role,
		GroupID:   groupID,
		FirstName: ki.FirstName,
		LastName:  ki.LastName,
	}
}

// FromModel creates a KeycloakIdentity from a domain Identity model
func FromModel(model *models.Identity, hashedPassword string) *KeycloakIdentity {
	attributes := map[string][]string{
		"role":    {string(model.Role)},
		"hasPin":  {strconv.FormatBool(model.PIN != nil)},
		"groupId": {model.GroupID},
	}

	if model.PIN != nil {
		attributes["pin"] = []string{*model.PIN}
	}

	credentials := []KeycloakCredential{
		{
			Type:      "password",
			Value:     hashedPassword,
			Temporary: false,
		},
	}

	return &KeycloakIdentity{
		ID:          model.ID,
		Username:    model.Email, // Use email as username
		Email:       model.Email,
		Enabled:     true, // Always enable users by default
		FirstName:   model.FirstName,
		LastName:    model.LastName,
		Attributes:  attributes,
		Credentials: credentials,
	}
}
