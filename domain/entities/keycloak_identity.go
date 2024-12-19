package entities

import (
	"time"

	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/models"
)

// KeycloakIdentity represents the Keycloak user structure
type KeycloakIdentity struct {
	ID          string               `json:"id"`
	CreatedAt   time.Time            `json:"createdTimestamp"`
	Email       string               `json:"email"`
	Attributes  map[string][]string  `json:"attributes"`
	Credentials []KeycloakCredential `json:"credentials,omitempty"`
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

	return &models.Identity{
		ID:    ki.ID,
		Email: ki.Email,
		PIN:   pin,
		Role:  role,
	}
}

// FromModel creates a KeycloakIdentity from a domain Identity model
func FromModel(model *models.Identity, hashedPassword string) *KeycloakIdentity {
	attributes := map[string][]string{
		"role": {string(model.Role)},
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
		Email:       model.Email,
		Attributes:  attributes,
		Credentials: credentials,
	}
}
