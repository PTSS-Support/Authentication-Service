package entities

// KeycloakCredential represents Keycloak credential structure
type KeycloakCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}
