package entities

type TokenIntrospectionResponse struct {
	Active   bool   `json:"active"`
	Exp      int64  `json:"exp"`
	Error    string `json:"error"`
	ErrorMsg string `json:"error_description"`
}

func (t *TokenIntrospectionResponse) IsValid() bool {
	return t.Active && t.Error == ""
}

func (t *TokenIntrospectionResponse) IsExpired() bool {
	// Keycloak only returns {"active": false} for expired tokens
	// see https://www.keycloak.org/docs/latest/authorization_services/index.html#obtaining-information-about-an-rpt or
	//https://www.keycloak.org/securing-apps/token-exchange 'making request' section
	return !t.Active && t.Error == ""
}

func (t *TokenIntrospectionResponse) HasInvalidSignature() bool {
	return !t.Active && t.Error == "invalid_token"
}
