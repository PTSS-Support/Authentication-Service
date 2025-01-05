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
	// see https://www.keycloak.org/securing-apps/token-exchange 'making request' section for more details on what could be in error field
	return !t.Active && t.Error == "token_expired"
}

func (t *TokenIntrospectionResponse) HasInvalidSignature() bool {
	return !t.Active && t.Error == "invalid_token"
}
