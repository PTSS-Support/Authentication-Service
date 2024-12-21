package entities

type KeycloakError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccountLinkURL   string `json:"account-link-url"`
}
