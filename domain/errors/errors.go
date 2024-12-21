package errors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPINAlreadyExists   = errors.New("PIN already exists")
	ErrNoPINSet           = errors.New("no PIN set")

	ErrInvalidEmail    = errors.New("invalid email")
	ErrInvalidPassword = errors.New("invalid password")

	ErrMissingToken = errors.New("missing token")

	ErrTokenExpired       = errors.New("token expired")
	ErrAccountNotLinked   = errors.New("account not linked")
	ErrInvalidToken       = errors.New("invalid token")
	ErrKeycloakUnexpected = errors.New("unexpected error occurred")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrInvalidResponse    = errors.New("invalid response format")
	ErrConnectionFailed   = errors.New("failed to connect to Keycloak")
)
