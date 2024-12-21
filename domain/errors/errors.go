package errors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPINAlreadyExists   = errors.New("PIN already exists")
	ErrNoPINSet           = errors.New("no PIN set")
)
