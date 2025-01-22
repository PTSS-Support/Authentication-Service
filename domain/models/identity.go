package models

import "github.com/PTSS-Support/identity-service/domain/enums"

// Identity represents the authentication-specific user data
type Identity struct {
	ID        string
	UserID    string
	Email     string
	Password  string
	PIN       *string
	Role      enums.Role
	GroupID   string
	FirstName string
	LastName  string
}
