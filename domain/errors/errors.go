package errors

import (
	"errors"
	"net/http"
)

type AppError struct {
	Code          string
	Err           error
	ClientMessage string
	StatusCode    int
}

func (e *AppError) Error() string {
	return e.Err.Error()
}

var (
	ErrInvalidCredentials = &AppError{
		Code:          "INVALID_CREDENTIALS",
		Err:           errors.New("invalid credentials"),
		ClientMessage: "Incorrect email or password. Please try again.",
		StatusCode:    http.StatusUnauthorized,
	}

	ErrPINAlreadyExists = &AppError{
		Code:          "PIN_EXISTS",
		Err:           errors.New("PIN already exists"),
		ClientMessage: "A PIN has already been set for this account.",
		StatusCode:    http.StatusConflict,
	}

	ErrNoPINSet = &AppError{
		Code:          "NO_PIN",
		Err:           errors.New("no PIN set"),
		ClientMessage: "PIN authentication is required but has not been set up.",
		StatusCode:    http.StatusBadRequest,
	}

	ErrGroupIDRequired = &AppError{
		Code:          "GROUP_REQUIRED",
		Err:           errors.New("group ID is required for this role"),
		ClientMessage: "This role requires a group assignment.",
		StatusCode:    http.StatusBadRequest,
	}

	ErrInvalidEmail = &AppError{
		Code:          "INVALID_EMAIL",
		Err:           errors.New("invalid email"),
		ClientMessage: "The email address entered is invalid. Please check and try again.",
		StatusCode:    http.StatusBadRequest,
	}

	ErrInvalidPassword = &AppError{
		Code:          "INVALID_PASSWORD",
		Err:           errors.New("invalid password"),
		ClientMessage: "The password entered is invalid. Please check and try again.",
		StatusCode:    http.StatusBadRequest,
	}

	ErrMissingToken = &AppError{
		Code:          "MISSING_TOKEN",
		Err:           errors.New("missing token"),
		ClientMessage: "Authentication is required. Please log in.",
		StatusCode:    http.StatusUnauthorized,
	}

	ErrTokenExpired = &AppError{
		Code:          "TOKEN_EXPIRED",
		Err:           errors.New("token is expired"),
		ClientMessage: "Your session has expired. Please log in again to continue.",
		StatusCode:    http.StatusUnauthorized,
	}

	ErrAccountNotLinked = &AppError{
		Code:          "ACCOUNT_NOT_LINKED",
		Err:           errors.New("account not linked"),
		ClientMessage: "This account is not linked. Please contact support for assistance.",
		StatusCode:    http.StatusBadRequest,
	}

	ErrInvalidToken = &AppError{
		Code:          "INVALID_TOKEN",
		Err:           errors.New("invalid token"),
		ClientMessage: "Your authentication token is invalid. Please try again.",
		StatusCode:    http.StatusUnauthorized,
	}

	ErrKeycloakUnexpected = &AppError{
		Code:          "UNEXPECTED_KEYCLOAK_ERROR",
		Err:           errors.New("unexpected error occurred"),
		ClientMessage: "An error occurred with the authentication service. Please try again later.",
		StatusCode:    http.StatusInternalServerError,
	}

	ErrInvalidResponse = &AppError{
		Code:          "INVALID_RESPONSE",
		Err:           errors.New("invalid response format from an external service"),
		ClientMessage: "An error occurred. Please try again later.",
		StatusCode:    http.StatusInternalServerError,
	}

	ErrConnectionFailed = &AppError{
		Code:          "CONNECTION_FAILED",
		Err:           errors.New("failed to connect to Keycloak"),
		ClientMessage: "The authentication service is temporarily unavailable. Please try again later.",
		StatusCode:    http.StatusServiceUnavailable,
	}

	ErrMissingPIN = &AppError{
		Code:          "ERR_MISSING_PIN",
		Err:           errors.New("missing PIN"),
		ClientMessage: "Please enter your PIN to continue.",
		StatusCode:    http.StatusBadRequest,
	}
)
