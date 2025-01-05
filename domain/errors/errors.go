package errors

import "errors"

type AppError struct {
	Err           error
	ClientMessage string
}

func (e *AppError) Error() string {
	return e.Err.Error()
}

var (
	ErrInvalidCredentials = &AppError{
		Err:           errors.New("invalid credentials"),
		ClientMessage: "Incorrect email or password. Please try again.",
	}

	ErrPINAlreadyExists = &AppError{
		Err:           errors.New("PIN already exists"),
		ClientMessage: "A PIN has already been set for this account.",
	}

	ErrNoPINSet = &AppError{
		Err:           errors.New("no PIN set"),
		ClientMessage: "PIN authentication is required but has not been set up.",
	}

	ErrGroupIDRequired = &AppError{
		Err:           errors.New("group ID is required for this role"),
		ClientMessage: "This role requires a group assignment.",
	}

	ErrInvalidEmail = &AppError{
		Err:           errors.New("invalid email"),
		ClientMessage: "The email address entered is invalid. Please check and try again.",
	}

	ErrInvalidPassword = &AppError{
		Err:           errors.New("invalid password"),
		ClientMessage: "The password entered is invalid. Please check and try again.",
	}

	ErrMissingToken = &AppError{
		Err:           errors.New("missing token"),
		ClientMessage: "Authentication is required. Please log in.",
	}

	ErrTokenInvalidSignature = &AppError{
		Err:           errors.New("token has invalid signature"),
		ClientMessage: "Your authentication token is invalid. Please log in again.",
	}

	ErrTokenExpired = &AppError{
		Err:           errors.New("token is expired"),
		ClientMessage: "Your session has expired. Please log in again to continue.",
	}

	ErrAccountNotLinked = &AppError{
		Err:           errors.New("account not linked"),
		ClientMessage: "This account is not linked. Please contact support for assistance.",
	}

	ErrInvalidToken = &AppError{
		Err:           errors.New("invalid token"),
		ClientMessage: "Your authentication token is invalid. Please try again.",
	}

	ErrKeycloakUnexpected = &AppError{
		Err:           errors.New("unexpected error occurred"),
		ClientMessage: "An error occurred with the authentication service. Please try again later.",
	}

	ErrInvalidRequest = &AppError{
		Err:           errors.New("invalid request"),
		ClientMessage: "The request is invalid. Please check your input and try again.",
	}

	ErrInvalidResponse = &AppError{
		Err:           errors.New("invalid response format"),
		ClientMessage: "An error occurred. Please try again later.",
	}

	ErrConnectionFailed = &AppError{
		Err:           errors.New("failed to connect to Keycloak"),
		ClientMessage: "The authentication service is temporarily unavailable. Please try again later.",
	}
)
