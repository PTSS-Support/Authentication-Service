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
		ClientMessage: "Invalid email or password",
	}

	ErrPINAlreadyExists = &AppError{
		Err:           errors.New("PIN already exists"),
		ClientMessage: "A PIN is already set for this account",
	}

	ErrNoPINSet = &AppError{
		Err:           errors.New("no PIN set"),
		ClientMessage: "PIN authentication is required but not set up",
	}

	ErrGroupIDRequired = &AppError{
		Err:           errors.New("group ID is required for this role"),
		ClientMessage: "Group assignment is required for this role",
	}

	ErrInvalidEmail = &AppError{
		Err:           errors.New("invalid email"),
		ClientMessage: "Please enter a valid email address",
	}

	ErrInvalidPassword = &AppError{
		Err:           errors.New("invalid password"),
		ClientMessage: "Please enter a valid password",
	}

	ErrMissingToken = &AppError{
		Err:           errors.New("missing token"),
		ClientMessage: "Authentication required",
	}

	ErrTokenInvalidSignature = &AppError{
		Err:           errors.New("token has invalid signature"),
		ClientMessage: "Invalid authentication token",
	}

	ErrTokenExpired = &AppError{
		Err:           errors.New("token is expired"),
		ClientMessage: "Your session has expired, please login again",
	}

	ErrAccountNotLinked = &AppError{
		Err:           errors.New("account not linked"),
		ClientMessage: "This account is not properly linked",
	}

	ErrInvalidToken = &AppError{
		Err:           errors.New("invalid token"),
		ClientMessage: "Invalid authentication token",
	}

	ErrKeycloakUnexpected = &AppError{
		Err:           errors.New("unexpected error occurred"),
		ClientMessage: "Authentication service error",
	}

	ErrInvalidRequest = &AppError{
		Err:           errors.New("invalid request"),
		ClientMessage: "Invalid request format",
	}

	ErrInvalidResponse = &AppError{
		Err:           errors.New("invalid response format"),
		ClientMessage: "Service returned an invalid response",
	}

	ErrConnectionFailed = &AppError{
		Err:           errors.New("failed to connect to Keycloak"),
		ClientMessage: "Authentication service temporarily unavailable",
	}
)
