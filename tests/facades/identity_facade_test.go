package facades_test

import (
	"context"
	authRequests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/tests/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	identityRequests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	identityResponses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/errors"
)

func TestHandleIdentityCreation(t *testing.T) {
	tests := []struct {
		name           string
		request        *identityRequests.CreateIdentityRequest
		mockSetup      func(*mocks.MockIdentityService, *mocks.MockEncryptionService, *mocks.MockAuthService)
		expectedResp   *identityResponses.IdentityResponse
		expectedTokens *entities.TokenPair
		expectedError  error
	}{
		{
			name: "Successful identity creation and login",
			request: &identityRequests.CreateIdentityRequest{
				Email:     "test@example.com",
				Password:  "password123",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService, authService *mocks.MockAuthService) {
				expectedResponse := &identityResponses.IdentityResponse{
					ID:    "user123",
					Email: "test@example.com",
					Role:  enums.RoleAdmin,
				}
				// Mock identity creation
				identityService.On("CreateIdentity", mock.Anything, mock.MatchedBy(func(req *identityRequests.CreateIdentityRequest) bool {
					return req.Email == "test@example.com" && req.Role == enums.RoleAdmin
				}), "password123").Return(expectedResponse, nil)

				// Mock login
				expectedTokens := &entities.TokenPair{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
				}
				authService.On("Login", mock.Anything, mock.MatchedBy(func(req *authRequests.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "password123"
				})).Return(expectedTokens, nil)
			},
			expectedResp: &identityResponses.IdentityResponse{
				ID:    "user123",
				Email: "test@example.com",
				Role:  enums.RoleAdmin,
			},
			expectedTokens: &entities.TokenPair{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "Failed identity creation",
			request: &identityRequests.CreateIdentityRequest{
				Email:     "test@example.com",
				Password:  "password123",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService, _ *mocks.MockAuthService) {
				identityService.On("CreateIdentity", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidEmail)
			},
			expectedError: errors.ErrInvalidEmail,
		},
		{
			name: "Successful creation but failed login",
			request: &identityRequests.CreateIdentityRequest{
				Email:     "test@example.com",
				Password:  "password123",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService, authService *mocks.MockAuthService) {
				// Mock successful identity creation
				expectedResponse := &identityResponses.IdentityResponse{
					ID:    "user123",
					Email: "test@example.com",
					Role:  enums.RoleAdmin,
				}
				identityService.On("CreateIdentity", mock.Anything, mock.Anything, mock.Anything).
					Return(expectedResponse, nil)

				// Mock failed login
				authService.On("Login", mock.Anything, mock.Anything).
					Return(nil, errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockIdentityService := new(mocks.MockIdentityService)
			mockEncryptionService := new(mocks.MockEncryptionService)
			mockAuthService := new(mocks.MockAuthService)
			tt.mockSetup(mockIdentityService, mockEncryptionService, mockAuthService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &mocks.MockLoggerFactory{}, mockAuthService)

			// Execute
			response, tokens, err := facade.HandleIdentityCreation(context.Background(), tt.request)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
				assert.Nil(t, response)
				assert.Equal(t, &entities.TokenPair{}, tokens)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				require.NotNil(t, tokens)
				assert.Equal(t, tt.expectedResp.ID, response.ID)
				assert.Equal(t, tt.expectedResp.Email, response.Email)
				assert.Equal(t, tt.expectedResp.Role, response.Role)
				assert.Equal(t, tt.expectedTokens.AccessToken, tokens.AccessToken)
				assert.Equal(t, tt.expectedTokens.RefreshToken, tokens.RefreshToken)
			}

			mockIdentityService.AssertExpectations(t)
			mockEncryptionService.AssertExpectations(t)
			mockAuthService.AssertExpectations(t)
		})
	}
}

func TestHandlePINCreation(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		request       *identityRequests.CreatePINRequest
		mockSetup     func(*mocks.MockIdentityService, *mocks.MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful PIN creation",
			id:   "user123",
			request: &identityRequests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Check current PIN doesn't exist
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("", nil)

				// Hash the new PIN
				encryptionService.On("HashPIN", "1234").
					Return("hashedPin123", nil)

				// Set the new PIN
				identityService.On("SetPIN", mock.Anything, "user123", "hashedPin123").
					Return(nil)
			},
		},
		{
			name: "PIN already exists",
			id:   "user123",
			request: &identityRequests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Hash the PIN first (this happens in the implementation before checking existence)
				encryptionService.On("HashPIN", "1234").
					Return("hashedPin123", nil)

				// Then check if PIN exists
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("existingHashedPin", nil)
			},
			expectedError: errors.ErrPINAlreadyExists,
		},
		{
			name: "PIN hashing fails",
			id:   "user123",
			request: &identityRequests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Only mock the HashPIN call since it fails and returns early
				encryptionService.On("HashPIN", "1234").
					Return("", errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
		{
			name: "Service SetPIN fails",
			id:   "user123",
			request: &identityRequests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// No existing PIN
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("", nil)

				// Successful hash
				encryptionService.On("HashPIN", "1234").
					Return("hashedPin123", nil)

				// SetPIN fails
				identityService.On("SetPIN", mock.Anything, "user123", "hashedPin123").
					Return(errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockIdentityService := new(mocks.MockIdentityService)
			mockEncryptionService := new(mocks.MockEncryptionService)
			mockAuthService := new(mocks.MockAuthService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &mocks.MockLoggerFactory{}, mockAuthService)

			// Execute
			err := facade.HandlePINCreation(context.Background(), tt.id, tt.request)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockIdentityService.AssertExpectations(t)
			mockEncryptionService.AssertExpectations(t)
		})
	}
}

func TestHandlePINUpdate(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		request       *identityRequests.UpdatePINRequest
		mockSetup     func(*mocks.MockIdentityService, *mocks.MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful PIN update",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Get current PIN hash
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("currentHashedPin", nil)

				// Verify old PIN
				encryptionService.On("VerifyPIN", "currentHashedPin", "1234").
					Return(true, nil)

				// Hash new PIN
				encryptionService.On("HashPIN", "5678").
					Return("newHashedPin", nil)

				// Update PIN
				identityService.On("UpdatePIN", mock.Anything, "user123", "newHashedPin").
					Return(nil)
			},
		},
		{
			name: "No existing PIN",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService) {
				// No existing PIN
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("", nil)
			},
			expectedError: errors.ErrNoPINSet,
		},
		{
			name: "Invalid old PIN",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "wrong",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Get current PIN hash
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("currentHashedPin", nil)

				// Verify old PIN fails
				encryptionService.On("VerifyPIN", "currentHashedPin", "wrong").
					Return(false, nil)
			},
			expectedError: errors.ErrInvalidCredentials,
		},
		{
			name: "PIN hashing fails",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Get current PIN hash
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("currentHashedPin", nil)

				// Verify old PIN succeeds
				encryptionService.On("VerifyPIN", "currentHashedPin", "1234").
					Return(true, nil)

				// Hash new PIN fails
				encryptionService.On("HashPIN", "5678").
					Return("", errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
		{
			name: "Service update fails",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Get current PIN hash
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("currentHashedPin", nil)

				// Verify old PIN succeeds
				encryptionService.On("VerifyPIN", "currentHashedPin", "1234").
					Return(true, nil)

				// Hash new PIN succeeds
				encryptionService.On("HashPIN", "5678").
					Return("newHashedPin", nil)

				// Update PIN fails
				identityService.On("UpdatePIN", mock.Anything, "user123", "newHashedPin").
					Return(errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
		{
			name: "PIN verification throws error",
			id:   "user123",
			request: &identityRequests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, encryptionService *mocks.MockEncryptionService) {
				// Get current PIN hash
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("currentHashedPin", nil)

				// Verify old PIN throws error
				encryptionService.On("VerifyPIN", "currentHashedPin", "1234").
					Return(false, errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockIdentityService := new(mocks.MockIdentityService)
			mockEncryptionService := new(mocks.MockEncryptionService)
			mockAuthService := new(mocks.MockAuthService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &mocks.MockLoggerFactory{}, mockAuthService)

			// Execute
			err := facade.HandlePINUpdate(context.Background(), tt.id, tt.request)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockIdentityService.AssertExpectations(t)
			mockEncryptionService.AssertExpectations(t)
		})
	}
}

func TestHandlePasswordUpdate(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		request       *identityRequests.UpdatePasswordRequest
		mockSetup     func(*mocks.MockIdentityService, *mocks.MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful password update",
			id:   "user123",
			request: &identityRequests.UpdatePasswordRequest{
				OldPassword: "oldPass123",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService) {
				// Verify old password
				identityService.On("VerifyPassword", mock.Anything, "user123", "oldPass123").
					Return(nil)
				// Update to new password
				identityService.On("UpdatePassword", mock.Anything, "user123", "newPass123").
					Return(nil)
			},
		},
		{
			name: "Old password verification fails",
			id:   "user123",
			request: &identityRequests.UpdatePasswordRequest{
				OldPassword: "wrongPass",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService) {
				identityService.On("VerifyPassword", mock.Anything, "user123", "wrongPass").
					Return(errors.ErrInvalidCredentials)
			},
			expectedError: errors.ErrInvalidCredentials,
		},
		{
			name: "Password update fails",
			id:   "user123",
			request: &identityRequests.UpdatePasswordRequest{
				OldPassword: "oldPass123",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *mocks.MockIdentityService, _ *mocks.MockEncryptionService) {
				// Verify old password succeeds
				identityService.On("VerifyPassword", mock.Anything, "user123", "oldPass123").
					Return(nil)
				// But update fails
				identityService.On("UpdatePassword", mock.Anything, "user123", "newPass123").
					Return(errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockIdentityService := new(mocks.MockIdentityService)
			mockEncryptionService := new(mocks.MockEncryptionService)
			mockAuthService := new(mocks.MockAuthService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &mocks.MockLoggerFactory{}, mockAuthService)

			// Execute
			err := facade.HandlePasswordUpdate(context.Background(), tt.id, tt.request)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockIdentityService.AssertExpectations(t)
			mockEncryptionService.AssertExpectations(t)
		})
	}
}
