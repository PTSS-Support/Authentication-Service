package facades_test

import (
	"context"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/core/facades"
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/errors"
)

// Mock Services
type MockIdentityService struct {
	mock.Mock
}

func (m *MockIdentityService) CreateIdentity(ctx context.Context, req *requests.CreateIdentityRequest, hashedPassword string) (*responses.IdentityResponse, error) {
	args := m.Called(ctx, req, hashedPassword)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*responses.IdentityResponse), args.Error(1)
}

func (m *MockIdentityService) UpdateRole(ctx context.Context, id string, req *requests.UpdateRoleRequest) (*responses.IdentityResponse, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*responses.IdentityResponse), args.Error(1)
}

func (m *MockIdentityService) DeleteIdentity(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockIdentityService) VerifyPassword(ctx context.Context, id string, password string) error {
	args := m.Called(ctx, id, password)
	return args.Error(0)
}

func (m *MockIdentityService) UpdatePassword(ctx context.Context, id string, newPassword string) error {
	args := m.Called(ctx, id, newPassword)
	return args.Error(0)
}

func (m *MockIdentityService) GetCurrentPINHash(ctx context.Context, id string) (string, error) {
	args := m.Called(ctx, id)
	return args.String(0), args.Error(1)
}

func (m *MockIdentityService) UpdatePIN(ctx context.Context, id string, hashedPIN string) error {
	args := m.Called(ctx, id, hashedPIN)
	return args.Error(0)
}

func (m *MockIdentityService) SetPIN(ctx context.Context, id string, hashedPIN string) error {
	args := m.Called(ctx, id, hashedPIN)
	return args.Error(0)
}

func (m *MockIdentityService) GetHashedPIN(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

type MockEncryptionService struct {
	mock.Mock
}

func (m *MockEncryptionService) HashPIN(pin string) (string, error) {
	args := m.Called(pin)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) VerifyPIN(hashedPIN string, pin string) (bool, error) {
	args := m.Called(hashedPIN, pin)
	return args.Bool(0), args.Error(1)
}

// Mock Logger
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...interface{}) {}
func (m *MockLogger) Info(msg string, args ...interface{})  {}
func (m *MockLogger) Warn(msg string, args ...interface{})  {}
func (m *MockLogger) Error(msg string, args ...interface{}) {}
func (m *MockLogger) WithContext(ctx context.Context) util.Logger {
	return m
}

type MockLoggerFactory struct{}

func (m *MockLoggerFactory) NewLogger(name string) util.Logger {
	return &MockLogger{}
}

func TestHandleIdentityCreation(t *testing.T) {
	tests := []struct {
		name          string
		request       *requests.CreateIdentityRequest
		mockSetup     func(*MockIdentityService, *MockEncryptionService)
		expectedResp  *responses.IdentityResponse
		expectedError error
	}{
		{
			name: "Successful identity creation",
			request: &requests.CreateIdentityRequest{
				Email:     "test@example.com",
				Password:  "password123",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
				expectedResponse := &responses.IdentityResponse{
					ID:    "user123",
					Email: "test@example.com",
					Role:  enums.RoleAdmin,
				}
				identityService.On("CreateIdentity", mock.Anything, mock.MatchedBy(func(req *requests.CreateIdentityRequest) bool {
					return req.Email == "test@example.com" && req.Role == enums.RoleAdmin
				}), "password123").Return(expectedResponse, nil)
			},
			expectedResp: &responses.IdentityResponse{
				ID:    "user123",
				Email: "test@example.com",
				Role:  enums.RoleAdmin,
			},
		},
		{
			name: "Service returns error",
			request: &requests.CreateIdentityRequest{
				Email:     "test@example.com",
				Password:  "password123",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
				identityService.On("CreateIdentity", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidEmail)
			},
			expectedError: errors.ErrInvalidEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockIdentityService := new(MockIdentityService)
			mockEncryptionService := new(MockEncryptionService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &MockLoggerFactory{})

			// Execute
			response, err := facade.HandleIdentityCreation(context.Background(), tt.request)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, tt.expectedResp.ID, response.ID)
				assert.Equal(t, tt.expectedResp.Email, response.Email)
				assert.Equal(t, tt.expectedResp.Role, response.Role)
			}

			mockIdentityService.AssertExpectations(t)
			mockEncryptionService.AssertExpectations(t)
		})
	}
}

func TestHandlePINCreation(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		request       *requests.CreatePINRequest
		mockSetup     func(*MockIdentityService, *MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful PIN creation",
			id:   "user123",
			request: &requests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
				// Only mock the HashPIN call since it fails and returns early
				encryptionService.On("HashPIN", "1234").
					Return("", errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
		{
			name: "Service SetPIN fails",
			id:   "user123",
			request: &requests.CreatePINRequest{
				PIN: "1234",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			mockIdentityService := new(MockIdentityService)
			mockEncryptionService := new(MockEncryptionService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &MockLoggerFactory{})

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
		request       *requests.UpdatePINRequest
		mockSetup     func(*MockIdentityService, *MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful PIN update",
			id:   "user123",
			request: &requests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
				// No existing PIN
				identityService.On("GetCurrentPINHash", mock.Anything, "user123").
					Return("", nil)
			},
			expectedError: errors.ErrNoPINSet,
		},
		{
			name: "Invalid old PIN",
			id:   "user123",
			request: &requests.UpdatePINRequest{
				OldPIN: "wrong",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			request: &requests.UpdatePINRequest{
				OldPIN: "1234",
				NewPIN: "5678",
			},
			mockSetup: func(identityService *MockIdentityService, encryptionService *MockEncryptionService) {
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
			mockIdentityService := new(MockIdentityService)
			mockEncryptionService := new(MockEncryptionService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &MockLoggerFactory{})

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
		request       *requests.UpdatePasswordRequest
		mockSetup     func(*MockIdentityService, *MockEncryptionService)
		expectedError error
	}{
		{
			name: "Successful password update",
			id:   "user123",
			request: &requests.UpdatePasswordRequest{
				OldPassword: "oldPass123",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
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
			request: &requests.UpdatePasswordRequest{
				OldPassword: "wrongPass",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
				identityService.On("VerifyPassword", mock.Anything, "user123", "wrongPass").
					Return(errors.ErrInvalidCredentials)
			},
			expectedError: errors.ErrInvalidCredentials,
		},
		{
			name: "Password update fails",
			id:   "user123",
			request: &requests.UpdatePasswordRequest{
				OldPassword: "oldPass123",
				NewPassword: "newPass123",
			},
			mockSetup: func(identityService *MockIdentityService, _ *MockEncryptionService) {
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
			mockIdentityService := new(MockIdentityService)
			mockEncryptionService := new(MockEncryptionService)
			tt.mockSetup(mockIdentityService, mockEncryptionService)

			facade := facades.NewIdentityFacade(mockIdentityService, mockEncryptionService, &MockLoggerFactory{})

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
