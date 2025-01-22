package services_test

import (
	"context"
	"github.com/PTSS-Support/identity-service/tests/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	"github.com/PTSS-Support/identity-service/core/services"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/PTSS-Support/identity-service/domain/enums"
	"github.com/PTSS-Support/identity-service/domain/errors"
)

func TestCreateIdentity(t *testing.T) {
	tests := []struct {
		name           string
		request        *requests.CreateIdentityRequest
		hashedPassword string
		mockSetup      func(*mocks.MockIdentityRepository)
		expectedError  error
		expectedID     string
	}{
		{
			name: "Successful identity creation for admin role",
			request: &requests.CreateIdentityRequest{
				Email:     "admin@test.com",
				Role:      enums.RoleAdmin,
				FirstName: "Admin",
				LastName:  "User",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock the email check - return nil to indicate email doesn't exist
				repo.On("GetIdentityByEmail", mock.Anything, "admin@test.com").Return(nil, nil)

				// Mock the creation
				repo.On("CreateIdentity", mock.Anything, mock.MatchedBy(func(identity *entities.KeycloakIdentity) bool {
					return identity.Email == "admin@test.com" &&
						len(identity.Attributes["userId"]) > 0
				})).Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "admin@test.com",
					Attributes: map[string][]string{
						"role":   {string(enums.RoleAdmin)},
						"userId": {"user123"},
					},
				}, nil)
			},
			expectedID: "user123",
		},
		{
			name: "Successful identity creation for healthcare professional",
			request: &requests.CreateIdentityRequest{
				Email:     "doctor@hospital.com",
				Role:      enums.RoleHealthcareProfessional,
				FirstName: "Doctor",
				LastName:  "Smith",
				GroupID:   "hospital123",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock the email check
				repo.On("GetIdentityByEmail", mock.Anything, "doctor@hospital.com").Return(nil, nil)

				// Mock the creation
				repo.On("CreateIdentity", mock.Anything, mock.MatchedBy(func(identity *entities.KeycloakIdentity) bool {
					return identity.Email == "doctor@hospital.com" &&
						len(identity.Attributes["userId"]) > 0 &&
						identity.Attributes["groupId"][0] == "hospital123"
				})).Return(&entities.KeycloakIdentity{
					ID:    "doctor123",
					Email: "doctor@hospital.com",
					Attributes: map[string][]string{
						"role":    {string(enums.RoleHealthcareProfessional)},
						"userId":  {"doctor123"},
						"groupId": {"hospital123"},
					},
				}, nil)
			},
			expectedID: "doctor123",
		},
		{
			name: "Email already exists",
			request: &requests.CreateIdentityRequest{
				Email:     "existing@test.com",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock the email check to return an existing user
				repo.On("GetIdentityByEmail", mock.Anything, "existing@test.com").Return(&entities.KeycloakIdentity{
					ID:    "existing123",
					Email: "existing@test.com",
				}, nil)
			},
			expectedError: errors.ErrUserAlreadyExists,
		},
		{
			name: "Missing GroupID for non-admin role",
			request: &requests.CreateIdentityRequest{
				Email:     "user@test.com",
				Role:      enums.Role("Patient"),
				FirstName: "Test",
				LastName:  "User",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// No need to set up mocks as it should fail validation before repository calls
			},
			expectedError: errors.ErrGroupIDRequired,
		},
		{
			name: "Repository error handling",
			request: &requests.CreateIdentityRequest{
				Email:     "error@test.com",
				Role:      enums.RoleAdmin,
				FirstName: "Error",
				LastName:  "Test",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock the email check
				repo.On("GetIdentityByEmail", mock.Anything, "error@test.com").Return(nil, nil)

				// Mock the creation to return an error
				repo.On("CreateIdentity", mock.Anything, mock.Anything).
					Return(nil, errors.ErrKeycloakUnexpected)
			},
			expectedError: errors.ErrKeycloakUnexpected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockRepo := new(mocks.MockIdentityRepository)
			tt.mockSetup(mockRepo)

			service := services.NewIdentityService(mockRepo, &mocks.MockLoggerFactory{})

			// Execute
			response, err := service.CreateIdentity(context.Background(), tt.request, tt.hashedPassword)

			// Assert
			if tt.expectedError != nil {
				assert.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok, "expected error should be an AppError")
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, tt.expectedID, response.ID)
				assert.Equal(t, tt.request.Email, response.Email)
				assert.Equal(t, tt.request.Role, response.Role)
			}

			// Verify all expectations were met
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestCreateIdentity_ValidationCases(t *testing.T) {
	tests := []struct {
		name           string
		request        *requests.CreateIdentityRequest
		hashedPassword string
		mockSetup      func(*mocks.MockIdentityRepository)
		expectedError  *errors.AppError
	}{
		{
			name: "Empty email",
			request: &requests.CreateIdentityRequest{
				Email:     "",
				Role:      enums.RoleAdmin,
				FirstName: "Test",
				LastName:  "User",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				repo.On("GetIdentityByEmail", mock.Anything, "").Return(nil, errors.ErrInvalidEmail)

				repo.On("CreateIdentity", mock.Anything, mock.MatchedBy(func(identity *entities.KeycloakIdentity) bool {
					return identity.Email == ""
				})).Return(nil, errors.ErrInvalidEmail)
			},
			expectedError: errors.ErrInvalidEmail,
		},
		{
			name: "Missing required GroupID for patient role",
			request: &requests.CreateIdentityRequest{
				Email:     "patient@test.com",
				Role:      "Patient",
				FirstName: "Test",
				LastName:  "User",
				GroupID:   "",
			},
			hashedPassword: "hashedpass123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// No need to set up mock expectation as it should fail before repository call
			},
			expectedError: errors.ErrGroupIDRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mocks.MockIdentityRepository)
			if tt.mockSetup != nil {
				tt.mockSetup(mockRepo)
			}
			service := services.NewIdentityService(mockRepo, &mocks.MockLoggerFactory{})

			response, err := service.CreateIdentity(context.Background(), tt.request, tt.hashedPassword)

			assert.Error(t, err)
			if appErr, ok := err.(*errors.AppError); ok {
				assert.Equal(t, tt.expectedError.Code, appErr.Code)
			}
			assert.Nil(t, response)
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUpdateRole(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		request       *requests.UpdateRoleRequest
		mockSetup     func(*mocks.MockIdentityRepository)
		expectedError error
		expectedRole  enums.Role
	}{
		{
			name: "Successful role update to admin",
			id:   "user123",
			request: &requests.UpdateRoleRequest{
				Role: enums.RoleAdmin,
			},
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock getting current identity
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "test@example.com",
					Attributes: map[string][]string{
						"role":    {"Patient"},
						"groupId": {"group123"},
						"userId":  {"user123"},
					},
				}, nil)

				// Mock updating identity
				repo.On("UpdateIdentity", mock.Anything, mock.MatchedBy(func(identity *entities.KeycloakIdentity) bool {
					roleAttr, exists := identity.Attributes["role"]
					return exists && len(roleAttr) > 0 && roleAttr[0] == string(enums.RoleAdmin)
				})).Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "test@example.com",
					Attributes: map[string][]string{
						"role":   {string(enums.RoleAdmin)},
						"userId": {"user123"},
					},
				}, nil)
			},
			expectedRole: enums.RoleAdmin,
		},
		{
			name: "Missing GroupID for non-admin role",
			id:   "user123",
			request: &requests.UpdateRoleRequest{
				Role: enums.Role("Patient"),
			},
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "test@example.com",
					Attributes: map[string][]string{
						"role": {"Admin"},
					},
				}, nil)
			},
			expectedError: errors.ErrGroupIDRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mocks.MockIdentityRepository)
			tt.mockSetup(mockRepo)

			service := services.NewIdentityService(mockRepo, &mocks.MockLoggerFactory{})

			response, err := service.UpdateRole(context.Background(), tt.id, tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Nil(t, response)
				if appErr, ok := err.(*errors.AppError); ok {
					expectedAppErr, ok := tt.expectedError.(*errors.AppError)
					require.True(t, ok)
					assert.Equal(t, expectedAppErr.Code, appErr.Code)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, tt.expectedRole, response.Role)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestVerifyPassword(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		password      string
		mockSetup     func(*mocks.MockIdentityRepository)
		expectedError error
	}{
		{
			name:     "Successful password verification",
			id:       "user123",
			password: "correctPassword",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "test@example.com",
					Attributes: map[string][]string{
						"userId": {"user123"},
					},
				}, nil)
				repo.On("VerifyPassword", mock.Anything, "test@example.com", "correctPassword").Return(nil)
			},
		},
		{
			name:     "Invalid credentials",
			id:       "user123",
			password: "wrongPassword",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID:    "user123",
					Email: "test@example.com",
				}, nil)
				repo.On("VerifyPassword", mock.Anything, "test@example.com", "wrongPassword").Return(errors.ErrInvalidCredentials)
			},
			expectedError: errors.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mocks.MockIdentityRepository)
			tt.mockSetup(mockRepo)

			service := services.NewIdentityService(mockRepo, &mocks.MockLoggerFactory{})

			err := service.VerifyPassword(context.Background(), tt.id, tt.password)

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

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestSetPIN(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		hashedPIN     string
		mockSetup     func(*mocks.MockIdentityRepository)
		expectedError error
	}{
		{
			name:      "Successful PIN creation",
			id:        "user123",
			hashedPIN: "hashedPin123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				// Mock getting current identity without PIN
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID:         "user123",
					Email:      "test@example.com",
					Attributes: map[string][]string{},
				}, nil)

				// Mock updating identity with PIN
				repo.On("UpdateIdentity", mock.Anything, mock.MatchedBy(func(identity *entities.KeycloakIdentity) bool {
					pinAttr, exists := identity.Attributes["pin"]
					hasPinAttr, hasHasPin := identity.Attributes["hasPin"]
					return exists && len(pinAttr) > 0 && pinAttr[0] == "hashedPin123" &&
						hasHasPin && len(hasPinAttr) > 0 && hasPinAttr[0] == "true"
				})).Return(&entities.KeycloakIdentity{}, nil)
			},
		},
		{
			name:      "PIN already exists",
			id:        "user123",
			hashedPIN: "hashedPin123",
			mockSetup: func(repo *mocks.MockIdentityRepository) {
				repo.On("GetIdentity", mock.Anything, "user123").Return(&entities.KeycloakIdentity{
					ID: "user123",
					Attributes: map[string][]string{
						"pin": {"existingHashedPin"},
					},
				}, nil)
			},
			expectedError: errors.ErrPINAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mocks.MockIdentityRepository)
			tt.mockSetup(mockRepo)

			service := services.NewIdentityService(mockRepo, &mocks.MockLoggerFactory{})

			err := service.SetPIN(context.Background(), tt.id, tt.hashedPIN)

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

			mockRepo.AssertExpectations(t)
		})
	}
}
