package mocks

import (
	"context"
	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/identity"
	responses "github.com/PTSS-Support/identity-service/api/dtos/responses/identity"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/stretchr/testify/mock"
)

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

func (m *MockIdentityService) GetIdentityByEmail(ctx context.Context, email string) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityService) ValidatePasswordResetEligibility(ctx context.Context, email string) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityService) ResetPassword(ctx context.Context, id string, newPassword string) error {
	args := m.Called(ctx, id, newPassword)
	return args.Error(0)
}
