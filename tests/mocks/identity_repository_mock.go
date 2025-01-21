package mocks

import (
	"context"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/stretchr/testify/mock"
)

type MockIdentityRepository struct {
	mock.Mock
}

func (m *MockIdentityRepository) CreateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, identity)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityRepository) GetIdentity(ctx context.Context, id string) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityRepository) UpdateIdentity(ctx context.Context, identity *entities.KeycloakIdentity) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, identity)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityRepository) DeleteIdentity(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockIdentityRepository) VerifyPassword(ctx context.Context, username string, password string) error {
	args := m.Called(ctx, username, password)
	return args.Error(0)
}

func (m *MockIdentityRepository) UpdatePassword(ctx context.Context, id string, newPassword string) error {
	args := m.Called(ctx, id, newPassword)
	return args.Error(0)
}

func (m *MockIdentityRepository) GetIdentityByEmail(ctx context.Context, email string) (*entities.KeycloakIdentity, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.KeycloakIdentity), args.Error(1)
}

func (m *MockIdentityRepository) ResetPassword(ctx context.Context, id string, newPassword string) error {
	args := m.Called(ctx, id, newPassword)
	return args.Error(0)
}
