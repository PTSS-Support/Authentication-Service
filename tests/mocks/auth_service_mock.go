package mocks

import (
	"context"
	requests "github.com/PTSS-Support/identity-service/api/dtos/requests/auth"
	"github.com/PTSS-Support/identity-service/domain/entities"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, req *requests.LoginRequest) (*entities.TokenPair, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.TokenPair), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *MockAuthService) ValidateAndRefreshIfNeeded(ctx context.Context, accessToken, refreshToken string) (*entities.TokenPair, error) {
	args := m.Called(ctx, accessToken, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.TokenPair), args.Error(1)
}

func (m *MockAuthService) ValidateLoginRequest(req *requests.LoginRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *MockAuthService) ValidateAndIntrospectRefreshToken(ctx context.Context, refreshToken string) (*entities.TokenIntrospectionResponse, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.TokenIntrospectionResponse), args.Error(1)
}

func (m *MockAuthService) RefreshTokens(ctx context.Context, refreshToken string) (*entities.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.TokenPair), args.Error(1)
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*entities.TokenIntrospectionResponse, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.TokenIntrospectionResponse), args.Error(1)
}
