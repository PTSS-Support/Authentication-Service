package mocks

import "github.com/stretchr/testify/mock"

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
