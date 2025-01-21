package mocks

import (
	"context"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"github.com/stretchr/testify/mock"
)

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
