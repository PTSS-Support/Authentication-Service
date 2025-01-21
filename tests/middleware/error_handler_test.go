package middleware_test

import (
	"fmt"
	"github.com/PTSS-Support/identity-service/api/middleware"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/tests/mocks"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorHandler_Handle(t *testing.T) {
	tests := []struct {
		name          string
		error         error
		expectedCode  int
		expectedBody  string
		expectedError bool
	}{
		{
			name:          "Direct AppError",
			error:         errors.ErrInvalidCredentials,
			expectedCode:  http.StatusUnauthorized,
			expectedBody:  `{"code":"INVALID_CREDENTIALS","message":"Incorrect email or password. Please try again."}`,
			expectedError: true,
		},
		{
			name:          "Wrapped AppError",
			error:         fmt.Errorf("failed to process request: %w", errors.ErrInvalidCredentials),
			expectedCode:  http.StatusUnauthorized,
			expectedBody:  `{"code":"INVALID_CREDENTIALS","message":"Incorrect email or password. Please try again."}`,
			expectedError: true,
		},
		{
			name:          "Regular error",
			error:         fmt.Errorf("some random error"),
			expectedCode:  http.StatusInternalServerError,
			expectedBody:  `{"error":"An unexpected error occurred"}`,
			expectedError: true,
		},
		{
			name:          "No error",
			error:         nil,
			expectedCode:  http.StatusOK,
			expectedBody:  "",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			// Create error handler
			handler := middleware.NewErrorHandler(&mocks.MockLoggerFactory{})

			// Add middleware
			r.Use(handler.Handle())

			// Add test route
			r.GET("/test", func(c *gin.Context) {
				if tt.error != nil {
					_ = c.Error(tt.error)
				}
			})

			// Make request
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
			r.ServeHTTP(w, c.Request)

			// Assert
			assert.Equal(t, tt.expectedCode, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}
