package middleware

import (
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/util"
	"github.com/gin-gonic/gin"
	"net/http"
)

type ErrorHandler struct {
	logger util.Logger
}

func NewErrorHandler(loggerFactory util.LoggerFactory) *ErrorHandler {
	return &ErrorHandler{
		logger: loggerFactory.NewLogger("ErrorHandler"),
	}
}

func (h *ErrorHandler) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		err := c.Errors.Last().Err

		if appErr, ok := err.(*errors.AppError); ok {
			h.logger.Error("Request failed", "error", appErr.Err)
			c.JSON(appErr.StatusCode, gin.H{
				"code":    appErr.Code,
				"message": appErr.ClientMessage,
			})
			return
		}

		// Handle regular errors
		h.logger.Error("Unexpected error", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An unexpected error occurred"})
	}
}
